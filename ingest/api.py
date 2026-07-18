"""Plain REST API — bulk match + LVE create, no LLM, zero per-call cost.

Runs the same matcher core as `vdb match` / the MCP tools, but as a direct HTTP service
for batch callers (a scanner / Windmill posting tens of thousands of components at once).
No model is involved, so there is no token cost — just a DB lookup.

    GET  /healthz
    POST /match   (any valid token)   { "components": [ {purl|cpe, version, release?}, … ] }
                                       → per component {status, cves} + summary. Deduped.
    POST /lve     (role lve_writer)    { "product", "title", "fixed"?, … } → create an LVE
                                       (a DB trigger materialises its affected row at once).

Auth: a Bearer HS256 JWT — the same token `vdb create-token` mints — verified locally with
the standard library (no external call). /match accepts any valid token; /lve requires the
lve_writer role. With no HASURA_JWT_SECRET set, auth is disabled (dev only).

Run: `vdb api` (or `python -m ingest.api`); listens on $API_PORT (default 8770).
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ingest.core.db import get_conn
from ingest.match import load_curations, match, parse_cpe, parse_purl, remediation

_SECRET = os.environ.get("HASURA_JWT_SECRET", "")


def _verify(token: str):
    """Validate an HS256 JWT with stdlib only → claims payload, or None."""
    try:
        h, p, s = token.split(".")
        want = base64.urlsafe_b64encode(
            hmac.new(_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(want, s):
            return None
        payload = json.loads(base64.urlsafe_b64decode(p + "=="))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None


def _roles(payload) -> list:
    return (payload or {}).get("https://hasura.io/jwt/claims", {}).get("x-hasura-allowed-roles", [])


def _fmt(findings: dict) -> list:
    out = []
    for cid, hits in sorted(findings.items()):
        out.append({"id": cid,
                    "fixed": next((f for _, _, f, _, _ in hits if f), None),
                    "fix_kb": next((k for _, _, _, k, _ in hits if k), None),
                    "status": hits[0][1],
                    "sources": sorted({s for s, _, _, _, _ in hits})})
    return out


def _bulk_match(components: list) -> list:
    """Match a batch; identical (ident, version, release) tuples are computed once."""
    conn = get_conn()
    try:
        curations = load_curations(conn)          # load once, apply to every component
        cache, results = {}, []
        for c in components:
            purl, cpe = c.get("purl") or "", c.get("cpe") or ""
            # a generic purl (pkg:generic/…) carries no ecosystem and never matches; prefer
            # the CPE then. A real ecosystem purl (rpm/deb/pypi/…) wins over the CPE.
            ident = purl if (purl and not purl.startswith("pkg:generic/")) else (cpe or purl)
            ver = c.get("version") or ""
            rel = c.get("release") or None
            if ident.startswith("pkg:rpm/") or ident.startswith("pkg:deb/"):
                _, name, _, quals = parse_purl(ident)
                # an installed-but-not-running kernel build (active=false, rpm or deb) — the
                # active main package already carries these CVEs.
                if quals.get("active") == "false":
                    continue
                # a satellite package of a bigger kernel build — the main kernel package
                # already covers it: rpm (upstream=kernel, e.g. kernel-tools, python3-perf on
                # a RHEL/SUSE build) or deb (upstream starts with "linux", e.g. linux-headers-*,
                # linux-*-gcp-6.17 — Ubuntu's per-flavor source names: linux, linux-meta,
                # linux-signed, linux-gcp-6.17, linux-meta-gcp-6.17, ...). rpm's bare kernel
                # roots (kernel, kernel-uek, kernel-rt, ...) carry no upstream qualifier (they
                # ARE their own upstream, so scanners skip the redundant tag) — caught instead
                # by name.startswith("kernel"). Safe because active=true always wins first:
                # this whole check only applies to non-active entries, so an actually-running
                # kernel-rt (or any other kernel-family root) is never hidden — only inactive/
                # duplicate installs are, exactly like an inactive standard kernel build. On deb
                # the running kernel image itself also carries an upstream qualifier
                # (linux-image-*-gcp?upstream=linux-signed-gcp-6.17&active=true), unlike rpm's
                # kernel-core which carries none — same active=true-wins logic applies there too.
                if quals.get("active") != "true":
                    upstream = quals.get("upstream") or ""
                    if ((ident.startswith("pkg:rpm/") and (upstream == "kernel" or name.startswith("kernel")))
                            or (ident.startswith("pkg:deb/") and upstream.startswith("linux"))):
                        continue
            k = (ident, ver, rel)
            if k not in cache:
                try:
                    f = match(conn, ident, ver, rel, curations)
                    cache[k] = {"status": "vulnerable" if f else "compliant",
                                "remediation": remediation(f), "cves": _fmt(f)}
                except Exception as e:
                    cache[k] = {"status": "unknown", "cves": [], "error": str(e)}
            results.append({"component": ident, "version": ver, **cache[k]})
        return results
    finally:
        conn.close()


_CUR_ACTIONS = ("suppress", "set_status", "set_fixed")
_CUR_STATUS = ("not_affected", "under_investigation", "affected", "fixed", "wont_fix", "unknown")


def _create_curation(d: dict) -> dict:
    """Insert a curation rule. Required: cve_id, action, reason. Selector + new-value fields
    are optional per action (validated to mirror the table CHECKs)."""
    cve, action, reason = d.get("cve_id"), d.get("action"), d.get("reason")
    if not cve or not action or not reason:
        raise ValueError("cve_id, action and reason are required")
    if action not in _CUR_ACTIONS:
        raise ValueError(f"action must be one of {', '.join(_CUR_ACTIONS)}")
    if action == "set_status":
        if d.get("status") not in _CUR_STATUS:
            raise ValueError(f"set_status needs status ∈ {', '.join(_CUR_STATUS)}")
    if action == "set_fixed" and not any(d.get(f) for f in ("fixed", "introduced", "last_affected")):
        raise ValueError("set_fixed needs at least one of fixed / introduced / last_affected")
    cols = ("cve_id", "action", "coord", "ecosystem", "package", "cpe23", "release", "source",
            "status", "fixed", "introduced", "last_affected", "reason", "created_by", "expires_at")
    rec = {c: d.get(c) for c in cols if d.get(c) is not None}
    rec["cve_id"], rec["action"], rec["reason"] = cve, action, reason
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(f"INSERT INTO curation ({','.join(rec)}) "
                        f"VALUES ({','.join(['%s'] * len(rec))}) RETURNING id",
                        list(rec.values()))
            rec["id"] = cur.fetchone()[0]
        conn.commit()
        return rec
    finally:
        conn.close()


def _list_curations() -> list:
    conn = get_conn()
    try:
        cols = ("id", "cve_id", "action", "coord", "ecosystem", "package", "cpe23", "release",
                "source", "status", "fixed", "introduced", "last_affected", "reason",
                "created_by", "created_at", "expires_at")
        with conn.cursor() as cur:
            cur.execute(f"SELECT {','.join(cols)} FROM curation ORDER BY created_at DESC LIMIT 1000")
            return [{c: (v.isoformat() if hasattr(v, "isoformat") else v)
                     for c, v in zip(cols, row)} for row in cur.fetchall()]
    finally:
        conn.close()


def _create_lve(d: dict) -> dict:
    if d["product"].startswith("cpe:"):
        key, _ = parse_cpe(d["product"])
        if not key:
            raise ValueError("invalid cpe 2.3 string")
        ident = {"coord": "cpe", "cpe23": key}
    else:
        ptype, name, _, quals = parse_purl(d["product"])
        if ptype == "generic":
            raise ValueError(
                "generic purls are not allowed for LVEs — a generic purl never matches a scanned "
                "component. Identify the product with a CPE 2.3 string (cpe:2.3:...) or an "
                "ecosystem/distro purl (pkg:rpm|deb|apk|pypi|npm|gem|golang|maven|cargo/...).")
        ident = {"coord": "purl", "ecosystem": ptype, "package": name, "purl": d["product"]}
        if quals.get("distro"):
            ident["release"] = quals["distro"]
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            year = datetime.datetime.now(datetime.timezone.utc).year
            cur.execute("SELECT id FROM lve WHERE id LIKE %s ORDER BY id DESC LIMIT 1", (f"LVE-{year}-%",))
            r = cur.fetchone()
            n = (int(r[0].rsplit("-", 1)[1]) + 1) if r else 1
            rec = {"id": f"LVE-{year}-{n:04d}", "title": d["title"], "description": d.get("description"),
                   "severity": d.get("severity"), "introduced": d.get("introduced"),
                   "fixed": d.get("fixed"), "last_affected": d.get("last_affected"),
                   "version_scheme": d.get("version_scheme") or "generic",
                   "status": d.get("status") or "affected", "created_by": d.get("created_by"), **ident}
            rec = {k: v for k, v in rec.items() if v is not None}
            cur.execute(f"INSERT INTO lve ({','.join(rec)}) VALUES ({','.join(['%s'] * len(rec))})",
                        list(rec.values()))
        conn.commit()
        return rec
    finally:
        conn.close()


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        elif self.path == "/curation":
            payload = _verify(self.headers.get("Authorization", "").removeprefix("Bearer ").strip())
            if _SECRET and not payload:
                return self._json(401, {"error": "unauthorized"})
            self._json(200, {"curations": _list_curations()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        payload = _verify(self.headers.get("Authorization", "").removeprefix("Bearer ").strip())
        if _SECRET and not payload:
            return self._json(401, {"error": "unauthorized"})
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            return self._json(400, {"error": "invalid json"})

        if self.path == "/match":
            res = _bulk_match(body.get("components") or [])
            self._json(200, {
                "total": len(res),
                "vulnerable": sum(1 for r in res if r["status"] == "vulnerable"),
                "compliant": sum(1 for r in res if r["status"] == "compliant"),
                "unknown": sum(1 for r in res if r["status"] == "unknown"),
                "results": res,
            })
        elif self.path == "/lve":
            if _SECRET and "lve_writer" not in _roles(payload):
                return self._json(403, {"error": "lve_writer role required"})
            if not body.get("product") or not body.get("title"):
                return self._json(400, {"error": "product and title required"})
            try:
                self._json(201, {"created": True, **_create_lve(body)})
            except Exception as e:
                self._json(400, {"created": False, "error": str(e)})
        elif self.path == "/curation":
            if _SECRET and "curation_writer" not in _roles(payload):
                return self._json(403, {"error": "curation_writer role required"})
            try:
                self._json(201, {"created": True, **_create_curation(body)})
            except Exception as e:
                self._json(400, {"created": False, "error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *_a):
        pass  # quiet — don't spam stdout per request


def main() -> int:
    port = int(os.environ.get("API_PORT", "8770"))
    if not _SECRET:
        print("WARNING: HASURA_JWT_SECRET not set — REST API is UNAUTHENTICATED", flush=True)
    print(f"limoza-vDB REST API on :{port}  "
          f"(POST /match · POST /lve · POST/GET /curation · GET /healthz)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    main()
