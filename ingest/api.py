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
from ingest.match import match, parse_cpe, parse_purl

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
                    "fixed": next((f for _, _, f, _ in hits if f), None),
                    "fix_kb": next((k for _, _, _, k in hits if k), None),
                    "status": hits[0][1],
                    "sources": sorted({s for s, _, _, _ in hits})})
    return out


def _bulk_match(components: list) -> list:
    """Match a batch; identical (ident, version, release) tuples are computed once."""
    conn = get_conn()
    try:
        cache, results = {}, []
        for c in components:
            purl, cpe = c.get("purl") or "", c.get("cpe") or ""
            # a generic purl (pkg:generic/…) carries no ecosystem and never matches; prefer
            # the CPE then. A real ecosystem purl (rpm/deb/pypi/…) wins over the CPE.
            ident = purl if (purl and not purl.startswith("pkg:generic/")) else (cpe or purl)
            ver = c.get("version") or ""
            rel = c.get("release") or None
            k = (ident, ver, rel)
            if k not in cache:
                try:
                    f = match(conn, ident, ver, rel)
                    cache[k] = {"status": "vulnerable" if f else "compliant", "cves": _fmt(f)}
                except Exception as e:
                    cache[k] = {"status": "unknown", "cves": [], "error": str(e)}
            results.append({"component": ident, "version": ver, **cache[k]})
        return results
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
        else:
            self._json(404, {"error": "not found"})

    def log_message(self, *_a):
        pass  # quiet — don't spam stdout per request


def main() -> int:
    port = int(os.environ.get("API_PORT", "8770"))
    if not _SECRET:
        print("WARNING: HASURA_JWT_SECRET not set — REST API is UNAUTHENTICATED", flush=True)
    print(f"limoza-vDB REST API on :{port}  (POST /match · POST /lve · GET /healthz)", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    main()
