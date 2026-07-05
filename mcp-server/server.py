"""The MCP server itself: a real MCP server (it exposes tools and never calls an LLM).

Transport is Streamable HTTP so it can be reached remotely — e.g. added as a custom
connector in the Claude chat window, or by any other MCP-capable client driving its
own LLM (Gemini, Vertex AI, OpenAI, Claude).

Run it directly: ``python server.py`` (this folder is intentionally NOT a Python
package — the import name ``mcp`` belongs to the SDK).
"""

import logging
from collections import Counter, defaultdict

import jwt as pyjwt
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Route

from config import load_settings
from hasura import HasuraClient, request_token
from lve import create_lve as _create_lve
from matcher import check as match_check
from queries import EXPLAIN_PACKAGE, EXPLAIN_STATUS, FULL_CVE_SCAN

log = logging.getLogger("limoza-mcp")

settings = load_settings()
hasura = HasuraClient(settings)

mcp = FastMCP("limoza-vdb", stateless_http=True, host=settings.host, port=settings.port)

# Reply template the consuming LLM must follow for get_cve_detail — returned in the result
# (`output_format`) so it sits right next to the data, and referenced from the docstring.
CVE_OUTPUT_FORMAT = """\
Respond ENTIRELY IN ENGLISH. Render the reply as Markdown using EXACTLY this structure, headings \
and order — the IDENTICAL layout for every CVE, every time. Keep it compact.

DO NOT HALLUCINATE: copy every value verbatim from THIS tool's result; render "—" for any empty \
or missing field. Never add versions, scores or facts not present in the data, and never add or \
reorder sections. Summarise the affected layer per source — do NOT list individual packages.

# {CVE-ID} — {severity}, CVSS {base_score}

{description — at most 2 sentences}

## Scores
| CVSS | EPSS | KEV | SSVC |
|------|------|-----|------|
| {base_score} {severity} (v{cvss_version}) | {epss.score} (p{epss.percentile}, {epss.date}) | {"yes — due {kev.due_date}" if KEV present else "no"} | {ssvc.exploitation} / {ssvc.automatable} / {ssvc.technical_impact} |

- **CWE:** {cwe_id} {name}
- **Vector:** {cvss.vector}
- **Exploits:** {"none known", or one "name — url" per exploit}

## Affected (summary)
{affected_summary.total_rows} entries · {affected_summary.distinct_packages} packages · fix available: {"yes" if affected_summary.fix_available else "no"}

| Source | fixed | affected | wont_fix | not_affected | example fix |
|--------|-------|----------|----------|--------------|-------------|
| {source} | {by_source.fixed} | {by_source.affected} | {by_source.wont_fix} | {by_source.not_affected} | {affected_summary.fixed_examples[source] or "—"} |

(One row per source in affected_summary.by_source. Do NOT list individual packages. If \
affected_summary.total_rows > affected_summary.shown, append: "summary based on {shown} of \
{total_rows} rows".)

## Fix & References
- **Fix:** {one line — distro upgrade note, or "no fix available"}
- **References:** {up to 3 links}

(To explain WHY one specific package has its status, call explain_status.)
"""


def _summarize_affected(rows: list, total) -> dict:
    """Compact the (possibly huge) affected layer into per-source counts + one example fix each,
    so get_cve_detail stays short and renders the same shape for every CVE."""
    by_status = Counter()
    by_source = defaultdict(Counter)
    pkgs = set()
    fixed_examples = {}
    for r in rows:
        s, src = r.get("status"), r.get("source")
        by_status[s] += 1
        by_source[src][s] += 1
        pkgs.add(r.get("package"))
        if s == "fixed" and r.get("fixed") and src not in fixed_examples:
            rel = r.get("release")
            fixed_examples[src] = f'{r.get("package")} {r["fixed"]}' + (f" ({rel})" if rel else "")
    return {
        "total_rows": total if total is not None else len(rows),
        "shown": len(rows),
        "distinct_packages": len(pkgs),
        "fix_available": by_status.get("fixed", 0) > 0,
        "by_status": dict(by_status),
        "by_source": {k: dict(v) for k, v in by_source.items()},
        "fixed_examples": fixed_examples,
    }


@mcp.tool()
async def get_cve_detail(cve_id: str) -> dict:
    """Return all known data for a single CVE from the limoza-vDB vulnerability database.

    IMPORTANT: Answer in ENGLISH and base your reply EXCLUSIVELY on the data returned by this tool.
    Do NOT supplement with your own training knowledge about this CVE. If a field is empty or
    missing (e.g. a distro's fixed version) render "—" — an empty value means the source published
    none; never fill gaps from memory, from other CVEs, or by guessing.

    OUTPUT FORMAT: Render your reply to the user as Markdown using EXACTLY the structure given in
    the result's ``output_format`` field (same headings and order). Fill each field from the data;
    write "—" for missing values or omit empty rows/sections. Do not add or reorder sections.

    Returns the CVE record (assigner/state/dates), descriptions, CVSS scores, CWE
    weaknesses, references, solutions/workarounds, impacts, aliases, per-vendor
    assessments, advisories, known exploits, EPSS/KEV/SSVC triage signals, a per-source
    affected-layer SUMMARY (counts + one example fix per source — not individual packages;
    use match/check_vulnerable for per-package decisions), and the tiered advisory view
    (advisory_tiers: L1 CNA / L2 upstream / L3 downstream). Returns {"found": false} when
    no record exists for the CVE.

    Args:
        cve_id: A CVE identifier such as "CVE-2024-3094" (case-insensitive).
    """
    cve_id = cve_id.strip().upper()
    data = await hasura.query(FULL_CVE_SCAN, {"cve_id": cve_id})
    rec = data.get("cve_by_pk")
    if not rec:
        return {
            "found": False,
            "cve_id": cve_id,
            "message": "No record found for this CVE in limoza-vDB.",
        }
    total = ((data.get("affected_aggregate") or {}).get("aggregate") or {}).get("count")
    rec["affected_summary"] = _summarize_affected(rec.pop("affected", None) or [], total)
    return {
        "found": True,
        "cve_id": cve_id,
        "record": rec,
        "advisory_tiers": data.get("cve_levels") or [],
        "output_format": CVE_OUTPUT_FORMAT,
    }


# ── explain_status: provenance for a CVE's affected-layer status ──────────────────────────
_SOURCE_LABEL = {
    "debian": "Debian Security Tracker", "ubuntu": "Ubuntu Security",
    "redhat": "Red Hat", "almalinux": "AlmaLinux (RHEL rebuild)",
    "rocky": "Rocky Linux (RHEL rebuild)", "oracle": "Oracle Linux", "suse": "SUSE",
    "nvd": "NVD (CPE configuration)", "cvelistv5": "CVE Record (CNA)",
    "ghsa": "GitHub Security Advisory", "osv": "OSV", "lve": "Local Vulnerability Entry",
}
_VENDOR_URL = {
    "debian": "https://security-tracker.debian.org/tracker/{cve}",
    "ubuntu": "https://ubuntu.com/security/{cve}",
    "redhat": "https://access.redhat.com/security/cve/{cve}",
    "almalinux": "https://access.redhat.com/security/cve/{cve}",   # AlmaLinux rebuilds RHEL
    "rocky": "https://access.redhat.com/security/cve/{cve}",        # Rocky rebuilds RHEL
    "oracle": "https://linux.oracle.com/cve/{cve}.html",
    "suse": "https://www.suse.com/security/cve/{cve}.html",
    "nvd": "https://nvd.nist.gov/vuln/detail/{cve}",
    "cvelistv5": "https://www.cve.org/CVERecord?id={cve}",
    "ghsa": "https://github.com/advisories?query={cve}",
    "osv": "https://osv.dev/vulnerability/{cve}",
}


def _verify_url(source: str, cve: str):
    t = _VENDOR_URL.get(source)
    return t.format(cve=cve) if t else None


def _bounds_phrase(introduced, fixed, last) -> str:
    intro = introduced if introduced and introduced != "0" else None
    if fixed:
        return f"{('from ' + intro + ' ') if intro else ''}up to (but not including) {fixed}"
    if last:
        return f"{('from ' + intro + ' ') if intro else ''}up to and including {last}"
    if intro:
        return f"{intro} and later"
    return "all versions"


def _explain_row(r: dict) -> str:
    label = _SOURCE_LABEL.get(r["source"], r["source"])
    rel = r.get("release")
    where = r["package"] + (f" in {rel}" if rel else "")
    status, raw, just, fixed = r["status"], r.get("status_raw"), r.get("justification"), r.get("fixed")
    if status == "fixed":
        return f"{label} fixed this in {where}: a host at {fixed} or later is not vulnerable; below it, it is."
    if status == "not_affected":
        return f"{label} states {where} is NOT affected" + (f" ({just})" if just else "") + "."
    if status == "wont_fix":
        return (f"{label} acknowledges {where} is affected"
                + (f" (vendor status '{raw}')" if raw else "")
                + " but will NOT ship a fix"
                + (f" — {just}" if just else "")
                + ". We keep it for audit but exclude it from the vulnerable count.")
    if status == "under_investigation":
        return f"{label} is still investigating {where} — no verdict yet."
    return (f"{label} lists {where} as affected ({_bounds_phrase(r.get('introduced'), fixed, r.get('last_affected'))})"
            + (f", vendor status '{raw}'" if raw else "")
            + ("; no fixed version published yet" if not fixed else "")
            + ".")


@mcp.tool()
async def explain_status(cve_id: str = "", package: str = "", release: str = "") -> dict:
    """Explain, WITH the vendor source and a link to verify, WHY a CVE/package has the status it has
    in limoza-vDB. You MUST call this — and quote its `explanation` + `verify` URL — whenever the
    user asks "why is X not_affected / vulnerable-without-a-fix / wont_fix?", why a package has
    (no) open CVEs, or to prove/justify a status. Never answer such questions from memory or by
    guessing; if you are about to say "this CVE was likely classified as fixed or not applicable",
    call this tool instead and report what it actually returns.

    Two modes:
      • cve_id given  → per-CVE: one entry per source/release with our derived ``status``, the
        vendor's ``raw_status``, the ``reason`` we derived it from, version bounds, a plain-English
        ``explanation`` and a vendor ``verify`` URL. Add ``package`` to narrow to one package.
      • only package  → package mode: WHY the package has (no) open CVEs for a ``release`` —
        status totals plus the wont_fix CVEs (with reasons + links) and example fixed versions, so
        "no open CVEs" can be proven (everything is fixed / wont_fix / not_affected).

    Base your answer ONLY on this data; cite the source and verify link.

    Args:
        cve_id:  CVE identifier, e.g. "CVE-2011-3374" (optional if package is given).
        package: source package / CPE product, e.g. "ghostscript" (optional if cve_id is given).
        release: distro release codename, e.g. "bullseye" (optional; recommended in package mode).
    """
    cve_id = cve_id.strip().upper()
    pkg = package.strip()
    rel = release.strip().lower()

    if cve_id:
        data = await hasura.query(EXPLAIN_STATUS, {"cve": cve_id, "pkg": pkg or "%"})
        rows = [r for r in (data.get("affected") or []) if not rel or (r.get("release") or "").lower() == rel]
        if not rows:
            return {"found": False, "cve_id": cve_id, "package": package or None, "release": release or None,
                    "message": "No affected-layer rows for this CVE/package/release in limoza-vDB."}
        out = [{
            "source": r["source"], "package": r["package"], "release": r.get("release"),
            "status": r["status"], "raw_status": r.get("status_raw"), "reason": r.get("justification"),
            "introduced": r.get("introduced"), "fixed": r.get("fixed"), "last_affected": r.get("last_affected"),
            "explanation": _explain_row(r), "verify": _verify_url(r["source"], cve_id),
        } for r in rows]
        return {"found": True, "mode": "cve", "cve_id": cve_id, "package": package or None,
                "release": release or None, "count": len(out), "explanations": out,
                "note": "Quote each explanation + verify URL in your answer; do not guess."}

    if not pkg:
        return {"found": False, "message": "Provide a cve_id and/or a package."}

    data = await hasura.query(EXPLAIN_PACKAGE, {"pkg": pkg})
    rows = [r for r in (data.get("affected") or []) if not rel or (r.get("release") or "").lower() == rel]
    if not rows:
        return {"found": False, "package": package, "release": release or None,
                "message": "No affected-layer rows for this package/release in limoza-vDB."}
    totals = Counter(r["status"] for r in rows)
    wont_fix, open_aff, fixed_ex, seen = [], [], [], set()
    for r in rows:
        cid, s = r["cve_id"], r["status"]
        if s == "wont_fix" and cid not in seen:
            seen.add(cid)
            wont_fix.append({"cve": cid, "source": r["source"], "release": r.get("release"),
                             "reason": r.get("justification"), "explanation": _explain_row({**r, "package": pkg}),
                             "verify": _verify_url(r["source"], cid)})
        elif s == "affected":
            open_aff.append({"cve": cid, "source": r["source"], "release": r.get("release"),
                             "explanation": _explain_row({**r, "package": pkg}),
                             "verify": _verify_url(r["source"], cid)})
        elif s == "fixed" and r.get("fixed") and len(fixed_ex) < 25:
            fixed_ex.append({"cve": cid, "source": r["source"], "release": r.get("release"), "fixed": r["fixed"]})
    where = pkg + (f" in {rel}" if rel else "")
    summary = (f"{where}: {totals.get('fixed', 0)} fixed, {totals.get('wont_fix', 0)} wont_fix "
               f"(deprioritised — listed), {totals.get('not_affected', 0)} not_affected, "
               f"{len(open_aff)} still-open affected. "
               + ("No genuinely open CVEs — they are either fixed at a version, wont_fix, or not affected."
                  if not open_aff else "Open CVEs need attention (no fix published)."))
    return {"found": True, "mode": "package", "package": package, "release": release or None,
            "totals": dict(totals), "summary": summary,
            "open_affected": open_aff[:50], "wont_fix": wont_fix[:50], "fixed_examples": fixed_ex,
            "note": ("Prove the verdict from this: open_affected = genuinely vulnerable; wont_fix = "
                     "deprioritised by the vendor (cite reason + verify); fixed_examples show the fix "
                     "versions. A host is patched if its version >= the fixed version for that CVE.")}


@mcp.tool()
async def check_vulnerable(purl: str, version: str, release: str = "") -> dict:
    """Check whether an installed package version is affected by known CVEs (version-compared
    against limoza-vDB's affected-version data). Use this for "is X version Y vulnerable?".

    Build the purl from the platform:
      - RHEL / AlmaLinux / Rocky / Oracle rpm:  pkg:rpm/redhat/<name>  (release = el8, el9, el9_2…)
      - SUSE rpm:                               pkg:rpm/suse/<name>    (release = sles15sp7, leap15.6…)
      - Ubuntu / Debian deb:                    pkg:deb/ubuntu/<name>  (release = jammy, noble, bookworm…)
      - Language ecosystems:                    pkg:pypi/<name> · pkg:npm/<name> · pkg:golang/<mod>
                                                · pkg:cargo/<name> · pkg:gem/<name>   (NO release)

    For OS packages (rpm/deb) `release` is REQUIRED — if the user didn't say which release/codename,
    ASK before calling. For language ecosystems leave `release` empty.

    Returns the vulnerable CVEs, each with the fixed version, status, and which source said so.

    Args:
        purl: package URL identifying the product (see above; version may be omitted from the purl).
        version: the installed version string (e.g. "1.0.1e-30.el6_6.1", "2.25.1").
        release: distro release/codename — required for rpm/deb, leave empty for ecosystems.
    """
    res = await match_check(hasura, purl, version, release or None)
    cves = res["cves"]
    return {
        "vulnerable": bool(cves),
        "purl": purl,
        "version": version,
        "ecosystem": res["ecosystem"],
        "release": res["release"],
        "count": len(cves),
        "cves": cves,
    }


@mcp.tool()
async def match_bulk(components: list[dict]) -> dict:
    """Bulk version-check a whole scan's components against the affected data (public CVEs
    AND custom LVEs) in one call — for a scanner/agent that has many components.

    Each component is an object: {"purl"|"cpe": <identifier>, "version": <installed>, "release"?: <distro>}
      - purl:  pkg:rpm/redhat/openssl · pkg:deb/ubuntu/curl (release el9 / jammy / …) · pkg:pypi/django
      - cpe:   a CPE 2.3 string for Windows / Microsoft / binary software

    Returns, per component, a status ("vulnerable" | "compliant" | "unknown") and the
    matching CVEs (id, fixed version, status, source), plus summary counts.

    Args:
        components: list of {purl|cpe, version, release?} objects.
    """
    results = []
    for c in components:
        purl, cpe = c.get("purl") or "", c.get("cpe") or ""
        # a generic purl carries no ecosystem and never matches → prefer the CPE then
        ident = purl if (purl and not purl.startswith("pkg:generic/")) else (cpe or purl)
        ver = c.get("version") or ""
        try:
            res = await match_check(hasura, ident, ver, c.get("release") or None)
            cves = res["cves"]
            results.append({"component": ident, "version": ver,
                            "status": "vulnerable" if cves else "compliant",
                            "count": len(cves), "cves": cves})
        except Exception as e:
            results.append({"component": ident, "version": ver, "status": "unknown", "error": str(e)})
    return {
        "total": len(results),
        "vulnerable": sum(1 for r in results if r["status"] == "vulnerable"),
        "compliant": sum(1 for r in results if r["status"] == "compliant"),
        "unknown": sum(1 for r in results if r["status"] == "unknown"),
        "results": results,
    }


@mcp.tool()
async def create_lve(product: str, title: str, fixed: str = "", introduced: str = "",
                     last_affected: str = "", severity: str = "", description: str = "",
                     version_scheme: str = "", status: str = "affected") -> dict:
    """Create a custom vulnerability entry (LVE) — your own "CVE" for something not in the
    public feeds (e.g. "Notepad++ < 8.7.4"). Once created it is matched immediately by
    check_vulnerable / match_bulk and survives rebuilds.

    Requires a token with the `lve_writer` role (mint one with
    `vdb create-token --role lve_writer`); a read-only token is rejected by the database.

    Args:
        product: the affected product — a CPE 2.3 string (cpe:2.3:...) or an ecosystem/distro purl
                 (pkg:rpm|deb|apk|pypi|npm|gem|golang|maven|cargo/...). Generic purls (pkg:generic/...)
                 are REJECTED — they never match a scanned component. For desktop apps without an
                 ecosystem purl (Notepad++, 7-Zip, …) use the CPE, e.g.
                 cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.7.3:*:*:*:*:*:*:*.
        title:   short description, e.g. "Notepad++ < 8.7.4 buffer overflow".
        fixed:   the version that fixes it (installed < fixed ⇒ vulnerable); omit for "no fix yet".
        introduced / last_affected: optional range bounds (last_affected = inclusive upper).
        severity / description: optional metadata.
        version_scheme: comparison scheme (rpm / deb / semver / pep440 / generic — default generic).
        status: canonical status (default "affected"; "fixed" pairs with a `fixed` version).
    """
    try:
        row = await _create_lve(hasura, product, title, fixed=fixed or None,
                                introduced=introduced or None, last_affected=last_affected or None,
                                severity=severity or None, description=description or None,
                                version_scheme=version_scheme or None, status=status)
        return {"created": True, **row}
    except Exception as e:
        return {"created": False, "error": str(e)}


class BearerAuthMiddleware:
    """Pure-ASGI JWT gate — accepts tokens minted by `ingest create-token`."""

    def __init__(self, app, jwt_secret: str | None) -> None:
        self.app = app
        self.jwt_secret = jwt_secret

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.jwt_secret is None:
            await self.app(scope, receive, send)
            return
        if scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode()
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        try:
            pyjwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        except pyjwt.PyJWTError:
            await JSONResponse({"error": "unauthorized"}, status_code=401)(scope, receive, send)
            return
        request_token.set(token)        # forward to Hasura → client role gates read/write
        await self.app(scope, receive, send)


async def _health(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def build_app():
    app = mcp.streamable_http_app()
    app.routes.append(Route("/healthz", _health, methods=["GET"]))
    app.add_middleware(BearerAuthMiddleware, jwt_secret=settings.jwt_secret)
    return app


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    if settings.jwt_secret is None:
        log.warning(
            "HASURA_JWT_SECRET is not set — the MCP endpoint is UNAUTHENTICATED."
        )
    log.info("limoza-vDB MCP server on http://%s:%s/mcp (GraphQL: %s)",
             settings.host, settings.port, settings.graphql_url)
    uvicorn.run(build_app(), host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
