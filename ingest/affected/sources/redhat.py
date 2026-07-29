"""Red Hat CSAF VEX → affected (coord=purl, full VEX status).

For every product in a CVE's VEX we emit one row carrying the canonical status
(not_affected / under_investigation / affected / fixed / wont_fix), the el-release,
and — for fixes — the RPM EVR. This is the source that gives us the explicit
``not_affected`` statements that kill false positives.

Product resolution (CSAF product_tree):
  product_status buckets hold product_ids → resolved via `relationships`
  (product_reference = the package, relates_to = the platform) into the package's
  purl (carries name + EVR + epoch) and the platform's CPE (→ el-release).
Per file we de-duplicate to one row per (package, release, status, fixed) — the
per-arch/per-stream variants collapse.
"""
import glob
import json
import re
from pathlib import Path

from ingest.affected import row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "redhat"

_EL = re.compile(r"enterprise_linux(?:_\w+)?:(\d+)(?:\.(\d+))?")   # base + _eus/_aus/_e4s/_tus/_els
_DIST = re.compile(r"\.el(\d+(?:_\d+)?)")                           # dist tag in an RPM version


def _dist_tag(evr: str | None):
    """Release from the RPM dist tag — authoritative, matches `rpm -q`.
    '140.9.0-1.el10_0' → 'el10_0' ; '3.5.10-115.el6_2' → 'el6_2' ; '...el6' → 'el6'."""
    if not evr:
        return None
    m = _DIST.search(evr)
    return f"el{m.group(1)}" if m else None


def _release(cpe: str | None):
    """Fallback release from a Red Hat platform CPE (incl. EUS/AUS/E4S/TUS/ELS).
    'enterprise_linux_eus:10.0' → 'el10_0' ; 'enterprise_linux:9' → 'el9'."""
    if not cpe:
        return None
    m = _EL.search(cpe)
    if not m:
        return None
    return f"el{m.group(1)}" + (f"_{m.group(2)}" if m.group(2) else "")


def _from_purl(purl: str):
    """pkg:rpm/redhat/kernel-headers@5.14.0-70.105.1.el9_0?arch=x&epoch=0
       → (name, evr, purl_base)."""
    head, _, qs = purl.partition("?")
    base_ver, _, ver = head.partition("@")
    name = base_ver.rsplit("/", 1)[-1]
    epoch = next((kv.split("=", 1)[1] for kv in qs.split("&") if kv.startswith("epoch=")), None)
    evr = f"{epoch}:{ver}" if (ver and epoch) else (ver or None)
    return name, evr, base_ver


def _name_from_id(pkgpart: str):
    """Best-effort package name from a bare product_id part (no purl)."""
    m = re.match(r"^(.+?)-\d", pkgpart)
    return m.group(1) if m else (pkgpart or None)


def _index_tree(pt: dict):
    cpe_by_id, purl_by_id = {}, {}

    def walk(branches):
        for b in branches or []:
            prod = b.get("product") or {}
            pid = prod.get("product_id")
            pih = prod.get("product_identification_helper") or {}
            if pid and pih.get("cpe"):
                cpe_by_id[pid] = pih["cpe"]
            if pid and pih.get("purl"):
                purl_by_id[pid] = pih["purl"]
            walk(b.get("branches"))

    walk(pt.get("branches"))
    rel = {}
    for r in pt.get("relationships") or []:
        fpn = (r.get("full_product_name") or {}).get("product_id")
        if fpn:
            rel[fpn] = (r.get("product_reference"), r.get("relates_to_product_reference"))
    return cpe_by_id, purl_by_id, rel


def _resolve(pid, cpe_by_id, purl_by_id, rel):
    pkg_ref, plat_ref = rel.get(pid, (None, None))
    if plat_ref is None and ":" in pid:
        plat_ref = pid.split(":", 1)[0]
    purl = purl_by_id.get(pkg_ref) if pkg_ref else None
    if purl and purl.startswith("pkg:rpm"):
        name, evr, base = _from_purl(purl)
    else:
        pkgpart = pid.split(":", 1)[1] if ":" in pid else pid
        name, evr = _name_from_id(pkgpart), None
        base = f"pkg:rpm/redhat/{name}" if name else None
    # dist tag from the version is authoritative (gives the minor stream el9_2);
    # platform CPE is the fallback for no-version (known_affected) products.
    release = _dist_tag(evr) or _release(cpe_by_id.get(plat_ref))
    return name, release, base, evr


def _status_of(pid, ps, fixstate_by_pid, mitig_by_pid, flag_by_pid):
    """→ (canonical status, status_raw, justification). status_raw is Red Hat's fix-state
    wording (Affected / Fix deferred / Will not fix / Out of support scope) taken from the
    no_fix_planned/none_available remediation; the workaround/mitigation prose goes to
    justification, never into status_raw."""
    if pid in ps["_not"]:
        return st.NOT_AFFECTED, None, st.CSAF_JUSTIFICATION.get(flag_by_pid.get(pid))
    if pid in ps["_inv"]:
        return st.UNDER_INVESTIGATION, None, None
    if pid in ps["_fixed"]:
        return st.FIXED, None, None
    if pid in ps["_aff"]:
        cat, det = fixstate_by_pid.get(pid, (None, None))
        return st.from_csaf_remediation(cat, det), det, mitig_by_pid.get(pid)
    return None, None, None


def _file_rows(d: dict):
    vulns = d.get("vulnerabilities") or []
    if not vulns:
        return
    v = vulns[0]
    cid = normalize(v.get("cve") or "")
    if not cid:
        return
    raw = v.get("product_status") or {}
    ps = {
        "_aff":   set(raw.get("known_affected") or []),
        "_not":   set(raw.get("known_not_affected") or []),
        "_inv":   set(raw.get("under_investigation") or []),
        "_fixed": set(raw.get("fixed") or []),
    }
    # Red Hat splits a product's remediations across categories. The FIX-STATE lives in
    # no_fix_planned / none_available — a controlled code (Will not fix / Out of support scope /
    # Fix deferred / Affected) that drives status + status_raw; no_fix_planned wins over
    # none_available (more authoritative) regardless of array order. workaround / mitigation carry
    # the how-to-mitigate PROSE, which belongs in justification, never in status_raw.
    fixstate_by_pid, mitig_by_pid = {}, {}
    for r in v.get("remediations") or []:
        cat, det = r.get("category"), r.get("details")
        for pid in r.get("product_ids") or []:
            if cat in ("no_fix_planned", "none_available"):
                cur = fixstate_by_pid.get(pid)
                if cur is None or (cat == "no_fix_planned" and cur[0] != "no_fix_planned"):
                    fixstate_by_pid[pid] = (cat, det)
            elif cat in ("workaround", "mitigation"):
                mitig_by_pid.setdefault(pid, det)
    flag_by_pid = {}
    for fl in v.get("flags") or []:
        for pid in fl.get("product_ids") or []:
            flag_by_pid.setdefault(pid, fl.get("label"))

    cpe_by_id, purl_by_id, rel = _index_tree(d.get("product_tree") or {})

    seen = set()
    for pid in (ps["_aff"] | ps["_not"] | ps["_inv"] | ps["_fixed"]):
        status, status_raw, just = _status_of(pid, ps, fixstate_by_pid, mitig_by_pid, flag_by_pid)
        if not status:
            continue
        name, release, base, evr = _resolve(pid, cpe_by_id, purl_by_id, rel)
        if not name or name == "red_hat_products":   # vendor umbrella "all RH products", not a package
            continue
        fixed = evr if status == st.FIXED else None
        key = (name, release, status, fixed)
        if key in seen:
            continue
        seen.add(key)
        yield row(
            cve_id=cid, coord="purl", ecosystem="rpm", package=name, purl=base,
            release=release, introduced="0", fixed=fixed, version_scheme="rpm",
            status=status, status_raw=status_raw, justification=just,
            source=SOURCE, status_source="own", origin=ORIGIN,
        )


def extract(conn, dirs):
    base = Path(dirs["redhat"]) / "vex"
    for f in glob.iglob(str(base / "**" / "cve-*.json"), recursive=True):
        try:
            d = json.loads(Path(f).read_bytes())
        except Exception:
            continue
        yield from _file_rows(d)
