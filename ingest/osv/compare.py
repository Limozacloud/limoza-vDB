"""Compare OSV advisory data vs DB for a given CVE."""
import json
import re
from collections import Counter
from pathlib import Path

from ingest.db import get_conn


def _load_index(base: Path) -> dict:
    p = base / "osv_index.json"
    if not p.exists():
        print("  OSV: no index found — run `sync osv` first")
        return {}
    idx = json.loads(p.read_bytes())
    print(f"  OSV: index loaded ({len(idx)} CVEs)")
    return idx


def _parse_advisory(path: Path) -> dict | None:
    try:
        data   = json.loads(path.read_bytes())
        adv_id = data.get("id", "")
        if not adv_id or adv_id.startswith("CVE-"):
            return None
        packages = []
        for affected in (data.get("affected") or []):
            pkg  = affected.get("package") or {}
            name = pkg.get("name", "")
            eco  = pkg.get("ecosystem", "")
            purl = pkg.get("purl", "")
            if not name:
                continue
            fix_version = None
            for rng in (affected.get("ranges") or []):
                for ev in (rng.get("events") or []):
                    if "fixed" in ev:
                        fix_version = ev["fixed"]
            packages.append({
                "name": name, "ecosystem": eco,
                "purl": purl, "fix_version": fix_version,
            })
        return {
            "id":        adv_id,
            "summary":   data.get("summary", ""),
            "published": (data.get("published") or "")[:10],
            "packages":  packages,
        }
    except Exception:
        return None


def _query_db(cve_id: str) -> tuple[list[dict], list[dict]]:
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT la.source, la.advisory_id, la.url, la.published
                FROM lve_cve lc
                JOIN lve_advisories la ON la.lve_id = lc.lve_id
                WHERE lc.cve_id = %s
                ORDER BY la.source, la.advisory_id
            """, (cve_id,))
            advisories = [
                {"source": r[0], "advisory_id": r[1], "url": r[2] or "",
                 "published": str(r[3])[:10] if r[3] else ""}
                for r in cur.fetchall()
            ]
            cur.execute("""
                SELECT lp.source, lp.purl, lp.remediation_state, lp.advisory_ref, lp.ranges
                FROM lve_cve lc
                JOIN lve_packages lp ON lp.lve_id = lc.lve_id
                WHERE lc.cve_id = %s
                ORDER BY lp.source, lp.purl
            """, (cve_id,))
            packages = [
                {"source": r[0], "purl": r[1], "remediation_state": r[2],
                 "advisory_ref": r[3], "fix_version": _extract_fix(r[4])}
                for r in cur.fetchall()
            ]
    finally:
        conn.close()
    return advisories, packages


def _extract_fix(ranges) -> str | None:
    if not ranges:
        return None
    for rng in (ranges if isinstance(ranges, list) else []):
        for ev in (rng.get("events") or []):
            if "fixed" in ev:
                return ev["fixed"]
    return None


def _purl_name(purl: str) -> str:
    return purl.split("/")[-1].split("@")[0].split("?")[0] if purl else ""


def _purl_distro(purl: str) -> str:
    if "?distro=" in purl:
        return purl.split("?distro=")[1].split("&")[0]
    return ""


_ECO_TO_SOURCE = {
    "AlmaLinux":   "almalinux",
    "Rocky Linux": "rocky",
    "Red Hat":     "redhat",
    "Debian":      "debian",
    "Ubuntu":      "ubuntu",
    "Alpine":      "alpine",
    "Oracle Linux": "oracle",
}

_DEB_CODENAME = {
    "9": "stretch", "10": "buster", "11": "bullseye",
    "12": "bookworm", "13": "trixie", "14": "forky",
}

_UBU_CODENAME = {
    "16.04": "xenial", "18.04": "bionic", "20.04": "focal",
    "22.04": "jammy",  "24.04": "noble",  "25.10": "questing",
    "26.04": "resolute",
}


def _eco_source(eco: str) -> str:
    for prefix, src in _ECO_TO_SOURCE.items():
        if eco.startswith(prefix):
            return src
    return eco.lower().split(":")[0]


def _osv_distro(ecosystem: str) -> str:
    """Normalize an OSV ecosystem string to match our PURL ?distro= qualifier."""
    eco = ecosystem.lower()
    if eco.startswith("red hat:"):
        # e.g. "Red Hat:enterprise_linux:9::appstream" → el9
        #      "Red Hat:rhel_aus:8.4::appstream"       → el8.4
        #      "Red Hat:rhel_e4s:8.8::appstream"       → el8.8
        #      "Red Hat:rhel_els:7"                    → el7
        parts = ecosystem.split(":")
        if len(parts) >= 3:
            ver_raw = parts[2].split("::")[0]
            if re.match(r"^\d+\.\d+$", ver_raw):
                return f"el{ver_raw}"   # EUS/AUS/TUS: preserve major.minor
            major = ver_raw.split(".")[0]
            if major.isdigit():
                return f"el{major}"     # base stream: major only
        return ""
    if eco.startswith("almalinux:"):
        return f"almalinux-{ecosystem.split(':')[1]}"
    if eco.startswith("rocky linux:"):
        return f"rocky-{ecosystem.split(':')[1].strip()}"
    if eco.startswith("debian:"):
        ver = ecosystem.split(":")[1]
        return _DEB_CODENAME.get(ver, f"debian-{ver}")
    if eco.startswith("ubuntu:"):
        # "Ubuntu:22.04:LTS" → jammy  |  "Ubuntu:Pro:20.04:LTS" → focal
        for part in ecosystem.split(":")[1:]:
            if re.match(r"^\d+\.\d+$", part):
                return _UBU_CODENAME.get(part, part)
        return ""
    if eco.startswith("alpine:"):
        return ecosystem.split(":")[1]
    if eco.startswith("oracle linux:"):
        return f"ol{ecosystem.split(':')[1].strip()}"
    return ""


def verify(cve_id: str, dirs: dict) -> None:
    base = Path(dirs["osv"])

    # ── OSV ──────────────────────────────────────────────────────────────────
    index = _load_index(base)
    files = index.get(cve_id, [])
    if not files:
        print(f"  OSV: {cve_id} not in index")

    osv_advs: list[dict] = []
    osv_pkgs: list[dict] = []
    for rel in files:
        entry = _parse_advisory(base / rel)
        if not entry:
            continue
        osv_advs.append({"id": entry["id"], "summary": entry["summary"],
                         "published": entry["published"]})
        for p in entry["packages"]:
            osv_pkgs.append({**p, "advisory": entry["id"]})

    print(f"  OSV: {len(osv_advs)} advisories, {len(osv_pkgs)} package entries")

    # ── DB ───────────────────────────────────────────────────────────────────
    db_advs, db_pkgs = _query_db(cve_id)
    print(f"  DB:  {len(db_advs)} advisories, {len(db_pkgs)} packages")

    # ── Advisory comparison ───────────────────────────────────────────────────
    osv_adv_ids = {a["id"] for a in osv_advs}
    db_adv_ids  = {a["advisory_id"] for a in db_advs}
    only_osv    = sorted(osv_adv_ids - db_adv_ids)
    only_db     = sorted(db_adv_ids  - osv_adv_ids)
    both        = sorted(osv_adv_ids & db_adv_ids)

    # ── Package comparison (keyed by source + name + distro) ─────────────────
    osv_map: dict[tuple, dict] = {}
    for p in osv_pkgs:
        src    = _eco_source(p["ecosystem"])
        distro = _osv_distro(p["ecosystem"])
        key    = (src, p["name"], distro)
        if key not in osv_map or p["fix_version"]:
            osv_map[key] = p

    db_map: dict[tuple, dict] = {}
    for p in db_pkgs:
        key = (p["source"], _purl_name(p["purl"]), _purl_distro(p["purl"]))
        if key not in db_map or p.get("fix_version"):
            db_map[key] = p

    pkg_rows = []
    for key in sorted(set(osv_map) | set(db_map)):
        src, name, distro = key
        in_osv  = key in osv_map
        in_db   = key in db_map
        osv_fix = osv_map[key]["fix_version"] if in_osv else None
        db_fix  = db_map[key].get("fix_version") if in_db else None
        db_st   = db_map[key].get("remediation_state", "") if in_db else ""

        if in_osv and in_db:
            ov = (osv_fix or "").lstrip("0:")
            dv = (db_fix  or "").lstrip("0:")
            status = "match" if (not ov or not dv or ov == dv) else "diff"
        elif in_osv:
            status = "only_osv"
        else:
            status = "only_db"

        pkg_rows.append((src, name, distro, osv_fix or "—", db_fix or "—", db_st, status))

    # ── Output ───────────────────────────────────────────────────────────────
    print()
    print(f"{'═'*60}")
    print(f"  {cve_id}  OSV vs DB")
    print(f"{'═'*60}")

    print(f"\nAdvisories  OSV:{len(osv_advs)}  DB:{len(db_advs)}  "
          f"both:{len(both)}  only-OSV:{len(only_osv)}  only-DB:{len(only_db)}")

    if only_osv:
        osv_by_id = {a["id"]: a for a in osv_advs}
        print("\n  In OSV but not DB:")
        for aid in only_osv:
            a = osv_by_id.get(aid, {})
            print(f"    {aid:40}  {a.get('published','')}  {a.get('summary','')[:60]}")

    if only_db:
        db_by_id = {a["advisory_id"]: a for a in db_advs}
        print("\n  In DB but not OSV:")
        for aid in only_db:
            a = db_by_id.get(aid, {})
            print(f"    {aid:40}  [{a.get('source','')}]  {a.get('url','')[:60]}")

    counts = Counter(r[6] for r in pkg_rows)
    print(f"\nPackages  total:{len(pkg_rows)}  match:{counts['match']}  "
          f"diff:{counts['diff']}  only-OSV:{counts['only_osv']}  only-DB:{counts['only_db']}")

    non_match = [r for r in pkg_rows if r[6] != "match"]
    if non_match:
        print(f"\n  {'Source':<12} {'Distro':<22} {'Package':<35} {'OSV fix':<28} {'DB fix':<28} {'Status'}")
        print(f"  {'-'*12} {'-'*22} {'-'*35} {'-'*28} {'-'*28} {'-'*10}")
        for src, name, distro, osv_fix, db_fix, db_st, status in non_match:
            icon = {"diff": "DIFF", "only_osv": "only-OSV", "only_db": "only-DB"}.get(status, status)
            print(f"  {src:<12} {distro:<22} {name:<35} {osv_fix:<28} {db_fix:<28} {icon}")
    else:
        print("  All packages match ✓")
