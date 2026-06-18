"""Compare local OSV dump vs DB for a given CVE.

Usage:
    python tools/osv_compare/local_compare.py CVE-2026-41651
    python tools/osv_compare/local_compare.py CVE-2026-41651 --osv-dir D:/osv/all

Finds all advisory files in the local OSV dump that reference the CVE,
queries GraphQL for the same CVE, and writes a comparison to output/.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path


def _load_env(path=".env"):
    try:
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())
    except FileNotFoundError:
        pass


_load_env()

OSV_API         = "https://api.osv.dev/v1/vulns"
OSV_DIR_DEFAULT = Path(os.environ.get("OSV_DUMP_DIR", "osv-dump"))
HASURA_URL      = os.environ.get("HASURA_GRAPHQL_URL", "http://localhost:8080/v1/graphql")
HASURA_SECRET   = os.environ.get("HASURA_ADMIN_SECRET", "")

GQL_QUERY = """
query CVEData($cve_id: String!) {
  lve_cve(where: { cve_id: { _eq: $cve_id } }) {
    cve_id
    lve {
      packages(order_by: [{ source: asc }, { purl: asc }]) {
        source purl affected_state remediation_state severity advisory_ref
      }
      advisories(order_by: [{ source: asc }, { advisory_id: asc }]) {
        source advisory_id url published
      }
    }
  }
}
"""

# Ecosystem label → source name in DB
ECO_TO_SOURCE = {
    "AlmaLinux":   "almalinux",
    "Rocky Linux": "rocky",
    "Red Hat":     "redhat",
    "Debian":      "debian",
    "Ubuntu":      "ubuntu",
    "Alpine":      "alpine",
    "SUSE":        "suse",
    "openSUSE":    "suse",
}


def _osv_get(id: str) -> dict | None:
    """Fetch a single OSV entry by ID. Returns None on 404/error."""
    try:
        url = f"{OSV_API}/{urllib.request.quote(id, safe='')}"
        req = urllib.request.Request(url, headers={"User-Agent": "limoza-osv-compare/1.0"})
        return json.loads(urllib.request.urlopen(req, timeout=15).read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    except Exception:
        return None


def _parse_osv_entry(data: dict) -> dict:
    """Extract advisories + packages from a single OSV JSON object."""
    packages = []
    for affected in data.get("affected") or []:
        pkg       = affected.get("package") or {}
        name      = pkg.get("name", "")
        ecosystem = pkg.get("ecosystem", "")
        purl      = pkg.get("purl", "")
        if not name:
            continue
        fix_version = None
        for rng in affected.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    fix_version = ev["fixed"]
        packages.append({
            "name": name, "ecosystem": ecosystem,
            "purl": purl, "fix_version": fix_version,
        })
    return {
        "id":       data.get("id", ""),
        "summary":  data.get("summary", ""),
        "published": data.get("published", ""),
        "packages": packages,
    }


def collect_osv_api(cve_id: str) -> tuple[list[dict], list[dict]]:
    """Discover advisory IDs via the CVE entry, then fetch each advisory."""
    print(f"  OSV API: fetching {cve_id}...")
    cve_entry = _osv_get(cve_id)

    adv_ids: list[str] = []
    if cve_entry:
        refs = (cve_entry.get("related") or []) + (cve_entry.get("aliases") or [])
        adv_ids = [r for r in refs if not r.startswith("CVE-")]
        print(f"  CVE entry found — {len(adv_ids)} related advisories")
    else:
        print(f"  CVE entry not in OSV — no advisory list available via API")

    advisories, packages = [], []
    for i, adv_id in enumerate(adv_ids, 1):
        print(f"  [{i}/{len(adv_ids)}] {adv_id}", end="\r")
        data = _osv_get(adv_id)
        if not data:
            continue
        entry = _parse_osv_entry(data)
        advisories.append({"id": entry["id"], "summary": entry["summary"], "published": entry["published"]})
        for pkg in entry["packages"]:
            packages.append({**pkg, "advisory": entry["id"]})
    if adv_ids:
        print()
    return advisories, packages


def collect_osv_local(cve_id: str, osv_dir: Path) -> tuple[list[dict], list[dict]]:
    """Fallback: scan local OSV dump directory with ripgrep."""
    print(f"  Local scan: {osv_dir}...")
    try:
        result = subprocess.run(
            ["rg", "-l", "--fixed-strings", cve_id, str(osv_dir)],
            capture_output=True, text=True, timeout=120,
        )
        files = [Path(p) for p in result.stdout.splitlines() if p.strip()]
    except FileNotFoundError:
        print("  rg not found — install ripgrep for local scan support")
        return [], []

    print(f"  {len(files)} files matched")
    advisories, packages = [], []
    for f in sorted(files):
        try:
            data = json.loads(f.read_bytes())
        except Exception:
            continue
        adv_id = data.get("id", "")
        if adv_id.startswith("CVE-"):
            continue
        refs = (data.get("related") or []) + (data.get("aliases") or []) + (data.get("upstream") or [])
        if cve_id not in refs:
            continue
        entry = _parse_osv_entry(data)
        advisories.append({"id": entry["id"], "summary": entry["summary"], "published": entry["published"]})
        for pkg in entry["packages"]:
            packages.append({**pkg, "advisory": entry["id"]})
    return advisories, packages


def collect_osv(cve_id: str, osv_dir: Path | None) -> tuple[list[dict], list[dict]]:
    """Try API first; if CVE not found there, fall back to local scan."""
    advs, pkgs = collect_osv_api(cve_id)
    if not advs and osv_dir and osv_dir.exists():
        print("  No results from API — falling back to local scan")
        advs, pkgs = collect_osv_local(cve_id, osv_dir)
    return advs, pkgs


def query_db(cve_id: str) -> dict:
    payload = json.dumps({"query": GQL_QUERY, "variables": {"cve_id": cve_id}}).encode()
    req = urllib.request.Request(
        HASURA_URL,
        data=payload,
        headers={
            "Content-Type":           "application/json",
            "x-hasura-admin-secret":  HASURA_SECRET,
        },
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
    rows = resp.get("data", {}).get("lve_cve", [])
    if not rows:
        return {"packages": [], "advisories": []}
    lve = rows[0]["lve"]
    return {"packages": lve["packages"], "advisories": lve["advisories"]}


def _eco_source(ecosystem: str) -> str:
    for prefix, source in ECO_TO_SOURCE.items():
        if ecosystem.startswith(prefix):
            return source
    return ecosystem.lower().split(":")[0]


def _purl_name(purl: str) -> str:
    """pkg:rpm/almalinux/PackageKit@1.2.6?distro=... → PackageKit"""
    if not purl:
        return ""
    p = purl.split("/")[-1].split("@")[0].split("?")[0]
    return p


def compare(osv_advs: list[dict], osv_pkgs: list[dict],
            db_advs: list[dict], db_pkgs: list[dict]) -> dict:

    # ── Advisories ──────────────────────────────────────────────────────────
    osv_adv_ids = {a["id"] for a in osv_advs}
    db_adv_ids  = {a["advisory_id"] for a in db_advs}

    only_osv_advs = sorted(osv_adv_ids - db_adv_ids)
    only_db_advs  = sorted(db_adv_ids - osv_adv_ids)
    both_advs     = sorted(osv_adv_ids & db_adv_ids)

    # ── Packages ─────────────────────────────────────────────────────────────
    # OSV key: (source, name)
    osv_pkg_map: dict[tuple, dict] = {}
    for p in osv_pkgs:
        key = (_eco_source(p["ecosystem"]), p["name"])
        if key not in osv_pkg_map or p["fix_version"]:
            osv_pkg_map[key] = p

    # DB key: (source, name from purl)
    db_pkg_map: dict[tuple, dict] = {}
    for p in db_pkgs:
        name = _purl_name(p["purl"])
        key  = (p["source"], name)
        if key not in db_pkg_map or p.get("remediation_state") == "fixed":
            db_pkg_map[key] = p

    all_keys = sorted(set(osv_pkg_map) | set(db_pkg_map))

    pkg_rows = []
    for key in all_keys:
        source, name = key
        in_osv = key in osv_pkg_map
        in_db  = key in db_pkg_map

        osv_fix = osv_pkg_map[key]["fix_version"] if in_osv else None
        # DB packages carry no scalar fix_version (fixed versions live in ranges).
        db_fix  = None
        db_pkg  = db_pkg_map[key] if in_db else {}
        db_status = (db_pkg.get("remediation_state") or db_pkg.get("affected_state") or "")

        if in_osv and in_db:
            # Normalize: strip epoch prefix "0:" for comparison
            osv_v = (osv_fix or "").lstrip("0:")
            db_v  = (db_fix or "").lstrip("0:")
            if osv_fix is None and db_status in ("not_affected", "will_not_fix"):
                status = "match"
            elif osv_v and db_v and osv_v == db_v:
                status = "match"
            elif osv_v and db_v:
                status = "version_diff"
            else:
                status = "match"  # one side has no version → accept
        elif in_osv:
            status = "only_osv"
        else:
            status = "only_db"

        pkg_rows.append({
            "source":     source,
            "name":       name,
            "osv_fix":    osv_fix,
            "db_fix":     db_fix,
            "db_status":  db_status,
            "status":     status,
        })

    return {
        "advisories": {
            "only_osv": only_osv_advs,
            "only_db":  only_db_advs,
            "both":     both_advs,
        },
        "packages": pkg_rows,
    }


def render(cve_id: str, osv_advs, osv_pkgs, db_advs, db_pkgs, result: dict, out: Path):
    from collections import Counter
    lines = [f"# OSV vs DB — {cve_id}", ""]

    # ── Advisory section ────────────────────────────────────────────────────
    adv = result["advisories"]
    lines += [
        f"## Advisories",
        f"OSV: {len(osv_advs)}  |  DB: {len(db_advs)}  |  both: {len(adv['both'])}  |  only-OSV: {len(adv['only_osv'])}  |  only-DB: {len(adv['only_db'])}",
        "",
    ]

    if adv["only_osv"]:
        lines += ["### In OSV but not DB"]
        osv_by_id = {a["id"]: a for a in osv_advs}
        for aid in adv["only_osv"]:
            a = osv_by_id.get(aid, {})
            lines.append(f"- `{aid}` — {a.get('summary', '')} ({a.get('published', '')[:10]})")
        lines.append("")

    if adv["only_db"]:
        lines += ["### In DB but not OSV"]
        db_by_id = {a["advisory_id"]: a for a in db_advs}
        for aid in adv["only_db"]:
            a = db_by_id.get(aid, {})
            lines.append(f"- `{aid}` [{a.get('source','')}]  {a.get('url','')}")
        lines.append("")

    # ── Package section ─────────────────────────────────────────────────────
    pkg_rows = result["packages"]
    counts   = Counter(r["status"] for r in pkg_rows)

    lines += [
        "## Packages",
        f"Total: {len(pkg_rows)}  |  match: {counts['match']}  |  version_diff: {counts['version_diff']}  |  only-OSV: {counts['only_osv']}  |  only-DB: {counts['only_db']}",
        "",
        "| Source | Package | OSV fix | DB fix | DB status | Result |",
        "|--------|---------|---------|--------|-----------|--------|",
    ]
    for r in pkg_rows:
        icon = {"match": "✓", "version_diff": "DIFF", "only_osv": "only-OSV", "only_db": "only-DB"}.get(r["status"], r["status"])
        lines.append(
            f"| {r['source']} | `{r['name']}` | {r['osv_fix'] or '—'} "
            f"| {r['db_fix'] or '—'} | {r['db_status']} | {icon} |"
        )

    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    return counts


def main():
    ap = argparse.ArgumentParser(description="Compare local OSV dump vs DB for a CVE")
    ap.add_argument("cve", help="CVE ID, e.g. CVE-2026-41651")
    ap.add_argument("--osv-dir", type=Path, default=OSV_DIR_DEFAULT if OSV_DIR_DEFAULT.exists() else None,
                    help="Local OSV dump directory (fallback if API has no CVE entry)")
    args = ap.parse_args()

    cve_id  = args.cve.upper()
    out_dir = Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)
    out = out_dir / f"local_compare_{cve_id}.md"

    print(f"CVE: {cve_id}")

    print("\n[OSV]")
    osv_advs, osv_pkgs = collect_osv(cve_id, args.osv_dir)
    print(f"  {len(osv_advs)} advisories, {len(osv_pkgs)} package entries")

    print("\n[DB]")
    db_data = query_db(cve_id)
    db_advs = db_data["advisories"]
    db_pkgs = db_data["packages"]
    print(f"  {len(db_advs)} advisories, {len(db_pkgs)} packages")

    print("\n[Comparing]")
    result = compare(osv_advs, osv_pkgs, db_advs, db_pkgs)
    counts = render(cve_id, osv_advs, osv_pkgs, db_advs, db_pkgs, result, out)

    adv = result["advisories"]
    print(f"  Advisories — both: {len(adv['both'])}  only-OSV: {len(adv['only_osv'])}  only-DB: {len(adv['only_db'])}")
    print(f"  Packages   — match: {counts['match']}  diff: {counts['version_diff']}  only-OSV: {counts['only_osv']}  only-DB: {counts['only_db']}")
    print(f"\n  Written: {out}")


if __name__ == "__main__":
    main()
