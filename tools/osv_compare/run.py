"""Compare OSV advisory data against our DB for a given CVE.

Usage:
    python tools/osv_compare.py CVE-2026-31431 advisory_ids.csv

CSV format (one column, with or without header):
    advisory_id
    RLSA-2026:13577
    USN-8220-1
    ...

OSV data is cached in _osv_cache_<CVE>.json next to the CSV file.
Output is written to _osv_delta_<CVE>.md.

Requires CVEDB_GRAPHQL_TOKEN and CVEDB_GRAPHQL_URL in env (or .env file).
"""
import sys, os, csv, json, pathlib, collections, urllib.request
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

OSV_API  = "https://api.osv.dev/v1/vulns"
GQL      = os.environ.get("CVEDB_GRAPHQL_URL", "http://localhost:8080/v1/graphql")
TOKEN    = os.environ.get("CVEDB_GRAPHQL_TOKEN", "")

ECO_TO_CPE = {
    "Debian:11":                          "cpe:2.3:o:debian:debian_linux:11:",
    "Debian:12":                          "cpe:2.3:o:debian:debian_linux:12:",
    "Debian:13":                          "cpe:2.3:o:debian:debian_linux:13:",
    "Debian:14":                          "cpe:2.3:o:debian:debian_linux:14:",
    "Ubuntu:14.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:14.04:",
    "Ubuntu:Pro:14.04:LTS":               "cpe:2.3:o:canonical:ubuntu_linux:14.04:",
    "Ubuntu:16.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:16.04:",
    "Ubuntu:Pro:16.04:LTS":               "cpe:2.3:o:canonical:ubuntu_linux:16.04:",
    "Ubuntu:18.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:18.04:",
    "Ubuntu:Pro:18.04:LTS":               "cpe:2.3:o:canonical:ubuntu_linux:18.04:",
    "Ubuntu:20.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:20.04:",
    "Ubuntu:Pro:20.04:LTS":               "cpe:2.3:o:canonical:ubuntu_linux:20.04:",
    "Ubuntu:22.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:22.04:",
    "Ubuntu:24.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:24.04:",
    "Ubuntu:25.10":                       "cpe:2.3:o:canonical:ubuntu_linux:25.10:",
    "Ubuntu:26.04:LTS":                   "cpe:2.3:o:canonical:ubuntu_linux:26.04:",
    "Alpine:v3.23":                       "cpe:2.3:o:alpinelinux:alpine_linux:3.23:",
    "Alpine:edge":                        "cpe:2.3:o:alpinelinux:alpine_linux:edge:",
    "Rocky Linux:8":                      "cpe:2.3:o:rocky:linux:8",
    "Rocky Linux:9":                      "cpe:2.3:o:rocky:linux:9",
    "Rocky Linux:10":                     "cpe:2.3:o:rocky:linux:10",
    "Red Hat:enterprise_linux:8::baseos":     "cpe:2.3:o:redhat:enterprise_linux:8:*:baseos:",
    "Red Hat:enterprise_linux:8::crb":        "cpe:2.3:a:redhat:enterprise_linux:8:*:crb:",
    "Red Hat:enterprise_linux:8::nfv":        "cpe:2.3:a:redhat:enterprise_linux:8:*:nfv:",
    "Red Hat:enterprise_linux:8::realtime":   "cpe:2.3:a:redhat:enterprise_linux:8:*:realtime:",
    "Red Hat:enterprise_linux:9::appstream":  "cpe:2.3:a:redhat:enterprise_linux:9:*:appstream:",
    "Red Hat:enterprise_linux:9::baseos":     "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:",
    "Red Hat:enterprise_linux:9::crb":        "cpe:2.3:a:redhat:enterprise_linux:9:*:crb:",
    "Red Hat:enterprise_linux:9::nfv":        "cpe:2.3:a:redhat:enterprise_linux:9:*:nfv:",
    "Red Hat:enterprise_linux:9::realtime":   "cpe:2.3:a:redhat:enterprise_linux:9:*:realtime:",
    "Red Hat:enterprise_linux:10.1":          "cpe:2.3:o:redhat:enterprise_linux:10.1:",
    "Red Hat:enterprise_linux:10.2":          "cpe:2.3:o:redhat:enterprise_linux:10.2:",
    "Red Hat:enterprise_linux_eus:10.0":      "cpe:2.3:o:redhat:enterprise_linux_eus:10.0:",
    "Red Hat:rhel_aus:8.4::baseos":           "cpe:2.3:o:redhat:rhel_aus:8.4:",
    "Red Hat:rhel_aus:8.6::baseos":           "cpe:2.3:o:redhat:rhel_aus:8.6:",
    "Red Hat:rhel_e4s:8.6::baseos":           "cpe:2.3:o:redhat:rhel_e4s:8.6:",
    "Red Hat:rhel_e4s:8.8::baseos":           "cpe:2.3:o:redhat:rhel_e4s:8.8:",
    "Red Hat:rhel_e4s:9.0::appstream":        "cpe:2.3:a:redhat:rhel_e4s:9.0:*:appstream:",
    "Red Hat:rhel_e4s:9.0::baseos":           "cpe:2.3:o:redhat:rhel_e4s:9.0:",
    "Red Hat:rhel_e4s:9.0::nfv":              "cpe:2.3:a:redhat:rhel_e4s:9.0:*:nfv:",
    "Red Hat:rhel_e4s:9.0::realtime":         "cpe:2.3:a:redhat:rhel_e4s:9.0:*:realtime:",
    "Red Hat:rhel_e4s:9.2::appstream":        "cpe:2.3:a:redhat:rhel_e4s:9.2:*:appstream:",
    "Red Hat:rhel_e4s:9.2::baseos":           "cpe:2.3:o:redhat:rhel_e4s:9.2:",
    "Red Hat:rhel_e4s:9.2::nfv":              "cpe:2.3:a:redhat:rhel_e4s:9.2:*:nfv:",
    "Red Hat:rhel_e4s:9.2::realtime":         "cpe:2.3:a:redhat:rhel_e4s:9.2:*:realtime:",
    "Red Hat:rhel_eus:9.4::appstream":        "cpe:2.3:a:redhat:rhel_eus:9.4:*:appstream:",
    "Red Hat:rhel_eus:9.4::baseos":           "cpe:2.3:o:redhat:rhel_eus:9.4:",
    "Red Hat:rhel_eus:9.4::crb":              "cpe:2.3:a:redhat:rhel_eus:9.4:*:crb:",
    "Red Hat:rhel_eus:9.4::nfv":              "cpe:2.3:a:redhat:rhel_eus:9.4:*:nfv:",
    "Red Hat:rhel_eus:9.4::realtime":         "cpe:2.3:a:redhat:rhel_eus:9.4:*:realtime:",
    "Red Hat:rhel_eus:9.6::appstream":        "cpe:2.3:a:redhat:rhel_eus:9.6:*:appstream:",
    "Red Hat:rhel_eus:9.6::baseos":           "cpe:2.3:o:redhat:rhel_eus:9.6:",
    "Red Hat:rhel_eus:9.6::crb":              "cpe:2.3:a:redhat:rhel_eus:9.6:*:crb:",
    "Red Hat:rhel_eus:9.6::nfv":              "cpe:2.3:a:redhat:rhel_eus:9.6:*:nfv:",
    "Red Hat:rhel_eus:9.6::realtime":         "cpe:2.3:a:redhat:rhel_eus:9.6:*:realtime:",
    "Red Hat:rhel_tus:8.6::baseos":           "cpe:2.3:o:redhat:rhel_tus:8.6:",
    "Red Hat:rhel_tus:8.8::baseos":           "cpe:2.3:o:redhat:rhel_tus:8.8:",
}

ICON = {
    "match":               "OK",
    "match_cloud_variant": "OK (cloud variant)",
    "version_diff":        "VERSION DIFF",
    "only_osv":            "only OSV",
    "only_ours":           "only ours",
}


def gql(query: str) -> dict:
    req = urllib.request.Request(
        GQL,
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
    )
    return json.loads(urllib.request.urlopen(req).read())


def fetch_osv(adv_id: str) -> dict:
    try:
        url = f"{OSV_API}/{urllib.request.quote(adv_id, safe='')}"
        return json.loads(urllib.request.urlopen(url, timeout=15).read())
    except Exception as e:
        return {"error": str(e)}


def load_advisory_ids(csv_path: pathlib.Path) -> list[str]:
    ids = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row:
                continue
            val = row[0].strip()
            if val and val.lower() != "advisory_id":
                ids.append(val)
    return ids


def load_or_fetch_cache(cve: str, advisory_ids: list[str], cache_path: pathlib.Path) -> dict:
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    missing = [i for i in advisory_ids if i not in cache]
    if missing:
        print(f"Fetching {len(missing)} advisories from OSV...")
        for i, adv_id in enumerate(missing, 1):
            print(f"  [{i}/{len(missing)}] {adv_id}", end="\r")
            cache[adv_id] = fetch_osv(adv_id)
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
        print()
    return cache


def parse_osv(cache: dict):
    fix = collections.defaultdict(lambda: collections.defaultdict(set))
    aff = collections.defaultdict(lambda: collections.defaultdict(set))
    for entry in cache.values():
        if "error" in entry:
            continue
        for a in entry.get("affected", []):
            eco  = a.get("package", {}).get("ecosystem", "")
            name = a.get("package", {}).get("name", "")
            has_fix = False
            for rng in a.get("ranges", []):
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fix[eco][name].add(ev["fixed"])
                        has_fix = True
            if not has_fix:
                aff[eco][name].add("affected")
    return fix, aff


def load_our_db(cve: str):
    r = gql('{fix:cve_fix(where:{cve_id:{_eq:"%s"}},distinct_on:product_id){product_id}'
            ' affected:cve_affected(where:{cve_id:{_eq:"%s"}},distinct_on:product_id){product_id}}' % (cve, cve))
    all_pids = list({x["product_id"] for x in r["data"]["fix"]} |
                    {x["product_id"] for x in r["data"]["affected"]})

    r2 = gql('{ product(where:{id:{_in:%s}}){id cpe} }' % json.dumps(all_pids))
    cpe_to_pid = {p["cpe"]: p["id"] for p in r2["data"]["product"]}

    rp = gql('{ source(where:{vendor:{_eq:"rhel_proxy"}}){id} }')
    proxy_ids = [s["id"] for s in rp["data"]["source"]]

    r3 = gql('{cve_fix(where:{cve_id:{_eq:"%s"},source_id:{_nin:%s}}){product_id package_name fix_at}}' % (cve, json.dumps(proxy_ids)))
    our_fix = collections.defaultdict(dict)
    for row in r3["data"]["cve_fix"]:
        our_fix[row["product_id"]][row["package_name"]] = row["fix_at"]

    r4 = gql('{cve_affected(where:{cve_id:{_eq:"%s"},source_id:{_nin:%s}}){product_id package_name status}}' % (cve, json.dumps(proxy_ids)))
    our_aff = collections.defaultdict(dict)
    for row in r4["data"]["cve_affected"]:
        our_aff[row["product_id"]][row["package_name"]] = row["status"]

    return cpe_to_pid, our_fix, our_aff


def compare(osv_fix, osv_aff, cpe_to_pid, our_fix, our_aff):
    rows = []
    for eco_label, cpe_prefix in sorted(ECO_TO_CPE.items()):
        matching_pids = [pid for cpe, pid in cpe_to_pid.items() if cpe.startswith(cpe_prefix)]
        eco_osv_fix = osv_fix.get(eco_label, {})
        eco_osv_aff = osv_aff.get(eco_label, {})
        our_pkgs_fix, our_pkgs_aff = {}, {}
        for pid in matching_pids:
            our_pkgs_fix.update(our_fix[pid])
            our_pkgs_aff.update(our_aff[pid])

        all_pkgs = sorted(set(eco_osv_fix) | set(eco_osv_aff) | set(our_pkgs_fix) | set(our_pkgs_aff))
        for pkg in all_pkgs:
            in_osv_fix = pkg in eco_osv_fix
            in_osv_aff = pkg in eco_osv_aff
            in_our_fix = pkg in our_pkgs_fix
            in_our_aff = pkg in our_pkgs_aff

            osv_ver = ", ".join(sorted(eco_osv_fix[pkg])) if in_osv_fix else ("affected" if in_osv_aff else "—")
            our_ver = our_pkgs_fix[pkg] if in_our_fix else (our_pkgs_aff[pkg] if in_our_aff else "—")

            if (in_osv_fix or in_osv_aff) and (in_our_fix or in_our_aff):
                if in_osv_fix and in_our_fix:
                    osv_v = eco_osv_fix[pkg]
                    our_v = our_pkgs_fix[pkg]
                    our_s = our_v.split(":", 1)[-1] if ":" in our_v else our_v
                    osv_s = {v.split(":", 1)[-1] if ":" in v else v for v in osv_v}
                    if our_s in osv_s or our_v in osv_v:
                        status = "match"
                    elif our_s in {v.split(".cloud")[0] for v in osv_s}:
                        status = "match_cloud_variant"
                    else:
                        status = "version_diff"
                else:
                    status = "match"
            elif in_osv_fix or in_osv_aff:
                status = "only_osv"
            else:
                status = "only_ours"

            cpe_short = cpe_prefix.rstrip(":*").replace("cpe:2.3:o:", "").replace("cpe:2.3:a:", "")
            rows.append((eco_label, cpe_short, pkg, osv_ver, our_ver, status))
    return rows


def write_output(rows: list, out: pathlib.Path, cve: str):
    counts = collections.Counter(r[5] for r in rows)
    lines = [
        f"# Delta OSV vs Ingest (excl. rhel_proxy) — {cve}", "",
        "| OS | CPE | Package | OSV | Ingest | Status |",
        "|---|---|---|---|---|---|",
    ]
    for eco, cpe, pkg, osv_v, our_v, status in rows:
        lines.append(f"| {eco} | `{cpe}` | `{pkg}` | {osv_v} | {our_v} | {ICON.get(status, status)} |")
    lines += ["", "## Summary", "", "| Status | Count |", "|---|---|"]
    for s in ["match", "match_cloud_variant", "version_diff", "only_osv", "only_ours"]:
        lines.append(f"| {ICON[s]} | {counts.get(s, 0)} |")
    out.write_text("\n".join(lines), encoding="utf-8")

    total = sum(counts.values())
    print(f"\nWritten {total} rows to {out}")
    for s in ["match", "match_cloud_variant", "version_diff", "only_osv", "only_ours"]:
        n = counts.get(s, 0)
        print(f"  {ICON[s]:35} {n:4d}  ({n/total*100:.0f}%)" if total else f"  {ICON[s]}")


def main():
    if len(sys.argv) < 3:
        print("Usage: python tools/osv_compare/run.py <CVE-ID> <advisory_ids.csv>")
        sys.exit(1)

    cve      = sys.argv[1].upper()
    csv_path = pathlib.Path(sys.argv[2])
    out_dir  = pathlib.Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)
    cache    = out_dir / f"_osv_cache_{cve}.json"
    out      = out_dir / f"_osv_delta_{cve}.md"

    print(f"CVE: {cve}")
    advisory_ids = load_advisory_ids(csv_path)
    print(f"Advisory IDs in CSV: {len(advisory_ids)}")

    osv_data          = load_or_fetch_cache(cve, advisory_ids, cache)
    osv_fix, osv_aff  = parse_osv(osv_data)
    cpe_to_pid, our_fix, our_aff = load_our_db(cve)
    rows              = compare(osv_fix, osv_aff, cpe_to_pid, our_fix, our_aff)
    write_output(rows, out, cve)


if __name__ == "__main__":
    main()
