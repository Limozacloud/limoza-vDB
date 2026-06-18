"""Compare trivy scan results against our DB for all CVEs on Ubuntu 22.04.

Usage:
    python tools/osv_compare/trivy_compare.py <trivy_csv>

Output: tools/osv_compare/output/_trivy_delta_<date>.md
"""
import sys, os, csv, json, re, pathlib, collections, urllib.request
from datetime import date


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

GQL   = os.environ.get("CVEDB_GRAPHQL_URL", "http://localhost:8080/v1/graphql")
TOKEN = os.environ.get("CVEDB_GRAPHQL_TOKEN", "")
UBUNTU_22_CPE = "cpe:2.3:o:canonical:ubuntu_linux:22.04:"

KERNEL_PKG = re.compile(r'^linux-(image|modules|headers|modules-extra|tools)-\d+\.\d+')


def gql(query: str) -> dict:
    req = urllib.request.Request(
        GQL,
        data=json.dumps({"query": query}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
    )
    return json.loads(urllib.request.urlopen(req).read())


def normalize(name: str) -> str:
    if KERNEL_PKG.match(name):
        return "linux"
    if name in ("linux-image-generic", "linux-headers-generic", "linux-generic",
                "linux-tools-generic", "linux-modules-extra-generic"):
        return "linux"
    return name


def read_trivy(path: pathlib.Path):
    data = collections.defaultdict(dict)
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            data[row["VulnID"]][row["Package"]] = (row["InstalledVersion"], row.get("FixedVersion", ""))
    return data


def get_ubuntu_pids() -> list:
    r = gql(f'{{ product(where:{{cpe:{{_like:"{UBUNTU_22_CPE}%"}}}}){{id}} }}')
    return [p["id"] for p in r["data"]["product"]]


def get_our_data(cves: list, pids: list) -> dict:
    cj, pj = json.dumps(cves), json.dumps(pids)
    r = gql(f'''{{
        fix: cve_fix(where:{{cve_id:{{_in:{cj}}},product_id:{{_in:{pj}}}}}){{cve_id package_name fix_at}}
        aff: cve_affected(where:{{cve_id:{{_in:{cj}}},product_id:{{_in:{pj}}}}}){{cve_id package_name status}}
    }}''')
    out = collections.defaultdict(dict)
    for row in r["data"]["fix"]:
        out[row["cve_id"]][row["package_name"]] = row["fix_at"]
    for row in r["data"]["aff"]:
        cid, pkg = row["cve_id"], row["package_name"]
        if pkg not in out[cid]:
            out[cid][pkg] = row["status"]
    return out


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/osv_compare/trivy_compare.py <trivy_csv>")
        sys.exit(1)

    csv_path = pathlib.Path(sys.argv[1])
    out_dir  = pathlib.Path(__file__).parent / "output"
    out_dir.mkdir(exist_ok=True)

    print("Reading trivy results...")
    trivy = read_trivy(csv_path)
    total_findings = sum(len(p) for p in trivy.values())
    print(f"  {len(trivy)} unique CVEs, {total_findings} package findings")

    print("Getting Ubuntu 22.04 product IDs...")
    pids = get_ubuntu_pids()
    print(f"  {len(pids)} products found")

    cves = list(trivy.keys())
    our  = {}
    batch = 50
    for i in range(0, len(cves), batch):
        chunk = cves[i:i+batch]
        print(f"  Querying CVEs {i+1}–{min(i+batch, len(cves))} of {len(cves)}...", end="\r")
        our.update(get_our_data(chunk, pids))
    print()

    rows = []
    for cve, pkgs in sorted(trivy.items()):
        our_pkgs = our.get(cve, {})
        for pkg, (inst, fix) in sorted(pkgs.items()):
            norm     = normalize(pkg)
            our_val  = our_pkgs.get(pkg) or our_pkgs.get(norm)

            if our_val is not None:
                if not fix or our_val == fix:
                    status = "match"
                else:
                    our_s = our_val.split(":", 1)[-1] if ":" in our_val else our_val
                    fix_s = fix.split(":", 1)[-1] if ":" in fix else fix
                    status = "match" if our_s == fix_s else "version_diff"
            elif our_pkgs:
                status = "pkg_missing"
            else:
                status = "cve_missing"

            rows.append((cve, pkg, norm, inst, fix or "—", our_val or "—", status))

    counts = collections.Counter(r[6] for r in rows)
    out    = out_dir / f"_trivy_delta_{date.today()}.md"

    lines = [
        f"# Trivy vs Ingest — Ubuntu 22.04 — {date.today()}", "",
        "| CVE | Package | Norm | Installed | Trivy Fix | Our Fix | Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for cve, pkg, norm, inst, fix, our_v, status in rows:
        lines.append(f"| {cve} | `{pkg}` | `{norm}` | {inst} | {fix} | {our_v} | {status} |")

    lines += ["", "## Summary", "", "| Status | Count | % |", "|---|---|---|"]
    total = len(rows)
    for s, n in sorted(counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {s} | {n} | {n/total*100:.0f}% |")

    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWritten {total} rows to {out}")
    for s, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {s:30} {n:5d}  ({n/total*100:.0f}%)")


if __name__ == "__main__":
    main()
