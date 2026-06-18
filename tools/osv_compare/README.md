# OSV / Trivy Gap Analysis

Compares what a real system reports as vulnerable (Trivy) against what our ingest delivers,
and what OSV advisories report against our ingest for a specific CVE.

## Workflow

### 1. Scan target system (Ubuntu)

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /tmp

# Create CSV conversion helper (one-time setup)
cat > ~/to_csv.py << 'EOF'
import json,sys,csv
data=json.load(sys.stdin)
w=csv.writer(sys.stdout)
w.writerow(['Package','InstalledVersion','FixedVersion','VulnID','Severity'])
for r in data.get('Results',[]):
    for v in r.get('Vulnerabilities',[]):
        w.writerow([v.get('PkgName'),v.get('InstalledVersion'),v.get('FixedVersion',''),v.get('VulnerabilityID'),v.get('Severity')])
EOF

# Run scan and save as CSV
sudo /tmp/trivy rootfs --vuln-type os --scanners vuln --format json / 2>/dev/null \
  | python3 ~/to_csv.py > ~/scan-<hostname>-<date>.csv
```

Copy CSV via SCP/WinSCP to `tools/osv_compare/`.

### 2. Compare against our DB (Windows)

```powershell
python tools/osv_compare/trivy_compare.py tools/osv_compare/<scan-file>.csv
```

Output: `tools/osv_compare/output/_trivy_delta_<date>.md`

### 3. Check OSV advisory gap for a specific CVE

Prepare a CSV with advisory IDs (one per line, header: `advisory_id`), then:

```powershell
python tools/osv_compare/run.py CVE-XXXX-XXXXX tools/osv_compare/CVE-XXXX-XXXXX.csv
```

Output: `tools/osv_compare/output/_osv_delta_CVE-XXXX-XXXXX.md`

Summarize only the gaps (only OSV / only ours / version diff):

```powershell
python tools/osv_compare/summarize_gaps.py tools/osv_compare/output/_osv_delta_CVE-XXXX-XXXXX.md
```

## Renewing the token

`CVEDB_GRAPHQL_TOKEN` in `.env` expires after 1 day:

```powershell
python main.py create-token
# paste new token into .env under CVEDB_GRAPHQL_TOKEN
```

## Status values

| Status | Meaning |
|---|---|
| `match` | Package and fix version match |
| `version_diff` | CVE known, but fix version differs |
| `pkg_missing` | CVE known, but this binary package is missing (usually source→binary mapping gap) |
| `cve_missing` | CVE completely missing for Ubuntu 22.04 |
| `only_osv` | OSV reports it, we don't have it |
| `only_ours` | We have it, OSV doesn't |

## Known gaps (as of 2026-06-07, Ubuntu 22.04, CVE-2026-31431)

- **`pkg_missing`**: We store source package names, Trivy reports binary package names.
  Example: we have `binutils`, Trivy reports `binutils-common`, `libbinutils`, etc.
- **`cve_missing`**: `CVE-2026-40228` (systemd) completely missing for Ubuntu 22.04.
- **USN mitigations**: `kmod` for kernel CVEs is only in the USN feed, not in CVE-JSON — missing from our ingest (TODO).
- **Rocky kernel-rt**: RLSA from NFV repo missing in aquasecurity/vuln-list (TODO).

## Scripts

| Script | Input | Purpose |
|---|---|---|
| `run.py` | CVE-ID + advisory CSV | Fetch OSV advisory data and compare against our ingest |
| `summarize_gaps.py` | `_osv_delta_*.md` | Compact gap table from OSV delta (only OSV / only ours / version diff) |
| `trivy_compare.py` | Trivy scan CSV | Compare Trivy system scan against our ingest (all CVEs at once) |
