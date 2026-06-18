# PoC-in-GitHub

Exploit-intelligence source. Aggregates GitHub repositories that contain
proof-of-concept code for a CVE and records each repository in `exploits[]`, setting
`has_exploit = true`. No package, CVSS, or remediation data is produced.

## nomi-sec/PoC-in-GitHub
- **URL:** `https://github.com/nomi-sec/PoC-in-GitHub`
- **Official:** No — community-maintained aggregator
- **Format:** JSON, one file per CVE; each file is a JSON array of GitHub repository objects
- **Local path:** `<poc_github>/<year>/CVE-YYYY-NNNNN.json` (shallow clone, `depth=1`)
- **Sync:** `git clone --depth=1` on first run, `git pull --ff-only` afterwards. No index is built — the ingest reads the per-CVE JSON files directly.
- **Content:** Per CVE, a list of GitHub repositories purporting to contain PoC exploit code, with repository metadata (stars, timestamps, fork flag).

### Field mapping

Ingest enumerates `CVE-*.json` files (or one file for a CVE filter), parses each array,
and writes one `exploits[]` entry per repository object.

```
<year>/CVE-YYYY-NNNNN.json (array of repo objects)
├── (filename stem)        ✅ → aliases[] + cve.cve_id  (kept if starts with "CVE-")
├── full_name              ✅ → exploits[].source_id  (required — entries without it are skipped)
├── description            ✅ → exploits[].name  (truncated to 200 chars)
├── html_url               ✅ → exploits[].url  (falls back to https://github.com/<full_name>)
├── stargazers_count       ✅ → exploits[].metadata.stars  (int)
├── created_at             ✅ → exploits[].metadata.created_at  (first 10 chars, YYYY-MM-DD)
├── pushed_at              ✅ → exploits[].metadata.pushed_at  (first 10 chars, YYYY-MM-DD)
└── fork                   ✅ → exploits[].metadata.is_fork  (bool)

constant
└── source                 ✅ → exploits[].source = "poc_github"

derived
└── has_exploit            ✅ → has_exploit = true  (when ≥1 repo with full_name)

Legend: ✅ imported  ✗ not imported
```

Repository objects without `full_name` are skipped; a CVE record is upserted only if at
least one repository entry survives.

## Notes
- Community-aggregated and unverified: many repositories are incomplete, educational,
  forks, or non-functional PoCs. There is no quality assessment beyond GitHub metadata.
- `stars` is a rough attention signal; `is_fork = true` repositories are typically lower
  quality; `pushed_at` indicates recency.
- Presence means PoC code is publicly accessible, but functionality varies widely.
- This source enriches existing LVE records (matched by CVE alias); it does not create
  package, CVSS, CWE, or advisory data.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ✅  set true when a repo with full_name exists
│
├── cve{}
│   ├── cve_id                   ✅  from filename (seed only)
│   ├── status                   ❌
│   ├── published               ❌
│   ├── updated                  ❌
│   ├── epss{}                   ❌
│   ├── kev{}                    ❌
│   └── ssvc{}                   ❌
│
├── titles[]                     ❌
├── descriptions[]               ❌
├── cvss[]                       ❌
├── cwes[]                       ❌
├── references[]                 ❌
│
├── advisories[]                 ❌
├── upstream[]                   ❌
├── packages[]                   ❌
│
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]
│   ├── source                   ✅  "poc_github"
│   ├── source_id                ✅  owner/repo (full_name)
│   ├── name                     ✅  repo description (≤200 chars)
│   ├── url                      ✅  html_url (or https://github.com/<full_name>)
│   └── metadata{}               ✅  {stars, created_at, pushed_at, is_fork}
│
└── history[]                    ❌
```
