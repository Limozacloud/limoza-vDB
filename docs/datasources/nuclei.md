# Nuclei Templates

Detection-intelligence source. Maps ProjectDiscovery Nuclei detection templates to
CVEs and records them in `exploits[]`, setting `has_exploit = true`. The presence of a
template indicates active detection is possible — it is not necessarily a working
exploit. No package, CVSS, or remediation data is produced.

## projectdiscovery/nuclei-templates
- **URL:** `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json`
- **Official:** Yes — ProjectDiscovery-maintained
- **Format:** JSON Lines (one JSON object per line) — a pre-built CVE index of templates
- **Local path:** generated index at `<nuclei>/nuclei_index.json`
- **Sync:** HTTP download of `cves.json` via `httpx` (follows redirects). Each line is parsed; objects whose `ID` starts with `CVE-` are kept and grouped into a `CVE → [templates]` index.
- **Content:** Detection templates for CVEs (active scanning signatures), with a ProjectDiscovery-assigned severity and short description.

### Field mapping

```
cves.json line (JSON object)
├── ID                              ✅ → aliases[] + cve.cve_id + exploits[].source_id  (kept if starts with "CVE-")
├── Info.Name                       ✅ → exploits[].name  (NUL-stripped)
├── Info.Severity                   ✅ → exploits[].metadata.severity
├── Info.Description                ✅ → exploits[].metadata.description  (NUL-stripped, truncated to 500 chars)
├── file_path                       ✅ → exploits[].url  (https://github.com/projectdiscovery/nuclei-templates/blob/main/<file_path>)
└── Info.Classification.cvss-score  ✗  parsed during sync, NOT written to cvss[] (dropped at ingest)

constant
└── source                          ✅ → exploits[].source = "nuclei"

derived
└── has_exploit                     ✅ → has_exploit = true  (when ≥1 entry with a non-empty url)

Legend: ✅ imported  ✗ not imported
```

Entries with no `url` are dropped; a CVE record is upserted only if at least one
template entry survives.

## Notes
- A Nuclei template means automated **detection** is feasible (the scanner can test
  whether a target is vulnerable). This is a detection signal, distinct from a
  weaponized exploit such as a Metasploit module.
- `severity` is independently assigned by ProjectDiscovery and may differ from the
  NVD or vendor severity.
- The sync step extracts `cvss-score` from the template classification, but the ingest
  does **not** map it into the LVE `cvss[]` array — it is silently discarded. Only the
  `severity` and `description` reach the record (inside `exploits[].metadata`).
- This source enriches existing LVE records (matched by CVE alias); it does not create
  package, CVSS, CWE, or advisory data.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ✅  set true when a template with a url exists
│
├── cve{}
│   ├── cve_id                   ✅  template ID (seed only)
│   ├── status                   ❌
│   ├── published               ❌
│   ├── updated                  ❌
│   ├── epss{}                   ❌
│   ├── kev{}                    ❌
│   └── ssvc{}                   ❌
│
├── titles[]                     ❌
├── descriptions[]               ❌
├── cvss[]                       ❌  cvss-score parsed during sync but dropped at ingest
├── cwes[]                       ❌
├── references[]                 ❌
│
├── advisories[]                 ❌
├── upstream[]                   ❌
├── packages[]                   ❌
│
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]                   ✅  (detection templates)
│   ├── source                   ✅  "nuclei"
│   ├── source_id                ✅  template ID (= CVE)
│   ├── name                     ✅  Info.Name
│   ├── url                      ✅  blob link to the template on main
│   └── metadata{}               ✅  {severity, description (≤500 chars)}
│
└── history[]                    ❌
```
