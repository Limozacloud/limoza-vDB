# Nuclei Templates

Detection-intelligence source. Maps ProjectDiscovery Nuclei CVE templates to CVEs and
records them in the `exploits` table. The presence of a template indicates that
automated detection is feasible — it is not necessarily a weaponized exploit. No CVSS,
advisory, or remediation data is produced.

## projectdiscovery/nuclei-templates
- **URL:** `https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json`
- **Official:** Yes — ProjectDiscovery-maintained
- **Format:** JSON Lines (one JSON object per line) — a pre-built CVE index of templates
- **Local path:** generated index at `<nuclei>/nuclei_index.json`
- **Sync:** HTTP download of `cves.json` on every run (no incremental gate — the file is rebuilt from scratch each time). Each line is parsed; objects whose `ID` starts with `CVE-` are kept and grouped into a `CVE → [templates]` index.
- **Content:** Detection templates for CVEs (active scanning signatures), with a ProjectDiscovery-assigned severity and short description.

### Field mapping

```
cves.json line (JSON object)
├── ID                              ✅ → cve_id  (kept if starts with "CVE-")
├── Info.Name                       ✅ → name  (NUL bytes stripped)
├── Info.Severity                   ✅ → metadata.severity
├── Info.Description                ✅ → metadata.description  (NUL bytes stripped, truncated to 500 chars)
├── file_path                       ✅ → url  (https://github.com/projectdiscovery/nuclei-templates/blob/main/<file_path>)
├── Info.Classification.cvss-score  ✗  parsed during sync but NOT written (dropped at ingest)
└── source_id                       ✗  NULL — the template ID equals the CVE id and is redundant

constant
└── source                          ✅ → source = "nuclei"

Legend: ✅ imported  ✗ not imported
```

Entries with no `url` are dropped at ingest.

## Notes

- A Nuclei template means automated **detection** is feasible (the scanner can probe
  whether a target is vulnerable). This is a detection signal, distinct from a
  weaponized exploit such as a Metasploit module.
- `severity` is independently assigned by ProjectDiscovery and may differ from the NVD
  or vendor severity.
- The sync step extracts `cvss-score` from the template classification, but ingest does
  not map it into the database — it is silently discarded. Only `severity` and
  `description` reach `metadata`.
- "Does this CVE have an exploit?" =
  `EXISTS (SELECT 1 FROM exploits WHERE cve_id = … AND source = 'nuclei')`.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ❌
cve_cvss           ❌
cve_cwe            ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ❌
advisory_cve       ❌
cve_vendor         ❌
exploits           ✅  source='nuclei' · source_id=NULL · name=Info.Name
                       url=https://github.com/projectdiscovery/nuclei-templates/blob/main/<file_path>
                       metadata={severity, description (≤500 chars)}
epss / kev / ssvc  ❌  their own sources
```
