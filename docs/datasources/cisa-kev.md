# CISA KEV (Known Exploited Vulnerabilities)

Enrichment-only source. Populates the `kev` table — one row per CVE — and
contributes nothing else to the database.

## KEV JSON Feed

- **URL:** `https://github.com/cisagov/kev-data` (file: `known_exploited_vulnerabilities.json`)
- **Official:** Yes — CISA (US federal)-maintained
- **Format:** JSON, single flat catalog
- **Local path:** `kev/repo/known_exploited_vulnerabilities.json` (shallow git checkout)
- **Sync:** shallow clone (`--depth=1`) on first run, `git pull --ff-only` afterwards
- **Content:** CVEs confirmed to be actively exploited in the wild, with CISA remediation
  guidance, due dates, and ransomware-campaign association

## Field mapping

```
known_exploited_vulnerabilities.json
└── vulnerabilities[]/
    ├── cveID                          ✅ → kev.cve_id  +  cve spine (ON CONFLICT DO NOTHING)
    ├── dateAdded                      ✅ → kev.date_added
    ├── dueDate                        ✅ → kev.due_date
    ├── knownRansomwareCampaignUse     ✅ → kev.known_ransomware  (see Notes)
    ├── requiredAction                 ✅ → kev.required_action
    ├── vendorProject                  ✅ → kev.vendor_project
    ├── product                        ✅ → kev.product
    ├── vulnerabilityName              ✅ → kev.vulnerability_name
    ├── shortDescription               ✅ → kev.short_description
    └── notes                          ✅ → kev.notes

Legend: ✅ imported
```

## Notes

- Pure enrichment: no CVSS, CWE, references, or advisory data are written.
- **`known_ransomware` coercion:** CISA emits the string `"Known"` or `"Unknown"`.
  The ingest step maps `"Known"` → `true`, `"Unknown"` → `false`, and any
  non-string value → `NULL`. Only `"Known"` is a confirmed ransomware-campaign
  association.
- The ingest pattern is **DELETE + INSERT** in a single transaction. KEV is a full
  snapshot and CISA can withdraw entries, so the table is rebuilt each sync to match
  the source exactly — withdrawn CVEs disappear atomically. `DELETE` (not `TRUNCATE`)
  takes only `ROW EXCLUSIVE`, so concurrent dashboard reads continue via MVCC until
  commit.
- KEV presence is a hard escalation signal regardless of CVSS score or EPSS
  probability.

---

## Schema coverage

```
cve                ✅  ON CONFLICT DO NOTHING — seeds the spine for every KEV entry
cve_record         ❌  CVE List only
cve_cvss           ❌
cve_cwe            ❌
cve_desc           ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ❌
advisory_cve       ❌
cve_vendor         ❌
exploits           ❌
epss               ❌  FIRST EPSS source
kev                ✅  cve_id, date_added, due_date, known_ransomware, required_action,
                        vendor_project, product, vulnerability_name, short_description, notes
ssvc               ❌  CISA SSVC source
```
