# Debian

Debian security data comes from two feeds. The **Security Tracker JSON** provides the
per-CVE descriptions and urgency assessments. The **OSV advisory export** (DSA/DLA
records from the Google OSV database) provides the formal bulletin metadata and CVE
links.

## Security Tracker JSON
- **URL:** `https://security-tracker.debian.org/tracker/data/json`
- **Official:** Yes — Debian Security Team-maintained
- **Format:** Single large JSON object (~75 MB), package-keyed → CVE-keyed → release-keyed
- **Local path:** `tracker.json`
- **Sync:** downloaded fresh on each sync run (no incremental; the file is replaced in full)
- **Content:** per-package, per-CVE descriptions and per-release urgency and scope. The
  transform inverts the package→CVE nesting to produce one record per distinct CVE id.
  Per-release fixed-version status is a later phase.

```
<package_name>/                         (top-level key)
└── <CVE-ID>/
    ├── description                     ✅ → cve_desc.value  (first package seen wins; source=NULL, Debian is not a CNA)
    ├── scope                           ✅ → cve_vendor.data.scope
    └── releases/
        └── <codename>/
            ├── urgency                 ✅ → cve_vendor.data.urgency  (highest urgency across all packages kept)
            ├── status                  ✗  per-release fix status — later phase
            └── (other keys)            ✗

Legend: ✅ imported  ✗ not imported (yet)
```

## OSV DSA/DLA advisories
- **URL:** `https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip`
- **Official:** Yes — Google OSV export of the Debian security-tracker advisory data
- **Format:** ZIP archive of OSV JSON files, one per DSA/DLA/DTSA
- **Local path:** `osv.zip`
- **Sync:** downloaded fresh on each sync run alongside the tracker JSON
- **Content:** DSA (Debian Security Advisory), DLA (Debian LTS Advisory), and DTSA advisory records with title, published/modified dates, and the CVE ids the advisory addresses

```
id                                      ✅ → advisory.advisory_id  (e.g. DSA-5678-1, DLA-3456-1)
summary                                 ✅ → advisory.title
published                               ✅ → advisory.published
modified                                ✅ → advisory.modified
upstream[]                              ✅ → advisory_cve.cve_id  (CVE-* entries only; DEBIAN-CVE-* dropped)
(other OSV fields)                      ✗

Legend: ✅ imported  ✗ not imported
```

## Notes

- Debian is not a CNA. Per-CVE description rows are written with `origin='debian'` and
  `source=NULL` (no orgId to reference).
- The Security Tracker JSON is package-keyed. The ingest inverts it to per-CVE: each
  distinct CVE id gets one `cve_desc` row (first package's description wins) and one
  `cve_vendor` row with the highest urgency seen across all packages.
- `cve_vendor.data` holds `{"urgency": "<value>", "scope": "<value>"}` — urgency is
  the highest-ranked value across all packages/releases for that CVE.
- Advisory URLs are constructed from the advisory id:
  `https://security-tracker.debian.org/tracker/<advisory-id>`. The `source_urls.json`
  entry (`cve_url = https://security-tracker.debian.org/tracker/{cve}`) drives the
  `cve_levels()` per-CVE tracking link for CVEs assessed but not covered by a DSA/DLA
  (shown as `tracked_only = true`).
- No CVSS or CWE data is available in either Debian feed.
- Affected/fixed package status (purls, version ranges) is a later phase and not
  written yet.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  tracker JSON per-CVE description
cve_cvss           ❌
cve_cwe            ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ✅  DSA / DLA / DTSA — id / title / published / modified / url
advisory_cve       ✅  advisory ↔ CVE
cve_vendor         ✅  {"urgency": "<highest urgency>", "scope": "<scope>"} (tracker)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
