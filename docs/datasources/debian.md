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
- **Content:** per-package, per-CVE descriptions, per-release status / fixed version /
  urgency / scope / no-dsa decisions. The metadata transform inverts the package→CVE
  nesting to one record per distinct CVE id; the per-release status drives the
  [affected-version layer](#affected-versions-l4).

```
<package_name>/                         (top-level key)
└── <CVE-ID>/
    ├── description                     ✅ → cve_desc.value  (first package seen wins; source=NULL, Debian is not a CNA)
    ├── scope                           ✅ → cve_vendor.data.scope
    └── releases/
        └── <codename>/
            ├── status                  ✅ → affected.status   (open → affected; resolved → fixed)
            ├── fixed_version           ✅ → affected.fixed    (resolved; "0" → not_affected)
            ├── urgency                 ✅ → cve_vendor.data.urgency (highest kept) + affected status
            ├── nodsa / nodsa_reason    ✅ → affected status (no-dsa → wont_fix)
            └── (other keys)            ✗

Legend: ✅ imported  ✗ not imported
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

## Affected versions (L4)

The Security Tracker's per-release status drives the `affected` layer (`coord=purl`,
`ecosystem=deb`, keyed by the **source** package). `vdb affected` maps each release entry:

| Tracker entry | → status |
|---------------|----------|
| `resolved` + real `fixed_version` | `fixed` (that version) |
| `resolved` + `fixed_version` `"0"` | `not_affected` (release ships a safe version) |
| `open` + `nodsa` (ignored / postponed) | `wont_fix` |
| `open` + urgency `unimportant` / `end-of-life` | `wont_fix` |
| `open` (else: high / medium / low / not-yet-assigned) | `affected` |
| `undetermined` | `unknown` |

`status_raw` keeps Debian's raw word (`open` / `resolved`); `justification` records the
deprioritisation reason (`urgency: unimportant`, `nodsa: ignored`, …). `wont_fix` rows stay
in the DB for audit but are excluded from the vulnerable verdict — this removes the classic
"Debian tracks every CVE, even the ones it won't fix" noise (e.g. apt CVE-2011-3374).

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
- The `affected` layer is keyed by the **source** package (the tracker is source-keyed), so
  a scanner must resolve a binary to its source — sent as the purl `upstream` qualifier
  (`zlib1g` → `upstream=zlib`) — and the release codename (`distro=debian-11` → `bullseye`).

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
affected           ✅  per-release status → fixed / affected / wont_fix / not_affected (source-keyed, coord=purl)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
