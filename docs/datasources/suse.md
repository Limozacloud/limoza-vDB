# SUSE

SUSE publishes its security data as CSAF 2.0. Two feeds are consumed: the **VEX**
feed (one file per CVE) carries the per-CVE enrichment; the **advisories** feed (one
file per bulletin) supplies the advisory metadata and the CVE links.

## CSAF-VEX
- **URL:** `https://ftp.suse.com/pub/projects/security/csaf-vex/`
- **Official:** Yes — SUSE-maintained
- **Format:** CSAF 2.0 JSON (VEX profile), one file per CVE, flat directory (no year subdirs)
- **Local path:** `vex/cve-<year>-<id>.json`
- **Sync:** full archive (`csaf-vex.tar.bz2`, ~377 MB) on first run, incremental via `changes.csv` afterwards
- **Content:** severity, CVSS scores, description, references, and workaround/mitigation prose per CVE. Advisory IDs are **not** embedded in the VEX files — they come from the advisory feed.

```
document/
├── aggregate_severity.text             ✅ → cve_vendor.data.severity
└── (other document fields)             ✗

vulnerabilities[0]/                     (only the first vulnerability object is read)
├── cve                                 ✅ → cve spine (ON CONFLICT DO NOTHING)
├── cwe.id                              ✅ → cve_cwe.cwe_id
├── notes[category=description|general].text  ✅ → cve_desc.value
├── scores[]/
│   └── cvss_v3 | cvss_v2
│       ├── baseScore                   ✅ → cve_cvss.base_score
│       ├── vectorString                ✅ → cve_cvss.vector
│       ├── version (from key)          ✅ → cve_cvss.version  (v3→3.1, v2→2.0)
│       └── baseSeverity                ✅ → cve_cvss.severity (lowercased; computed from score if absent)
├── references[].{url, category}        ✅ → cve_ref.{url, type}
├── remediations[workaround|mitigation].details  ✅ → cve_workaround.value
├── product_status / product_tree       ✅ → affected (coord=purl) — full VEX status + fix versions
└── threats[impact].details             ✅ → cve_vendor.data.impact

Legend: ✅ imported  ✗ not imported
```

## CSAF-Advisories
- **URL:** `https://ftp.suse.com/pub/projects/security/csaf/`
- **Official:** Yes — SUSE-maintained
- **Format:** CSAF 2.0 JSON, one file per advisory (SUSE-SU-\*, openSUSE-SU-\*, SUSE-OU-\*, openSUSE-RU-\*, …)
- **Local path:** `advisories/<advisory-slug>.json`
- **Sync:** full pass over `index.txt` (filtered to `*-su-*` security updates) on first run, incremental via `changes.csv` afterwards
- **Content:** per-advisory tracking id, title, severity, published/modified dates, and the CVE list the advisory fixes

```
document/
├── tracking.id                         ✅ → advisory.advisory_id
├── title                               ✅ → advisory.title
├── aggregate_severity.text             ✅ → advisory.severity
├── tracking.initial_release_date       ✅ → advisory.published
├── tracking.current_release_date       ✅ → advisory.modified
└── references[category=self].url       ✅ → advisory.url (fallback; see URL notes below)

vulnerabilities[]/
└── cve                                 ✅ → advisory_cve.cve_id  (the CVE links live here)
```

## Notes

- The VEX feed writes per-CVE enrichment (`cve_cvss`, `cve_cwe`, `cve_desc`, `cve_ref`,
  `cve_workaround`) plus the `cve_vendor` severity assessment. It carries **no** advisory
  references — those come exclusively from the advisory feed.
- The advisory feed writes `advisory` + `advisory_cve` rows; the CVE links (what a bulletin
  fixes) are read from each advisory file's `vulnerabilities[].cve` fields.
- **URL routing via `source_urls.json`:** SUSE-SU advisories get a human-readable announcement
  URL (`https://www.suse.com/support/update/announcement/{year}/{slug}/`) because
  `source_urls.json` sets `when_id_prefix = "SUSE-SU"`. openSUSE-SU advisories do not match
  that prefix, so their stored CSAF `self` reference URL (the raw JSON link) is kept. This
  mapping drives how `cve_levels()` renders L3 downstream links.
- `cve_vendor` rows are written from the VEX feed (`document.aggregate_severity.text`).
  Distros without a formal bulletin still appear in `cve_vendor` (no `advisory` row), which
  `cve_levels()` surfaces as `tracked_only = true`.
- `cve_cwe` is not present in SUSE VEX files — the field is parsed but typically empty.
- Only `vulnerabilities[0]` is processed per VEX file (SUSE VEX files carry a single CVE).
- SUSE's CSAF VEX `product_status` (known_affected / known_not_affected / first_fixed /
  recommended) drives the [affected layer](../affected-versions.md) (`coord=purl`).
  `no_fix_planned` products are kept out of the status buckets, so SUSE's affected set is
  already free of won't-fix noise.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  vulnerabilities[0].notes[description|general]
cve_cvss           ✅  vulnerabilities[0].scores[].cvss_v3 / cvss_v2
cve_cwe            ✅  vulnerabilities[0].cwe.id  (present when non-empty)
cve_ref            ✅  vulnerabilities[0].references[]
cve_solution       ❌
cve_workaround     ✅  remediations[workaround|mitigation].details
cve_impact         ❌
cve_alias          ❌
advisory           ✅  SUSE-SU / openSUSE-SU — id / title / severity / dates / url
advisory_cve       ✅  advisory ↔ CVE
cve_vendor         ✅  {"severity": aggregate_severity, "impact": threats[impact]} (VEX)
affected           ✅  product_status + product_tree → coord=purl (full VEX status)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
