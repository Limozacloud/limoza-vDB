# Ubuntu / Canonical

Ubuntu security data is fetched as a sparse clone of the
`canonical/ubuntu-security-notices` GitHub repository. Three sub-feeds are consumed:
the **OSV** feed (one file per CVE) carries the per-CVE enrichment and version ranges;
the **USN** feed (one file per advisory) supplies the bulletin metadata and CVE links;
the **VEX** feed (OpenVEX, one file per CVE) carries the per-release triage status the
OSV export omits (not-affected and won't-fix), used to refine the
[affected-version layer](#affected-versions-l4).

## OSV (per-CVE enrichment)
- **URL:** `https://github.com/canonical/ubuntu-security-notices` (sparse clone, `osv/cve/` directory)
- **Official:** Yes — Canonical-maintained
- **Format:** OSV JSON per CVE
- **Local path:** `osv/cve/<year>/CVE-<year>-<id>.json`
- **Sync:** `git pull --ff-only` on each run
- **Content:** CVSS vectors (Ubuntu provides vectors without a pre-computed base score — the score is computed on import), Ubuntu priority/severity label, and description

```
aliases[]                               ✅ → cve spine (first CVE-* alias used as cve_id)
details                                 ✅ → cve_desc.value
severity[]/
├── type = "CVSS_V3" | "CVSS_V4" | "CVSS_V2"
│   └── score  (CVSS vector string)     ✅ → cve_cvss.{vector, base_score (computed), version, severity}
└── type = "Ubuntu"
    └── score  (priority label)         ✅ → cve_vendor.data.severity
(all other OSV fields)                  ✗

Legend: ✅ imported  ✗ not imported
```

## USN (Ubuntu Security Notices)
- **URL:** `https://github.com/canonical/ubuntu-security-notices` (sparse clone, `usn/` directory)
- **Official:** Yes — Canonical-maintained
- **Format:** JSON per USN advisory, filename `<id>.json` (e.g. `USN-6765-1.json`)
- **Local path:** `usn/<id>.json`
- **Sync:** `git pull --ff-only` on each run (same sparse clone as the OSV feed)
- **Content:** advisory id, title, publish timestamp, and the list of CVEs the notice addresses

```
id                                      ✅ → advisory.advisory_id  (e.g. USN-6765-1)
title                                   ✅ → advisory.title
timestamp  (Unix int or ISO string)     ✅ → advisory.published
cves[]                                  ✅ → advisory_cve.cve_id  (one row per CVE)
(other fields)                          ✗

Legend: ✅ imported  ✗ not imported
```

## Affected versions (L4)

The OSV feed supplies the version ranges (`affected`, `coord=purl`, `ecosystem=deb`, keyed
by the **source** package); the VEX feed refines their **status**. `vdb affected` builds
each row from OSV (introduced / fixed) then overlays the OpenVEX statement for that
(CVE, package, release):

| OSV / VEX | → status |
|-----------|----------|
| OSV has a `fixed` event | `fixed` (that version) |
| VEX `not_affected` | `not_affected` (+ justification) |
| VEX `affected`, action "no longer supported" (EOL) | `wont_fix` |
| VEX `affected`, action "decided to not fix" | `wont_fix` |
| OSV affected, no won't-fix VEX | `affected` |

OpenVEX's `status` only carries affected / fixed / not_affected / under_investigation; the
won't-fix nuance lives in the statement's `action_statement` text, matched on Ubuntu's
fixed template phrases. `wont_fix` rows stay in the DB (with `justification`) but are
excluded from the vulnerable verdict — removing the EOL / "won't fix" noise while keeping
genuinely open CVEs.

## Notes

- All three feeds live in one sparse git clone; only `usn/`, `osv/cve/` and `vex/cve/` are
  checked out.
- The OSV pass runs in parallel workers and writes per-CVE enrichment plus `cve_vendor`.
  The USN pass (single-threaded) writes `advisory` + `advisory_cve` rows.
- Ubuntu gives CVSS vectors without pre-computed base scores. The importer computes the
  base score from the vector (`score_from_vector`) and derives severity from the score.
- `cve_vendor.data.severity` holds Ubuntu's own priority label (e.g. `medium`, `high`,
  `critical`), which is separate from the computed CVSS severity.
- Advisory URLs are constructed at import time:
  `https://ubuntu.com/security/notices/<USN-ID>`. The `source_urls.json` entry
  (`cve_url = https://ubuntu.com/security/{cve}`) drives the `cve_levels()` per-CVE
  tracking link for CVEs that have no formal USN (shown as `tracked_only = true`).
- No CWE data is present in any Ubuntu feed.
- The `affected` layer is keyed by the **source** package and release codename, so a
  scanner sends the source (binary→source via the purl `upstream` qualifier) and
  `distro=ubuntu-22.04` (→ `jammy`).

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ✅  OSV details
cve_cvss           ✅  OSV severity[CVSS_V3/V4/V2] — score computed from vector
cve_cwe            ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ✅  USN — id / title / published / url
advisory_cve       ✅  USN ↔ CVE
cve_vendor         ✅  {"severity": Ubuntu priority label} (OSV)
affected           ✅  OSV ranges + OpenVEX status → fixed / affected / wont_fix / not_affected (source-keyed, coord=purl)
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
