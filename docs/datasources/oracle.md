# Oracle Linux

Oracle Linux publishes its security advisories (ELSA) as a single combined OVAL XML
file covering all currently maintained major releases.

## OVAL
- **URL:** `https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2`
- **Official:** Yes — Oracle-maintained
- **Format:** bzip2-compressed OVAL XML (one combined "all" file, 200+ MB uncompressed)
- **Local path:** `oval.xml` (downloaded as `.xml.bz2`, then decompressed in-place)
- **Sync:** full re-download on every sync run; the XML is streamed with `iterparse`
  over `<definition class="patch">` elements
- **Content:** ELSA-\* (Oracle Linux Security Advisory) definitions with their CVE
  references, advisory severity, title, issued date, and per-CVE CVSS v3 vectors and
  scores. The OVAL criteria fix tests drive the affected layer.

```
oval_definitions/definitions/definition[@class="patch"]/
├── metadata/
│   ├── title                           ✅ → advisory.title; ELSA-ID parsed from prefix before first ":"
│   │                                       → advisory.advisory_id
│   ├── reference[@source="ELSA"].ref_id ✅ → advisory.advisory_id  (explicit ref_id, preferred over title parse)
│   ├── reference[@source="CVE"].ref_id ✅ → advisory_cve.cve_id + cve spine
│   └── advisory/
│       ├── severity                    ✅ → advisory.severity
│       ├── issued[@date]               ✅ → advisory.published
│       └── cve[@cvss3]                 ✅ → cve_cvss.{base_score, vector, version, severity}
│                                           (parsed as "<score>/CVSS:<version>/..." per CVE element)
└── criteria/                           ✅ → affected (coord=purl, via the OVAL fix tests)

Legend: ✅ imported  ✗ not imported
```

## Notes

- Oracle Linux is not a CNA. `cve_cvss` rows are written with `origin='oracle'` and
  `source` set to Oracle's CNA orgId UUID (looked up from the `cna` table at import
  time, or `NULL` if not found).
- `cve_vendor.data.severity` is set to the highest ELSA severity seen for each CVE across
  all advisories (Critical > Important > Moderate > Low). This feeds the
  [downstream tier](../advisory-tiers.md) `cve_levels()` assessment.
- Oracle Linux rebuilds Red Hat errata; each ELSA typically corresponds to a RHSA, but the
  RHSA cross-reference is not embedded in the OVAL data and is not extracted.
- Advisory URLs are constructed at import time:
  `https://linux.oracle.com/errata/<ELSA-ID>.html`. When the title carries no `:` prefix
  the ELSA ID cannot be parsed; such definitions produce no `advisory` row and the
  `advisory_cve` link is omitted.
- The OVAL file covers all currently maintained major releases (e.g. Oracle Linux 7, 8, 9,
  10). Unlike AlmaLinux and Rocky, this source **does** carry per-CVE CVSS v3 data.
- The advisory has only an `issued` date — no `modified`/updated date is present.
- Oracle Linux's OVAL fix tests drive the [affected layer](../affected-versions.md)
  (`coord=purl`), **alongside** the Red Hat ranges Oracle inherits — both come out of the
  same `ingest/affected/sources/oracle.py` extractor (`status_source`: `own` for the OVAL
  rows, `redhat-inherited` for the clone rows). This is what actually covers Oracle's own
  UEK kernel (`kernel-uek*`) and anything else Oracle-specific that Red Hat has never heard
  of — the Red Hat inheritance alone never matches those packages.
- The fix-version criteria don't need resolving against the OVAL `<tests>`/`<objects>`/
  `<states>` sections: each `<criterion comment="X is earlier than Y">` already carries the
  package name and fix EVR directly in its human-readable comment, regardless of AND/OR
  nesting (arch-specific branches just repeat the same pair) — a straight text match, no
  cross-referencing.

---

## Schema coverage

```
cve_record         ❌  CVE List only
cve_desc           ❌
cve_cvss           ✅  advisory/cve[@cvss3] — score + vector (CVSS v3 only)
cve_cwe            ❌
cve_ref            ❌
cve_solution       ❌
cve_workaround     ❌
cve_impact         ❌
cve_alias          ❌
advisory           ✅  ELSA — id / title / severity / published / url
advisory_cve       ✅  ELSA ↔ CVE
cve_vendor         ✅  {"severity": "<highest ELSA severity for this CVE>"}
affected           ✅  OVAL fix tests + Red Hat-inherited ranges → coord=purl
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
