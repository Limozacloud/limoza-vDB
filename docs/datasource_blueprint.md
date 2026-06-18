# Datasource Documentation Blueprint

This page defines the canonical **LVE record** and the conventions every
`docs/datasources/<vendor>.md` page should follow. Red Hat
([redhat.md](datasources/redhat.md)) is the reference implementation — match its
structure and level of detail when documenting a new source.

## LVE Record

```
LVE Record
├── lve_id                    string        LVDB-XXXXXXXX  (auto, assigned by DB)
├── aliases[]                 string[]      CVE-ID + all vendor advisory IDs
├── has_exploit               bool          derived from exploits[]
│
├── cve{}
│   ├── cve_id                string        CVE-YYYY-NNNNN
│   ├── status                enum          cve_assigned | cve_reserved | cve_pending | cve_rejected
│   ├── published             datetime
│   ├── updated               datetime
│   ├── epss{}                              score, percentile, date
│   ├── kev{}                               date_added, due_date, known_ransomware, required_action
│   └── ssvc{}                              exploitation, automatable, technical_impact
│
├── titles[]                  {value, source, advisory_ref}
├── descriptions[]            {value, source, advisory_ref}
├── cvss[]                    {version, score, vector, severity, source, advisory_ref, product_id}
├── cwes[]                    {cwe_id, name, source, advisory_ref}
├── references[]              {url, type[patch|advisory|article|fix|report|web], source, advisory_ref}
│
├── advisories[]             advisory_id = key
│   └── {advisory_id, source, url, published, updated, vendor_data{}}
│
├── upstream[]               upstream_id = key
│   └── {upstream_id, purl, fix_version, fix_commit, ranges[], versions[], source, advisory_ref}
│
├── packages[]
│   └── {name, purl (no version),
│         affected_state[affected|not_affected|not_applicable|unknown],
│         remediation_state[fixed|will_not_fix|pending|none|unknown],
│         status_raw, vex_justification,
│         ranges[{type, events[{introduced|fixed|last_affected}]}],
│         severity, source, advisory_ref, upstream_ref, vendor_data{}}
│
├── mitigations[]            {value, source, advisory_ref, purls[]}
├── impacts[]                {value, source, advisory_ref}
├── exploits[]               {source, source_id, name, url, metadata{}}
│
└── history[]
    └── {date, event, source, detail}
        events: created | cve_assigned | advisory_added | advisory_updated |
                vex_published | vex_updated | severity_changed | cvss_updated |
                kev_added | epss_updated | ssvc_updated | exploit_added |
                description_updated | status_changed
```

> **Package status model.** The legacy single `fix_status` field has been split into
> two orthogonal fields: `affected_state` (is the product affected?) and
> `remediation_state` (is a fix available?). `status_raw` preserves the original
> vendor status string, and `vex_justification` carries the VEX "not affected"
> reason where the source provides one.

## Page structure

Each `docs/datasources/<vendor>.md` should contain:

1. **Per-feed section** — `URL`, `Official`, `Format`, `Local path`, `Sync`, `Content` bullets (one block per feed if the vendor has several).
2. **Field-mapping tree** — a fenced ASCII tree of the source format, annotating each field with where it lands in the LVE record. Legend: `✅ imported`, `✗ not imported`, plus source-specific markers (e.g. `⊃ covered by another feed`).
3. **PURL** — the package URL format this source produces.
4. **State mapping** — a table mapping the source's status vocabulary to `affected_state` / `remediation_state` (for sources that emit package fix data).
5. **Notes** — caveats, gaps, cross-source relationships.
6. **Schema Coverage** — the full LVE Record tree above with `✅ / ❌` per field, showing exactly which sections this source populates.

Enrichment-only sources (EPSS, KEV, SSVC, BSI) and detection/exploit-intel sources
(Nuclei, Metasploit, PoC-in-GitHub, Exploit-DB) write only a slice of the record;
their pages may omit the PURL and State-mapping sections where they do not apply, but
should still include the Schema Coverage section so the populated slice is explicit.

> **Note on `notices`.** Transforms also return a `notices` key, which is written to
> the standalone `notices` table — an operational diagnostics channel for data that
> could not be fully mapped (e.g. a product with no derivable PURL). It is **not** part
> of the per-vulnerability LVE record and is therefore excluded from Schema Coverage.
