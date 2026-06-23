# CPE Dictionary

The NVD CPE (Common Platform Enumeration) dictionary is a **reference source**, not a
per-CVE source. It populates the standalone `cpe` table — a catalogue of all known CPE
names used to validate product identifiers. It writes no per-CVE rows; it is a reference
dictionary.

## NVD CPE 2.0 bulk feed

- **URL:** `https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip`
- **Official:** Yes — NIST/NVD-maintained
- **Format:** NVD CPE 2.0 JSON, delivered as a single zip containing multiple chunk JSONs
- **Local path:** `cpe/cpe_dict.json` (compact index built from the feed)
- **Sync:** gated on the `.meta` file (`https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta`).
  If `lastModifiedDate` is unchanged since the last run, the download is skipped entirely.
  Otherwise the full zip (~76 MB) is downloaded, all chunk JSONs are merged, and
  `cpe_dict.json` is written.
- **Content:** one entry per CPE name: CPE 2.3 URI, type (application / OS / hardware),
  vendor, product, version, English title, deprecation flag, created/last-modified timestamps.

```
products[]/cpe/
├── cpeNameId              ✅ → cpe.cpe_name_id  (PK; entry skipped if absent)
├── cpeName                ✅ → cpe.cpe_uri       (must be cpe:2.3:…; parts[1]=="2.3" enforced)
├── (URI part[2])          ✅ → cpe.type          ('a' | 'o' | 'h')
├── (URI part[3])          ✅ → cpe.vendor        (entry skipped if empty)
├── (URI part[4])          ✅ → cpe.product
├── (URI part[5])          ✅ → cpe.version
├── titles[lang=en].title  ✅ → cpe.title_en
├── deprecated             ✅ → cpe.deprecated
├── created                ✅ → cpe.created_at
├── lastModified           ✅ → cpe.modified_at
└── refs / deprecatedBy /
    other API fields        ✗  not retained

Legend: ✅ imported  ✗ not imported
```

## Notes

- The bulk feed replaces API pagination: a single zip download is faster and avoids the
  NVD API's 403/503 rate-limiting behaviour.
- CPE entries are deprecated (the `deprecated` flag is set to `true`) but never deleted
  from the feed, so the ingest pattern is pure UPSERT — no sweep is needed.
- Entries that fail the format check (missing `cpeNameId`, URI not in CPE 2.3 form, or
  empty vendor) are silently skipped.
- `cpe.ingested_at` is set to `now()` on every upsert; `created_at` / `modified_at` come
  from the upstream feed and are preserved unchanged.

---

## Schema coverage

```
cpe                ✅  full dictionary upsert (~1.7M entries)

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
exploits           ❌
epss / kev / ssvc  ❌  their own sources
```
