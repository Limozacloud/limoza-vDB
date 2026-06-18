# BSI WID (German Federal Office for Information Security)

Advisory-level enrichment source. The BSI "Warn- und Informationsdienst" (WID),
operated by CERT-Bund, publishes CSAF 2.0 advisories. This source writes a small
slice of the LVE record: the CVE alias, the WID advisory entry, a title and
description (from the CSAF document when available), one advisory reference, and
history events. It writes **no** CVSS, CWE, package, or severity data.

## WID CSAF Feed

The pipeline uses the official CSAF distribution (ROLIE feed + per-advisory CSAF
files), not the HTML portal.

- **URL (base):** `https://wid.cert-bund.de/.well-known/csaf/white`
- **ROLIE feed:** `https://wid.cert-bund.de/.well-known/csaf/white/bsi-wid-white.json` — used to build the CVE → WID index
- **Changes feed:** `https://wid.cert-bund.de/.well-known/csaf/white/changes.csv` — drives incremental CSAF downloads
- **Individual advisory (CSAF):** `https://wid.cert-bund.de/.well-known/csaf/white/<year>/<wid-id>.json`
- **Official:** Yes — German federal cybersecurity authority (BSI / CERT-Bund)
- **Format:** CSAF 2.0 JSON
- **Local path:** `bsi_index.json` (CVE → `{wid_id, wid_url}`), `csaf/<year>/<wid-id>.json` (cached CSAF files), `csaf_manifest.json` (path → last-modified for incremental sync)
- **Sync:** the ROLIE feed is downloaded and reduced to a CVE→WID index on every run; CSAF files are downloaded only when `changes.csv` reports a newer `last_modified` than the manifest records (incremental), fetched concurrently (10 workers, 3 retries with backoff)
- **Content:** German government security advisories with broad vendor coverage, including ICS/SCADA frequently missed by other sources

## Field mapping

Two stages contribute. The **ROLIE feed** yields the CVE↔WID linkage and the
advisory URL. The **CSAF document** (if cached locally) yields the title,
description, and release dates. When the CSAF file is absent, the record still
gets the alias, the advisory `@id`/`url`, and the reference — but no title,
description, dates, or history.

```
bsi-wid-white.json (ROLIE feed)
└── feed.entry[]/
    ├── id                                   ✅ → aliases[1] (upper-cased WID-ID) + advisories[].@id + history[].detail
    ├── content.src                          ✅ → advisories[].url + references[].url
    └── category[] (scheme startswith cve.org)
        └── term (= CVE-ID)                  ✅ → aliases[0] + cve.cve_id

<year>/<wid-id>.json (per-advisory CSAF)
└── document/
    ├── title                                ✅ → titles[].value
    ├── notes[]/
    │   ├── [category=summary].text          ✅ → descriptions[].value  (preferred)
    │   └── [category=description].text      ✅ → descriptions[].value  (fallback when no summary)
    └── tracking/
        ├── initial_release_date             ✅ → advisories[].published + history[].date (advisory_added)
        └── current_release_date             ✅ → advisories[].updated + history[].date (advisory_updated, only if != published)

Legend: ✅ imported  ✗ not imported
```

Everything else in the CSAF document — `document.aggregate_severity`,
`document.publisher`, `document.references[]`, `product_tree`,
`vulnerabilities[].scores`, `vulnerabilities[].cwe`, `vulnerabilities[].remediations`,
`product_status` — is **not** read by the transform.

## Severity mapping (NOT IMPLEMENTED)

> The current ingest code does **not** read or map BSI severity at all.

BSI advisories carry a German severity scale (`kritisch`, `hoch`, `mittel`,
`niedrig`) in `document.aggregate_severity.text`, but `transform()` never accesses
that field, so no severity is written to the LVE record (no `cvss[].severity`, no
`packages[].severity`, no `vendor_data`). The intended German→English mapping, for
reference if this is implemented later, would be:

| BSI (German) | English |
|---|---|
| `kritisch` | `critical` |
| `hoch` | `high` |
| `mittel` | `medium` |
| `niedrig` | `low` |

(Earlier versions of this page claimed severity was written to
`vendor_data.severity_raw`; that mapping does not exist in the code and has been
removed.)

## Notes
- One WID advisory can reference multiple CVEs; the ingest iterates the CVE→WID index, so each CVE is upserted separately, all pointing at the same WID advisory.
- Index-only mode: if `bsi_index.json` exists but no CSAF files have been synced, only the alias, advisory `@id`/`url`, and reference are written — titles, descriptions, dates, and history require the CSAF files (`sync bsi`).
- Title and description prose is German (BSI is a German-language source). Only the prose in this documentation is English; the stored advisory values remain in their source language.
- `cve.cve_id` is written as a seed only — not authoritative and not overwritten if already set.
- No fix-version or package data — BSI advisories point to vendor advisories for remediation detail. No PURLs are produced.
- All emitted dates are normalised to UTC `YYYY-MM-DDTHH:MM:SSZ`; if parsing fails the original trimmed string is kept.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id, WID-ID]
├── has_exploit                  ❌  always emitted as false
│
├── cve{}
│   ├── cve_id                   ✅  seed only (not overwritten if already set)
│   ├── status                   ❌  NVD only
│   ├── published               ❌  NVD only
│   ├── updated                  ❌  NVD only
│   ├── epss{}                   ❌  EPSS vendor
│   ├── kev{}                    ❌  CISA KEV vendor
│   └── ssvc{}                   ❌  CISA SSVC vendor
│
├── titles[]                     ✅  document.title  {value, source:"bsi", advisory:WID-ID}  (CSAF only)
├── descriptions[]               ✅  notes[summary|description].text                          (CSAF only)
├── cvss[]                       ❌  not read (no scores written)
├── cwes[]                       ❌  not read
├── references[]                 ✅  WID advisory URL  {url, type:"advisory", source:"bsi", advisory:WID-ID}
│
├── advisories[]
│   ├── @id                      ✅  WID-ID
│   ├── source                   ✅  "bsi"
│   ├── url                      ✅  ROLIE content.src
│   ├── published                ✅  tracking.initial_release_date  (CSAF only)
│   ├── updated                  ✅  tracking.current_release_date  (CSAF only, if != published)
│   └── vendor_data              ❌  not written
│
├── upstream[]                   ❌
├── packages[]                   ❌  no package/fix data
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]                   ❌
│
└── history[]
    ├── advisory_added           ✅  {date: initial_release_date, source:"bsi", detail:WID-ID}  (CSAF only)
    └── advisory_updated         ✅  {date: current_release_date, source:"bsi", detail:WID-ID}  (CSAF only, if != published)
```
