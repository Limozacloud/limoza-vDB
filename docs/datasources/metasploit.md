# Metasploit Framework

Exploit-intelligence source. Maps Metasploit modules to the CVEs they reference and
writes them to `exploits[]`, setting `has_exploit = true`. No package, CVSS, or
remediation data is produced.

## rapid7/metasploit-framework
- **URL:** `https://github.com/rapid7/metasploit-framework`
- **Official:** Yes — Rapid7-maintained
- **Format:** Ruby modules (`*.rb`) with a structured metadata header
- **Local path:** `<metasploit>/repo` (sparse, blobless clone of `modules/` only); generated index at `<metasploit>/metasploit_index.json`
- **Sync:** `git clone --depth=1 --filter=blob:none --sparse` then `git sparse-checkout set modules/` on first run; `git pull --ff-only` afterwards. The sync step walks every `modules/**/*.rb`, regex-extracts `['CVE', 'YYYY-NNNN']` references, and builds a `CVE → [modules]` index. Modules with no CVE reference are skipped.
- **Content:** Exploit, auxiliary, post, and payload modules, many CVE-mapped.

### Field mapping

Module metadata is extracted from the Ruby source via regex during sync; ingest reads
the index and writes `exploits[]`.

```
modules/**/*.rb (parsed)
├── References ['CVE', 'YYYY-NNNN']  ✅ → aliases[] + cve.cve_id  (regex; prefixed "CVE-")
├── module path (rel, no .rb)        ✅ → exploits[].source_id + exploits[].url
│                                          (https://github.com/rapid7/metasploit-framework/blob/master/modules/<path>.rb)
├── 'Name' => '…'                    ✅ → exploits[].name  (falls back to file stem)
├── Rank = <X>Ranking                ✅ → exploits[].metadata.rank  ("Ranking" stripped, lower-cased)
└── first path segment               ✅ → exploits[].metadata.type  (exploits | auxiliary | post | payload)

constant
└── source                           ✅ → exploits[].source = "metasploit"

derived
└── has_exploit                      ✅ → has_exploit = true  (always)

Legend: ✅ imported  ✗ not imported
```

## Notes
- A Metasploit module is the strongest weaponization signal in the dataset: if a
  module exists, the vulnerability is effectively weaponized.
- `rank` is the normalized module reliability (e.g. `excellent`, `great`, `good`,
  `normal`, `average`, `low`, `manual`) — stored verbatim as text in metadata; no
  numeric mapping is applied.
- Multiple modules per CVE are possible (different targets/payloads); each becomes a
  separate `exploits[]` entry. The CVE record is upserted unconditionally for every
  CVE in the index.
- This source enriches existing LVE records (matched by CVE alias); it does not create
  package, CVSS, CWE, or advisory data.

## Schema Coverage

```
LVE Record
├── aliases[]                    ✅  [cve_id]
├── has_exploit                  ✅  always set true
│
├── cve{}
│   ├── cve_id                   ✅  CVE referenced in module header (seed only)
│   ├── status                   ❌
│   ├── published                ❌
│   ├── updated                  ❌
│   ├── epss{}                   ❌
│   ├── kev{}                    ❌
│   └── ssvc{}                   ❌
│
├── titles[]                     ❌
├── descriptions[]               ❌
├── cvss[]                       ❌
├── cwes[]                       ❌
├── references[]                 ❌
│
├── advisories[]                 ❌
├── upstream[]                   ❌
├── packages[]                   ❌
│
├── mitigations[]                ❌
├── impacts[]                    ❌
├── exploits[]
│   ├── source                   ✅  "metasploit"
│   ├── source_id                ✅  module path (e.g. exploits/linux/http/…)
│   ├── name                     ✅  module Name (or file stem)
│   ├── url                      ✅  blob link to the .rb on master
│   └── metadata{}               ✅  {rank, type}
│
└── history[]                    ❌
```
