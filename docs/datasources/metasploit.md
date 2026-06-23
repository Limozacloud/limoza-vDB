# Metasploit Framework

Exploit-intelligence source. Maps Metasploit modules to the CVEs they reference and
writes them to the `exploits` table. No CVSS, advisory, or remediation data is
produced.

## rapid7/metasploit-framework
- **URL:** `https://github.com/rapid7/metasploit-framework`
- **Official:** Yes — Rapid7-maintained
- **Format:** Ruby modules (`*.rb`) with a structured metadata header
- **Local path:** `<metasploit>/repo` (sparse, blobless clone of `modules/` only); generated index at `<metasploit>/metasploit_index.json`
- **Sync:** `git clone --filter=blob:none --sparse` then `git sparse-checkout set modules/` on first run; `git pull --ff-only` afterwards, gated on HEAD commit hash. The sync step walks every `modules/**/*.rb`, regex-extracts `['CVE', 'YYYY-NNNN']` references, and builds a `CVE → [modules]` index. Modules with no CVE reference are skipped.
- **Content:** Exploit, auxiliary, post, and payload modules, many CVE-mapped.

### Field mapping

Module metadata is extracted from the Ruby source via regex during sync; ingest reads
the index and writes to `exploits`.

```
modules/**/*.rb (parsed)
├── References ['CVE', 'YYYY-NNNN']  ✅ → cve_id  (regex; prefixed "CVE-")
├── module path (rel, no .rb)        ✅ → source_id
│                                         url = https://github.com/rapid7/metasploit-framework/blob/master/modules/<path>.rb
├── 'Name' => '…'                    ✅ → name  (falls back to file stem)
├── Rank = <X>Ranking                ✅ → metadata.rank  ("Ranking" stripped, lower-cased)
└── first path segment               ✅ → metadata.type  (exploits | auxiliary | post | payload)

constant
└── source                           ✅ → source = "metasploit"

Legend: ✅ imported  ✗ not imported
```

## Notes

- A Metasploit module is among the strongest weaponization signals available: if a
  module exists, the vulnerability is effectively weaponized.
- `rank` is the normalized module reliability (e.g. `excellent`, `great`, `good`,
  `normal`, `average`, `low`, `manual`) — stored verbatim as text in `metadata`; no
  numeric mapping is applied.
- Multiple modules per CVE are possible (different targets/payloads); each becomes a
  separate `exploits` row. The ingest writes one row per `(cve_id, source, url)`.
- "Does this CVE have an exploit?" =
  `EXISTS (SELECT 1 FROM exploits WHERE cve_id = … AND source = 'metasploit')`.

---

## Schema coverage

```
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
exploits           ✅  source='metasploit' · source_id=module path (e.g. exploits/linux/http/…)
                       name=module Name (or file stem)
                       url=https://github.com/rapid7/metasploit-framework/blob/master/modules/<path>.rb
                       metadata={rank, type}
epss / kev / ssvc  ❌  their own sources
```
