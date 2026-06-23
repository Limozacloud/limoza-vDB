# PoC-in-GitHub

Exploit-intelligence source. Aggregates GitHub repositories that contain
proof-of-concept code for CVEs and records each repository in the `exploits` table. No
CVSS, advisory, or remediation data is produced.

## nomi-sec/PoC-in-GitHub
- **URL:** `https://github.com/nomi-sec/PoC-in-GitHub`
- **Official:** No — community-maintained aggregator
- **Format:** JSON, one file per CVE; each file is a JSON array of GitHub repository objects
- **Local path:** `<poc_github>/repo` (shallow clone, `depth=1`); generated index at `<poc_github>/poc_github_index.json`
- **Sync:** `git clone --depth=1` on first run, `git pull --ff-only` afterwards, gated on HEAD commit hash. The sync step walks all `CVE-*.json` files in the repository, parses each array of repository objects, and builds a `CVE → [repos]` index. Repository objects without a `full_name` are skipped.
- **Content:** Per CVE, a list of GitHub repositories purporting to contain PoC exploit code, with repository metadata (stars, timestamps, fork flag).

### Field mapping

Ingest reads the index and writes one `exploits` row per repository object.

```
<year>/CVE-YYYY-NNNNN.json (array of repo objects)
├── (filename stem)        ✅ → cve_id  (kept if starts with "CVE-")
├── full_name              ✅ → source_id  (required — entries without it are skipped)
├── description            ✅ → name  (truncated to 200 chars)
├── html_url               ✅ → url  (falls back to https://github.com/<full_name>)
├── stargazers_count       ✅ → metadata.stars  (int)
├── created_at             ✅ → metadata.created_at  (first 10 chars, YYYY-MM-DD)
├── pushed_at              ✅ → metadata.pushed_at  (first 10 chars, YYYY-MM-DD)
└── fork                   ✅ → metadata.is_fork  (bool)

constant
└── source                 ✅ → source = "poc_github"

Legend: ✅ imported  ✗ not imported
```

## Notes

- Community-aggregated and unverified: many repositories are incomplete, educational,
  forks, or non-functional. There is no quality filter beyond the GitHub metadata
  available in the source.
- `stars` is a rough attention signal; `is_fork = true` repositories are typically lower
  quality; `pushed_at` indicates recency.
- Presence of a row means PoC code is publicly accessible for that CVE, but
  functionality varies widely.
- "Does this CVE have an exploit?" =
  `EXISTS (SELECT 1 FROM exploits WHERE cve_id = … AND source = 'poc_github')`.

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
exploits           ✅  source='poc_github' · source_id=owner/repo (full_name)
                       name=repo description (≤200 chars)
                       url=html_url (or https://github.com/<full_name>)
                       metadata={stars, created_at, pushed_at, is_fork}
epss / kev / ssvc  ❌  their own sources
```
