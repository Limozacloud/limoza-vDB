# Data Sources

limoza-vDB aggregates 20+ upstream sources into the unified [LVE record](../ingest/schema.md).
Each source page documents its feeds, the exact source→schema field mapping, and a
**Schema Coverage** table showing which parts of the record it populates.

[Red Hat](redhat.md) is the reference implementation — its page is the template every
other source follows (see the [documentation conventions](../datasource_blueprint.md)).

## Sources by category

### Linux distributions

| Source | Format | Populates |
|--------|--------|-----------|
| [Red Hat](redhat.md) | CSAF 2.0 (VEX + advisories) | titles, descriptions, cvss, cwes, references, advisories, packages, mitigations, impacts, history |
| [SUSE](suse.md) | CSAF 2.0 (VEX + advisories) | descriptions, cvss, references, advisories, packages, impacts, history |
| [Ubuntu](ubuntu.md) | OpenVEX + USN + OSV | titles, descriptions, references, advisories, packages, history |
| [Debian](debian.md) | Security Tracker + DSA/DLA | titles, descriptions, references, advisories, packages, history |
| [Alpine](alpine.md) | secdb | packages |
| [AlmaLinux](almalinux.md) | errata JSON | titles, descriptions, references, advisories, packages, history |
| [Rocky Linux](rocky.md) | updateinfo + Apollo API | titles, descriptions, references, advisories, packages, history |
| [Oracle Linux](oracle.md) | OVAL | titles, cvss, advisories, packages, history |

### OS / vendor

| Source | Format | Populates |
|--------|--------|-----------|
| [Microsoft MSRC](microsoft.md) | CVRF v3.0 | titles, descriptions, cvss, cwes, references, advisories, packages, notices, history |

### CVE baseline

| Source | Format | Populates |
|--------|--------|-----------|
| [NVD / MITRE](nvd.md) | NVD JSON 2.0 | cve spine (status/published/updated), descriptions, cvss, cwes, references, history |

### Package ecosystems

| Source | Format | Populates |
|--------|--------|-----------|
| [GitHub Security Advisories](ghsa.md) | OSV JSON | titles, descriptions, cvss, cwes, references, advisories, upstream |
| [OSV](osv.md) | OSV JSON | titles, descriptions, cvss, cwes, references, advisories, upstream, history |

### Risk scoring & enrichment

| Source | Format | Populates |
|--------|--------|-----------|
| [FIRST EPSS](epss.md) | CSV / JSON | `cve.epss` |
| [CISA KEV](cisa-kev.md) | JSON feed | `cve.kev` |
| [CISA SSVC](cisa-ssvc.md) | vulnrichment JSON | `cve.ssvc` |
| [BSI WID](bsi.md) | ROLIE + CSAF | titles, descriptions, references, advisories, history |

### Exploit intelligence

| Source | Format | Populates |
|--------|--------|-----------|
| [Exploit-DB](exploitdb.md) | git + CSV | exploits, `has_exploit` |
| [Metasploit](metasploit.md) | git (modules) | exploits, `has_exploit` |
| [Nuclei](nuclei.md) | JSON Lines | exploits, `has_exploit` |
| [PoC-in-GitHub](poc-github.md) | JSON | exploits, `has_exploit` |

### Reference dictionaries

| Source | Format | Role |
|--------|--------|------|
| [NVD CPE](cpe.md) | NVD CPE API 2.0 | CPE validation dictionary (no LVE records) |
| [CWE](cwe.md) | CWE REST-API repo | `cwe` dictionary table + name fallback for `cwes[].name` |

## Source data licenses

limoza-vDB **redistributes** data from these sources, so each feed's terms apply to the
aggregated database. Licenses are summarized below as published by each source — always
check the source for the authoritative terms. Sources marked **attribution** require you
to credit them when redistributing.

| Source | License / terms | Notes |
|--------|-----------------|-------|
| NVD / MITRE (CVE, CWE), NIST CPE | Public domain / free CVE Terms of Use | U.S. government data |
| CISA KEV, CISA SSVC | Public domain | U.S. government data |
| FIRST EPSS | Free to use — **attribution** requested | See FIRST EPSS terms |
| GitHub Advisories (GHSA) | CC-BY-4.0 — **attribution** | |
| OSV | CC-BY-4.0 — **attribution** | Per-record licenses may vary |
| Red Hat (CSAF), SUSE (CSAF) | Freely available vendor security data — **attribution** | |
| Ubuntu (USN), Debian, Alpine, Oracle, AlmaLinux, Rocky | Free distro security data | Respect each distro's terms |
| BSI WID | German federal advisory data | Stored titles/descriptions may be in German |
| Metasploit modules | BSD-style (Metasploit Framework license) | Individual modules may differ |
| Nuclei templates | MIT | |
| PoC-in-GitHub | Aggregated GitHub repo metadata | Each linked repo has its own license |
| Exploit-DB | Links + metadata only | Exploit bodies are not stored |

For the exploit-intelligence sources (Exploit-DB, Metasploit, Nuclei, PoC-in-GitHub),
limoza-vDB stores only a **link** to each artifact plus factual metadata — never the
exploit/script body itself.

This project itself is licensed under
[PolyForm Noncommercial 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0)
(noncommercial use only); see also the repository's `THIRD-PARTY-NOTICES.md` for the
software dependencies.
