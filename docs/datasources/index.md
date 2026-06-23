# Data Sources

limoza-vDB aggregates 20+ upstream sources, keyed by CVE id, into the shared
[data model](../ingest/schema.md). Each source page documents its feeds, the exact
source→schema mapping, and a **Schema Coverage** table showing which tables it
writes into.

[Red Hat](redhat.md) is the reference implementation — its page is the template
every other source follows (see the [documentation conventions](../datasource_blueprint.md)).

## Sources by category

### CVE baseline

| Source | Format | Writes |
|--------|--------|--------|
| [CVE List](cvelistv5.md) | CVE Record Format v5 (git) | `cve_record`, descriptions, cvss, cwes, references, solutions, workarounds, impacts, aliases |

### Linux distributions

| Source | Format | Writes |
|--------|--------|--------|
| [Red Hat](redhat.md) | CSAF 2.0 (VEX + advisories) | descriptions, cvss, cwes, references, advisories, vendor assessment |
| [SUSE](suse.md) | CSAF 2.0 (VEX + advisories) | descriptions, cvss, references, advisories, vendor assessment |
| [Ubuntu](ubuntu.md) | USN + OSV | descriptions, references, advisories, vendor assessment |
| [Debian](debian.md) | Security Tracker + OSV (DSA/DLA) | advisories, vendor assessment |
| [AlmaLinux](almalinux.md) | errata JSON | advisories, cvss, vendor assessment |
| [Rocky Linux](rocky.md) | Apollo API | advisories, cvss, cwes, vendor assessment |
| [Oracle Linux](oracle.md) | OVAL | advisories, cvss, vendor assessment |

### OS / vendor

| Source | Format | Writes |
|--------|--------|--------|
| [Microsoft MSRC](microsoft.md) | CVRF v3.0 | descriptions, cvss, cwes, references, advisories, vendor assessment |

### Package ecosystems

| Source | Format | Writes |
|--------|--------|--------|
| [GitHub Advisories](ghsa.md) | OSV JSON (advisory-database) | advisories, cvss, cwes, descriptions, affected packages |
| [OSV ecosystems](osv.md) | OSV JSON (native DBs) | advisories, descriptions |

### Risk scoring

| Source | Format | Writes |
|--------|--------|--------|
| [FIRST EPSS](epss.md) | CSV | `epss` |
| [CISA KEV](cisa-kev.md) | JSON feed | `kev` |
| [CISA SSVC](cisa-ssvc.md) | vulnrichment JSON | `ssvc` |

### Exploit intelligence

| Source | Format | Writes |
|--------|--------|--------|
| [Exploit-DB](exploitdb.md) | git + CSV | `exploits` |
| [Metasploit](metasploit.md) | git (modules) | `exploits` |
| [Nuclei](nuclei.md) | JSON Lines | `exploits` |
| [PoC-in-GitHub](poc-github.md) | JSON | `exploits` |

### Reference dictionaries

| Source | Format | Role |
|--------|--------|------|
| [CNA directory](cna.md) | CVE Program partner list | `cna` dictionary + L2 advisory patterns |
| [NVD CPE](cpe.md) | NVD CPE API 2.0 | `cpe` validation dictionary |
| [CWE](cwe.md) | CWE-CAPEC repo | `cwe` dictionary table |

## Source data licenses

limoza-vDB **redistributes** data from these sources, so each feed's terms apply to
the aggregated database. Licenses are summarized below as published by each source —
always check the source for the authoritative terms. Sources marked **attribution**
require you to credit them when redistributing.

| Source | License / terms | Notes |
|--------|-----------------|-------|
| CVE List (CVE Program / MITRE), CWE, NIST CPE | Public domain / free CVE Terms of Use | |
| CISA KEV, CISA SSVC | Public domain | U.S. government data |
| FIRST EPSS | Free to use — **attribution** requested | See FIRST EPSS terms |
| GitHub Advisories (GHSA) | CC-BY-4.0 — **attribution** | |
| OSV ecosystems | CC-BY-4.0 — **attribution** | Per-record licenses may vary |
| Red Hat (CSAF), SUSE (CSAF) | Freely available vendor security data — **attribution** | |
| Ubuntu (USN), Debian, Oracle, AlmaLinux, Rocky | Free distro security data | Respect each distro's terms |
| Microsoft MSRC | Freely available vendor security data | |
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
