# Changelog

## [0.5.0](https://github.com/Limozacloud/limoza-vDB/compare/v0.4.0...v0.5.0) (2026-09-04)


### Features

* github_repo source — per-repo GitHub security advisories for non-ecosystem software ([#28](https://github.com/Limozacloud/limoza-vDB/issues/28)) ([b2f1b7d](https://github.com/Limozacloud/limoza-vDB/commit/b2f1b7d2a9d580300b3ca0c8dde5bc5ea25216b2))


### Bug Fixes

* align Microsoft and GHSA remediation matching with Tenable ([#56](https://github.com/Limozacloud/limoza-vDB/issues/56)) ([e3d28b3](https://github.com/Limozacloud/limoza-vDB/commit/e3d28b315fcf2bd2db7e077812f5c4c72dbefcb9))
* backfill empty Edge FixedBuild so all Edge (Chromium) CVEs match ([#29](https://github.com/Limozacloud/limoza-vDB/issues/29)) ([86986c9](https://github.com/Limozacloud/limoza-vDB/commit/86986c93cf4551ba18a6567bed1dd97730ccb450))
* match Microsoft SQL Server CPE across its edition products ([#44](https://github.com/Limozacloud/limoza-vDB/issues/44)) ([#46](https://github.com/Limozacloud/limoza-vDB/issues/46)) ([9306c1a](https://github.com/Limozacloud/limoza-vDB/commit/9306c1ace1dd74625e1f9230607d8110dd5b4f40))
* matcher looks up the binary package first, source only as fallback ([#38](https://github.com/Limozacloud/limoza-vDB/issues/38)) ([9dcbc34](https://github.com/Limozacloud/limoza-vDB/commit/9dcbc34e4d54d07494f982eb8820c8c2430ed48a))
* Microsoft CPE family match uses exact keys (index scan, not a 14M-row seq scan) ([#48](https://github.com/Limozacloud/limoza-vDB/issues/48)) ([e9bc072](https://github.com/Limozacloud/limoza-vDB/commit/e9bc0722276f36bcfdb8fe82516d6867963cc0d5))
* only emit affected rows for base-RHEL platforms, skip layered products ([#40](https://github.com/Limozacloud/limoza-vDB/issues/40)) ([85d1171](https://github.com/Limozacloud/limoza-vDB/commit/85d1171c740d11726189eea2810c1368d66b70f1))
* rebuild each affected origin with an atomic swap so /match stays consistent ([#33](https://github.com/Limozacloud/limoza-vDB/issues/33)) ([6db3882](https://github.com/Limozacloud/limoza-vDB/commit/6db388262dfd282f98df3f7fc6669efb13b2969a))
* redhat _resolve returns a 5-tuple in the base-platform guard (daily crash) ([#47](https://github.com/Limozacloud/limoza-vDB/issues/47)) ([a28dd6f](https://github.com/Limozacloud/limoza-vDB/commit/a28dd6f8b628766a5333368ce7e94b884d566af1))
* rpm matcher — binary+source lookup and bare .elN stream expansion ([#31](https://github.com/Limozacloud/limoza-vDB/issues/31)) ([e0a370f](https://github.com/Limozacloud/limoza-vDB/commit/e0a370fe3e2a7d32071d785336d368fe96748e08))
* rpm matcher — scope to the host's own line (fips/ksplice variant + EUS minor) ([#32](https://github.com/Limozacloud/limoza-vDB/issues/32)) ([6d95743](https://github.com/Limozacloud/limoza-vDB/commit/6d957434cc5052acf7586dc287b0b6dda64509af))
* scope a kernel host to its own version line (kernel-alt cross-line FP) ([#53](https://github.com/Limozacloud/limoza-vDB/issues/53)) ([a2e567b](https://github.com/Limozacloud/limoza-vDB/commit/a2e567b334cad1b7043fdc3a4bf5b9b70ea00ba1))
* scope AppStream module fixes to the host's stream (module_stream) ([#43](https://github.com/Limozacloud/limoza-vDB/issues/43)) ([e6f8c06](https://github.com/Limozacloud/limoza-vDB/commit/e6f8c0612e96b7414cf4fbb99eee8d1795a8f5a8))
* scope Microsoft remediation by applicability ([#58](https://github.com/Limozacloud/limoza-vDB/issues/58)) ([1d1670b](https://github.com/Limozacloud/limoza-vDB/commit/1d1670bf794d96bdd89ac418c6cbc856cd27f825))
* scope SharePoint vulnerability matching by edition ([#51](https://github.com/Limozacloud/limoza-vDB/issues/51)) ([070965e](https://github.com/Limozacloud/limoza-vDB/commit/070965ee64347af9fd5cac2dc6c71204cb11a7db))
* scope SUSE/SLE hosts to their own codestream + product family ([#22](https://github.com/Limozacloud/limoza-vDB/issues/22), [#23](https://github.com/Limozacloud/limoza-vDB/issues/23)) ([#45](https://github.com/Limozacloud/limoza-vDB/issues/45)) ([44ba6b4](https://github.com/Limozacloud/limoza-vDB/commit/44ba6b451c1ae955e63cf1596374984ecc3d471b))
* suppress AppStream module co-rebuild false positives (parallel-line guard + VEX) ([#39](https://github.com/Limozacloud/limoza-vDB/issues/39)) ([c6cfa51](https://github.com/Limozacloud/limoza-vDB/commit/c6cfa513f6c882581436de9ca7ec55b9928727a0))

## [0.4.0](https://github.com/Limozacloud/limoza-vDB/compare/v0.3.0...v0.4.0) (2026-07-18)


### Features

* per-component remediation in /match (highest fix that closes all) ([#21](https://github.com/Limozacloud/limoza-vDB/issues/21)) ([247640a](https://github.com/Limozacloud/limoza-vDB/commit/247640ab7ae897deb6804163ee421ca2417c205e))

## [0.3.0](https://github.com/Limozacloud/limoza-vDB/compare/v0.2.0...v0.3.0) (2026-07-07)


### Features

* matcher accuracy, fix_kb, curation layer, Node.js source, read-only MCP ([#19](https://github.com/Limozacloud/limoza-vDB/issues/19)) ([a8d1cfc](https://github.com/Limozacloud/limoza-vDB/commit/a8d1cfc89e80992fa36f01e761efba9615aa3215))

## [0.2.0](https://github.com/Limozacloud/limoza-vDB/compare/v0.1.1...v0.2.0) (2026-06-26)


### Features

* add shared CWE dictionary table with rich weakness definitions ([#19](https://github.com/Limozacloud/limoza-vDB/issues/19)) ([20bb9a9](https://github.com/Limozacloud/limoza-vDB/commit/20bb9a925b62f38eec1b3b179f7c103449a894b1))
* LVE (custom entries) + bulk match — MCP tools + REST API ([#10](https://github.com/Limozacloud/limoza-vDB/issues/10)) ([e089a44](https://github.com/Limozacloud/limoza-vDB/commit/e089a44ff4c978e8e887cf8936d73cc71d1367e0))
* **mcp:** add optional self-hosted MCP server ([#18](https://github.com/Limozacloud/limoza-vDB/issues/18)) ([0567fff](https://github.com/Limozacloud/limoza-vDB/commit/0567fff2b7a022a0d6b95946f76f5162a42ed693))
* Microsoft MSRC affected layer + NVD-validated CPE matching ([#8](https://github.com/Limozacloud/limoza-vDB/issues/8)) ([d7115ea](https://github.com/Limozacloud/limoza-vDB/commit/d7115eaf4ef87ae85e844f335e6371f749ae8070))
* NVD CPE enrichment + matcher correctness & coverage fixes ([#14](https://github.com/Limozacloud/limoza-vDB/issues/14)) ([30b45ff](https://github.com/Limozacloud/limoza-vDB/commit/30b45fff0b225fd8a8d34270c7af40afb26b389e))
* NVD ingestor, distro status de-noising (Debian/Ubuntu), explain_status MCP tool, compact get_cve_detail ([#15](https://github.com/Limozacloud/limoza-vDB/issues/15)) ([d8222c3](https://github.com/Limozacloud/limoza-vDB/commit/d8222c339af47cba460ed13f7e6490767d0e3412))


### Bug Fixes

* **exploitdb:** store only link and metadata, not the exploit body ([#11](https://github.com/Limozacloud/limoza-vDB/issues/11)) ([337760e](https://github.com/Limozacloud/limoza-vDB/commit/337760eaead46485e8d33fdae76275695e4ab1ed))
* maven matcher — normalize group:artifact ([#7](https://github.com/Limozacloud/limoza-vDB/issues/7)) ([065e88e](https://github.com/Limozacloud/limoza-vDB/commit/065e88e93383ea5588e7063206a68a6231e7376f))
* ofelia daily job — run the pipeline via a single `vdb daily` command ([#9](https://github.com/Limozacloud/limoza-vDB/issues/9)) ([f04b085](https://github.com/Limozacloud/limoza-vDB/commit/f04b085f9105e3cdcd32d2ba374875f996984844))
* prefer CPE over a generic purl in bulk match ([#13](https://github.com/Limozacloud/limoza-vDB/issues/13)) ([8efff0b](https://github.com/Limozacloud/limoza-vDB/commit/8efff0bf2525bdfba080d8da2db3d2326305b81d))
* prevent lve_history collision on simultaneous advisories ([03de94c](https://github.com/Limozacloud/limoza-vDB/commit/03de94c458bd704227beb3e7978e385f7622d3a0))


### CI

* allow manual dispatch of release-please ([4a357fb](https://github.com/Limozacloud/limoza-vDB/commit/4a357fba236177b82fbdb371b102f6aeb796c93a))
* path-filtered CI with aggregating gate, dependabot groups, prod image ([#12](https://github.com/Limozacloud/limoza-vDB/issues/12)) ([fe2d556](https://github.com/Limozacloud/limoza-vDB/commit/fe2d55654513e888076226422c811f46aa830a5a))
* publish image from the release-please run, add manual tag dispatch ([#15](https://github.com/Limozacloud/limoza-vDB/issues/15)) ([0bd36c6](https://github.com/Limozacloud/limoza-vDB/commit/0bd36c62735edd40aefa76d945ae8385395a7608))


### Chores

* set next release to 0.2.0 ([#12](https://github.com/Limozacloud/limoza-vDB/issues/12)) ([7124756](https://github.com/Limozacloud/limoza-vDB/commit/712475667f7655385fef4a088480aa11e31e0db8))
* start release line at 0.1.0 ([978edee](https://github.com/Limozacloud/limoza-vDB/commit/978edee24936e1a9839d644daae8ca392f5f5145))
