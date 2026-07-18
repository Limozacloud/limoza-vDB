# Changelog

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
