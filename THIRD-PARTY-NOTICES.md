# Third-Party Notices

limoza-vDB is built on third-party software and aggregates data from third-party
sources. This file lists them and their licenses as published by their respective
authors. limoza-vDB does **not** vendor (bundle) the source code of these dependencies —
they are fetched at build/run time — but they are acknowledged here as good practice.

The licenses below are believed accurate at the time of writing; the authoritative
license is always the one shipped by each upstream project. Links are provided so the
exact terms can be verified.

## Python dependencies

Installed at image-build time from `requirements.txt`.

| Package | License | Project |
|---------|---------|---------|
| httpx | BSD-3-Clause | https://github.com/encode/httpx |
| PyJWT | MIT | https://github.com/jpadilla/pyjwt |
| jmespath | MIT | https://github.com/jmespath/jmespath.py |
| jsonschema | MIT | https://github.com/python-jsonschema/jsonschema |
| psycopg2-binary | LGPL-3.0 (with OpenSSL exception) | https://github.com/psycopg/psycopg2 |
| python-debian | GPL-2.0-or-later | https://salsa.debian.org/python-debian-team/python-debian |

> **Note:** `python-debian` is GPL-2.0+ and `psycopg2` is LGPL-3.0. They are used as
> runtime libraries and are not redistributed as part of this repository. If you ever
> vendor them into the source tree, review the copyleft obligations of the combined work.

## Build tools & runtime images

Pulled at build or run time — not redistributed in this repository.

| Component | License | Source |
|-----------|---------|--------|
| Python (base image `python:3.12-slim`) | PSF License | https://www.python.org |
| Go toolchain (build stage `golang:1.22-alpine`) | BSD-3-Clause | https://go.dev |
| PostgreSQL (`postgres:16-alpine`) | PostgreSQL License | https://www.postgresql.org |
| pgAdmin (`dpage/pgadmin4`) | PostgreSQL License | https://www.pgadmin.org |
| Hasura GraphQL Engine (Community, custom build) | Apache-2.0 | https://github.com/McHill007/graphql-engine (fork of https://github.com/hasura/graphql-engine) |
| ofelia (`mcuadros/ofelia`) | MIT | https://github.com/mcuadros/ofelia |
| trivy-db-to | MIT | https://github.com/k1LoW/trivy-db-to |
| pgschema | see upstream | https://github.com/pgplex/pgschema |

> **Custom Hasura image:** the compose files use `ghcr.io/mchill007/graphql-engine`,
> a fork of Hasura GraphQL Engine **Community Edition** (Apache-2.0). It adds `_any` /
> `_all` filter operators for element-level pattern matching on string-array columns
> (e.g. `lve.aliases`), which limoza-vDB relies on. The changes are community-edition
> server features and remain under Apache-2.0:
> [PR #1](https://github.com/McHill007/graphql-engine/pull/1) (add `_any`/`_all` for
> `TEXT[]`) and [PR #2](https://github.com/McHill007/graphql-engine/pull/2) (extend to
> `varchar[]` and other string arrays). See
> [GraphQL & Hasura → custom build](docs/running/graphql.md#custom-hasura-build) for how
> it is used.

## Source data

limoza-vDB redistributes vulnerability **data** aggregated from many upstream feeds.
Each feed carries its own license / terms of use — see
[Data Sources → Source data licenses](docs/datasources/index.md#source-data-licenses).
For exploit-intelligence sources, only links + metadata are stored — never the exploit
or script body itself.
