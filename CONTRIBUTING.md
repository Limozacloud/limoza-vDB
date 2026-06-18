# Contributing

Thanks for your interest in improving limoza-vDB.

## Branching strategy

limoza-vDB uses a **trunk-based** workflow:

- **`main`** is the single long-lived branch. It is protected and always kept in a
  releasable state — every commit on `main` has passed CI.
- All work happens on **short-lived branches** off `main`, named by intent:
  - `feat/<short-description>` — new functionality
  - `fix/<short-description>` — bug fixes
  - `docs/<short-description>` — documentation only
  - `chore/` · `refactor/` · `ci/` · `build/` — everything else
- Open a **Pull Request** into `main`. CI must pass and at least one review is required
  before merge. Prefer **squash merges** so each change is one clean commit on `main`.

Direct pushes to `main` are disabled — always go through a PR.

## Commit messages — Conventional Commits

Commit messages (and PR titles, since PRs are squash-merged) **must** follow
[Conventional Commits](https://www.conventionalcommits.org):

```
<type>[optional scope]: <description>

feat(ghsa): add Erlang/hex ecosystem PURL mapping
fix(cisa_kev): treat "Unknown" ransomware flag as false
docs(redhat): correct the CVSS field mapping
```

Common types: `feat`, `fix`, `perf`, `refactor`, `docs`, `build`, `ci`, `chore`.
A breaking change is marked with `!` (e.g. `feat!:`) or a `BREAKING CHANGE:` footer.

This is required because versioning and the changelog are **automated** (see below).

## Releases

Releases are automated with
[release-please](https://github.com/googleapis/release-please):

1. Merging Conventional Commits into `main` makes release-please open/update a
   **release PR** that bumps the version and updates `CHANGELOG.md`.
2. Merging that release PR creates the Git tag `vX.Y.Z` and a GitHub Release.
3. Publishing the release triggers the Docker image build, pushed to
   `ghcr.io/limozacloud/limoza-vdb`.

Version bumps follow semver: `fix` → patch, `feat` → minor, breaking change → major.

## Local development

```bash
python -m venv .venv && . .venv/Scripts/activate   # or .venv/bin/activate on Linux/macOS
pip install ruff
pip install -r requirements-docs.txt

ruff check .                 # lint (same check CI runs)
mkdocs serve                 # preview docs at http://127.0.0.1:8000
```

CI runs `ruff check .` and `mkdocs build --strict` on every pull request.

## Adding a new data source

See the [documentation conventions](docs/datasource_blueprint.md) for the LVE record and
the structure every `docs/datasources/<vendor>.md` page must follow. Use
[Red Hat](docs/datasources/redhat.md) as the reference implementation.

## Reporting security issues

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md). Do not open a
public issue for security problems.
