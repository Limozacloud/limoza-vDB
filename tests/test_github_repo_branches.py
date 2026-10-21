"""Multi-branch per-repository GitHub advisories (php-src style) must keep each fix on its branch."""
from ingest.affected import COLS
from ingest.affected.sources import github_repo
from ingest.match import _cpe_verdict

# CVE-2026-109618 as php-src publishes it: one open-ended '<fix' span per maintained branch
# (php-src is configured with "branch_floors": true, which the ingest stamps onto its packages)
_PHP_PACKAGES = [{"purl": "pkg:php/php-src", "cpe": "cpe:2.3:a:php:php", "ranges": f"<{fix}",
                  "branch_floors": True} for fix in ("8.2.35", "8.3.36", "8.4.27", "8.5.12")]


class _Cursor:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, *_a):
        pass

    def fetchall(self):
        return self._rows


class _Conn:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return _Cursor(self._rows)


def _cpe_rows(packages):
    rows = (dict(zip(COLS, r)) for r in github_repo.extract(_Conn([("CVE-2026-109618", packages)]), {}))
    return [r for r in rows if r["coord"] == "cpe"]


def _affected(version, rows):
    verdict_rows = [(r["source"], r["introduced"], r["fixed"], r["last_affected"],
                     r["version_scheme"], r["status"], None, None) for r in rows]
    return bool(_cpe_verdict(version, verdict_rows))


def test_each_fix_branch_gets_its_own_lower_bound():
    rows = _cpe_rows(_PHP_PACKAGES)
    assert {(r["introduced"], r["fixed"]) for r in rows} == {
        ("8.2", "8.2.35"), ("8.3", "8.3.36"), ("8.4", "8.4.27"), ("8.5", "8.5.12")}
    assert {r["cpe23"] for r in rows} == {"cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"}


def test_vulnerable_host_on_every_branch_is_flagged():
    rows = _cpe_rows(_PHP_PACKAGES)
    for version in ("8.2.30", "8.3.30", "8.4.20", "8.5.10"):
        assert _affected(version, rows), version


def test_per_branch_fix_never_reaches_an_older_branch():
    # CVE-2026-17544: php-src '<8.4.24', '<8.5.9' — the CNA record and NVD say 8.4.0+ only
    rows = _cpe_rows([{"purl": "pkg:php/php-src", "cpe": "cpe:2.3:a:php:php", "ranges": f"<{fix}",
                       "branch_floors": True} for fix in ("8.4.24", "8.5.9")])
    for version in ("7.4.33", "8.2.30", "8.3.30"):
        assert not _affected(version, rows), version
    assert _affected("8.4.23", rows) and _affected("8.5.8", rows)


def test_unconfigured_repo_keeps_older_releases_affected():
    # without "branch_floors" the lowest branch keeps introduced='0' (literal advisory reading),
    # but the higher branches still get their own floor — a vulnerable 8.3.30 is never cleared
    rows = _cpe_rows([dict(p, branch_floors=False) for p in _PHP_PACKAGES])
    assert {(r["introduced"], r["fixed"]) for r in rows} == {
        ("0", "8.2.35"), ("8.3", "8.3.36"), ("8.4", "8.4.27"), ("8.5", "8.5.12")}
    for version in ("7.4.33", "8.2.30", "8.3.30"):
        assert _affected(version, rows), version


def test_rangeless_advisory_of_a_per_branch_project_is_not_applied_to_every_release():
    # php-src GHSA for CVE-2024-2408 carries no version range at all
    rangeless = [{"purl": "pkg:php/php-src", "cpe": "cpe:2.3:a:php:php", "ranges": None,
                  "branch_floors": True}]
    assert _cpe_rows(rangeless) == []
    # an unconfigured repo keeps the literal reading (Notepad++ behaviour unchanged)
    assert len(_cpe_rows([dict(rangeless[0], branch_floors=False)])) == 1


def test_patched_host_on_every_branch_is_clear():
    rows = _cpe_rows(_PHP_PACKAGES)
    for version in ("8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"):
        assert not _affected(version, rows), version


def test_single_open_span_and_explicit_ranges_are_unchanged():
    assert github_repo._branch_floors([(None, "8.7.4", None)]) == [(None, "8.7.4", None)]
    assert github_repo._branch_floors([(None, "8.3.6", None)], True) == [("8.3", "8.3.6", None)]
    spans = [("1.0", "1.5", None), (None, "2.0.3", None)]
    assert github_repo._branch_floors(spans) == spans


def test_ambiguous_fixes_are_left_alone():
    # two fixes on the same branch, or a non-x.y.z fix: no floor can be derived safely
    same = [(None, "8.2.30", None), (None, "8.2.35", None)]
    short = [(None, "8.2", None), (None, "8.3.1", None)]
    dot_zero = [(None, "8.0.0", None)]
    assert github_repo._branch_floors(same) == same
    assert github_repo._branch_floors(short) == short
    assert github_repo._branch_floors(dot_zero, True) == dot_zero
