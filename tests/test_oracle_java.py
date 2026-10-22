"""Oracle Java: NVD's CPU point rows mean "this release and every earlier one of the line"."""
from ingest.match import _java_host, _java_row, match_cpe


class _Cursor:
    def __init__(self, rows):
        self.rows, self.sql = rows, None

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def execute(self, sql, params=None):
        self.sql = sql

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, rows):
        self.cur = _Cursor(rows)

    def cursor(self):
        return self.cur


def _row(cve, update, intro, fixed=None, last=None):
    # (cve, source, introduced, fixed, last_affected, scheme, status, kb, update field, source_data)
    return (cve, "nvd", intro, fixed, last, "generic", "affected" if not fixed else "fixed", None, update, None)


def test_host_release_from_every_glance_form():
    assert _java_host("cpe:2.3:a:oracle:jre:1.8.0:update_231:*:*:*:*:*:*", "8.0.2310.11") == ("1.8", "1.8.0.231")
    assert _java_host("cpe:2.3:a:oracle:jre:8.0.2310.11:*:*:*:*:*:*:*", "8.0.2310.11") == ("1.8", "1.8.0.231")
    assert _java_host("cpe:2.3:a:oracle:openjdk:1.8.0_291-b09:update*:*:*:*:*:*:*", "") == ("1.8", "1.8.0.291")
    assert _java_host("cpe:2.3:a:oracle:jdk:11.0.24:*:*:*:*:*:*:*", "11.0.24+8-LTS") == ("11", "11.0.24")
    assert _java_host("cpe:2.3:a:oracle:jre:11.0.2+9:*:*:*:*:*:*:*", "11.0.2+9") == ("11", "11.0.2")
    assert _java_host("cpe:2.3:a:oracle:jre:-:*:*:*:*:*:*:*", "") is None   # → exact-key matching


def test_point_rows_mean_this_release_and_earlier():
    # 8u251 point → 1.8.0 GA … 8u251; update-field spellings incl. build suffix
    for upd in ("update251", "update_251", "update251_b08", "update251-b08"):
        assert _java_row("1.8", upd, "1.8.0", None, "1.8.0") == ("1.8.0.0", None, "1.8.0.251"), upd
    assert _java_row("11", "*", "11.0.7", None, "11.0.7") == ("11.0.0", None, "11.0.7")
    # another release line says nothing about this host
    assert _java_row("1.8", "update27", "1.7.0", None, "1.7.0") is None
    assert _java_row("11", "*", "17.0.11", None, "17.0.11") is None
    assert _java_row("11", "update251", "1.8.0", None, "1.8.0") is None
    # an update-less 1.8.0 (NVD 2014) is the GA release, not every update
    assert _java_row("1.8", "*", "1.8.0", None, "1.8.0") == ("1.8.0.0", None, "1.8.0.0")
    # Oracle CNA record (java_se) carries the newest CPU before NVD analysed it
    assert _java_row("1.8", "*", "Oracle Java SE:8u401", None, "Oracle Java SE:8u401") == (
        "1.8.0.0", None, "1.8.0.401")
    assert _java_row("11", "*", "Oracle Java SE:11.0.22", None, "Oracle Java SE:11.0.22") == (
        "11.0.0", None, "11.0.22")
    assert _java_row("11", "*", "Oracle GraalVM Enterprise Edition:20.3.13", None,
                     "Oracle GraalVM Enterprise Edition:20.3.13") is None


def test_java8_host_verdicts():
    rows = [_row("CVE-A", "update251", "1.8.0", last="1.8.0"),     # 8u251 and earlier
            _row("CVE-B", "update201", "1.8.0", last="1.8.0"),     # 8u201 and earlier
            _row("CVE-C", "*", "11.0.7", last="11.0.7"),           # only the 11 line
            _row("CVE-D", "update27", "0", last="1.6.0")]          # everything up to 6u27
    hits = match_cpe(_Conn(rows), "cpe:2.3:a:oracle:jre:1.8.0:update_231:*:*:*:*:*:*", "8.0.2310.11",
                     curations={})
    assert set(hits) == {"CVE-A"}                                  # 231 ≤ 251; 231 > 201
    newest = match_cpe(_Conn(rows), "cpe:2.3:a:oracle:jre:1.8.0:update_481:*:*:*:*:*:*", "1.8.0",
                       curations={})
    assert newest == {}


def test_java11_host_verdicts_and_real_fixes():
    rows = [_row("CVE-A", "*", "11.0.23", last="11.0.23"),
            _row("CVE-B", "*", "11", fixed="11.0.24"),               # a real fixed range (OpenJDK)
            _row("CVE-C", "update251", "1.8.0", last="1.8.0")]
    hits = match_cpe(_Conn(rows), "cpe:2.3:a:oracle:jdk:11.0.2:*:*:*:*:*:*:*", "11.0.2+9", curations={})
    assert set(hits) == {"CVE-A", "CVE-B"}
    assert match_cpe(_Conn(rows), "cpe:2.3:a:oracle:jdk:11.0.27:*:*:*:*:*:*:*", "11.0.27", curations={}) == {}
