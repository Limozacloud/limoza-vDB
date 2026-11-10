"""Windows Server 2012 R2 / 2008 R2: the MSRC rows name the product windows_server_2012_r2 while the CPE
key keeps R2 in the update field; the host must be looked up under the R2 product, not the base one."""
import pytest

from ingest.match import match_cpe


class _Cursor:
    def __init__(self, rows):
        self.rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return None

    def execute(self, _sql, _params=None):
        return None

    def fetchall(self):
        return self.rows


class _Conn:
    def __init__(self, rows):
        self.rows = rows

    def cursor(self):
        return _Cursor(self.rows)


def _row(product, fixed, kb):
    return ("CVE-2026-0001", "microsoft", "6.3", fixed, None, "generic", "fixed", kb, product,
            {"windows_product": product})


@pytest.mark.parametrize("cpe, version", [
    ("cpe:2.3:o:microsoft:windows_server_2012:*:r2:*:*:*:*:*:*", "6.3.9600.22221"),          # canonical (NVD) form
    ("cpe:2.3:o:microsoft:windows_server_2012_r2:*:*:*:*:*:*:*:*", "10.0.9600.22221"),       # older glance form
])
def test_an_r2_host_matches_the_r2_rows(cpe, version):
    rows = [_row("windows_server_2012_r2", "6.3.9600.22523", "KB5123456")]
    findings = match_cpe(_Conn(rows), cpe, version, curations={})
    assert findings["CVE-2026-0001"][0][3] == "KB5123456"


def test_an_r2_host_at_the_fixed_build_is_clean():
    rows = [_row("windows_server_2012_r2", "6.3.9600.22523", "KB5123456")]
    assert match_cpe(_Conn(rows), "cpe:2.3:o:microsoft:windows_server_2012:*:r2:*:*:*:*:*:*",
                     "6.3.9600.22523", curations={}) == {}


def test_a_host_without_r2_still_matches_its_own_rows():
    rows = [("CVE-2026-0002", "microsoft", "6.2", "6.2.9200.25000", None, "generic", "fixed", "KB5000001",
             "windows_server_2012", {"windows_product": "windows_server_2012"})]
    findings = match_cpe(_Conn(rows), "cpe:2.3:o:microsoft:windows_server_2012:*:*:*:*:*:*:*:*",
                         "6.2.9200.20000", curations={})
    assert findings["CVE-2026-0002"][0][3] == "KB5000001"


def test_r2_rows_do_not_apply_to_a_host_of_the_base_release():
    rows = [_row("windows_server_2012_r2", "6.3.9600.22523", "KB5123456")]
    assert match_cpe(_Conn(rows), "cpe:2.3:o:microsoft:windows_server_2012:*:*:*:*:*:*:*:*",
                     "6.2.9200.20000", curations={}) == {}
