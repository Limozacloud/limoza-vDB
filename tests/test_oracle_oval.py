"""Oracle OVAL: the fix EVR of a module-stream build names its release with "+el8", a plain build with ".el8"."""
from ingest.affected import COLS
from ingest.affected.sources.oracle import _oval_rows

OVAL = """<oval_definitions><definitions>
<definition class="patch"><metadata><advisory><cve>CVE-2026-0001</cve></advisory></metadata>
 <criteria><criterion comment="httpd is earlier than 0:2.4.37-65.0.1.module+el8.10.0+91092+d4ec9ae3.8"/>
 <criterion comment="bind is earlier than 32:9.11.4-26.P2.el7_9.16"/>
 <criterion comment="kernel-uek is earlier than 0:5.15.0-300.el8uek"/>
 <criterion comment="nothing-with-a-tag is earlier than 1.2.3-4"/></criteria></definition>
</definitions></oval_definitions>"""


def test_module_stream_and_plain_builds_both_get_their_release(tmp_path):
    f = tmp_path / "oval.xml"
    f.write_text(OVAL)
    rows = list(_oval_rows(f))
    got = {(r[COLS.index("package")], r[COLS.index("release")], r[COLS.index("fixed")]) for r in rows}
    assert got == {
        ("httpd", "el8", "0:2.4.37-65.0.1.module+el8.10.0+91092+d4ec9ae3.8"),
        ("bind", "el7", "32:9.11.4-26.P2.el7_9.16"),
        ("kernel-uek", "el8", "0:5.15.0-300.el8uek"),
    }
