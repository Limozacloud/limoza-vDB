"""Parse the "Response Matrix" of a Broadcom (VMware) security advisory page.

Each advisory page carries one table per vulnerability group with the columns

    Product | Component | Version | Running On | CVE | CVSSv3 | Severity | Fixed Version | Workaround | …

e.g. ``VMware Tools | N/A | 12.x.x, 11.x.x | Windows, Linux | CVE-2025-41244 | 7.8 | Important | 12.5.4``.
Pages written before the matrix was introduced use other column names and yield nothing.
"""
import re
from html.parser import HTMLParser

_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_FOOTNOTE = re.compile(r"\s*\[\d+\]")
_VERSION = re.compile(r"^\d+(?:\.\d+)*$")
_PREFIX = re.compile(r"^\s*(\d+(?:\.\d+)*)")
# the column layouts seen on the portal: "Product" or "VMware Product", "CVE" or "CVE Identifier", with or
# without a "Component" column
_COLUMNS = {
    "product": ("product", "vmware product"),
    "component": ("component",),
    "version": ("version",),
    "running_on": ("running on",),
    "cve": ("cve", "cve identifier"),
    "fixed": ("fixed version",),
}
_OPTIONAL = {"component"}


def _column_index(head: list):
    """Column name → index for a matrix header, or None when the table is not a response matrix."""
    out = {}
    for key, names in _COLUMNS.items():
        hit = next((head.index(n) for n in names if n in head), None)
        if hit is None and key not in _OPTIONAL:
            return None
        out[key] = hit
    return out


class _Tables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self._table, self._row, self._cell = [], None, None, None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self._table = []
        elif tag == "tr" and self._table is not None:
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self._cell is not None and self._row is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None and self._table is not None:
            self._table.append(self._row)
            self._row = None
        elif tag == "table" and self._table is not None:
            self.tables.append(self._table)
            self._table = None

    def handle_data(self, data):
        if self._cell is not None:
            self._cell.append(data)


def strip_footnote(text: str) -> str:
    """'VMware Tools [2]' → 'VMware Tools'"""
    return _FOOTNOTE.sub("", text or "").strip()


def parse_matrices(page: str) -> list:
    """Every matrix row of the page as a dict: product, component, version, running_on, cves, fixed."""
    p = _Tables()
    p.feed(page)
    out = []
    for table in p.tables:
        if not table:
            continue
        ix = _column_index([c.lower() for c in table[0]])
        if ix is None:
            continue
        need = max(i for i in ix.values() if i is not None)
        for r in table[1:]:
            if len(r) <= need:
                continue
            out.append({
                "product": strip_footnote(r[ix["product"]]),
                "component": strip_footnote(r[ix["component"]]) if ix["component"] is not None else "",
                "version": r[ix["version"]],
                "running_on": r[ix["running_on"]],
                "cves": _CVE.findall(r[ix["cve"]]),
                "fixed": strip_footnote(r[ix["fixed"]]),
            })
    return out


def lower_bound(version_cell: str):
    """Lowest affected version a matrix 'Version' cell stands for, or None.
    '13.x.x.x [2]' → '13', '12.x.x, 11.x.x' → '11', '12.5.x' → '12.5', '8.0 U3' → '8.0'."""
    bounds = []
    for token in re.split(r"[,;/]|\band\b", strip_footnote(version_cell)):
        m = _PREFIX.match(token.replace(".x", ""))
        if m:
            bounds.append(m.group(1))
    if not bounds:
        return None
    return min(bounds, key=lambda v: tuple(int(x) for x in v.split(".")))


def fixed_version(cell: str):
    """The fixed version when the cell is one, else None ('Unaffected', 'N/A', 'KB92148', 'Patch Pending')."""
    cell = (cell or "").strip()
    return cell if _VERSION.match(cell) else None
