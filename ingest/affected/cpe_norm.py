"""Canonical CPE resolution against the NVD CPE dictionary.

MSRC and the CVE List encode the same product differently — MSRC puts "R2" in the
product name (windows_server_2012_R2) while NVD/scanners put it in the update field
(windows_server_2012 + update=r2) — and many older MSRC entries (2019-2021) carry no
CPE at all. We resolve everything to the form the NVD dictionary actually has:
generate candidate (vendor, product, update) tuples and keep the one NVD contains, so a
stored affected row and a scanned component always land on the same key.

Call :func:`load` once (DB access needed); :func:`canonical` resolves a real CPE,
:func:`from_name` resolves a human product name (the no-CPE fallback). The key keeps the
update field (so windows_server_2012 vs …_2012 r2 stay distinct) and is 13-field lowercase.
"""
import re

_VP = None       # {(vendor, product)}
_VPU = None      # {(vendor, product, update)}
_VAGUE = {"*", "-", ""}
_SPLIT = re.compile(r"(.+?)_(r2|sp\d+)$")
# product-name qualifiers that don't affect product identity (arch / core / SP / CU / edition)
_QUAL = re.compile(
    r"\s*\(server core[^)]*\)|\s*\((?:32|64)-bit editions?\)"
    r"|\s+for (?:x64|32|64|arm64|itanium)[\w-]*\s*systems?"
    r"|\s+for (?:32|64)-bit editions?|\s+(?:32|64)-bit editions?"
    r"|\s+service pack \d+|\s+cumulative update \d+|\s+version \d+\.\d.*$"
    r"|\s+gold\b", re.I)


def load(conn) -> None:
    global _VP, _VPU
    if _VP is not None:
        return
    _VP, _VPU = set(), set()
    with conn.cursor() as cur:
        cur.execute("SELECT vendor, product, split_part(cpe_uri, ':', 7) FROM cpe")
        for v, p, u in cur:
            if v and p:
                _VP.add((v, p))
                if u and u not in _VAGUE:
                    _VPU.add((v, p, u))


def _key(part, vendor, product, update) -> str:
    return ":".join(["cpe", "2.3", part, vendor, product, "*", update or "*"] + ["*"] * 6)


def _resolve(part, vendor, product, update):
    """Pick the NVD-valid (product, update) among candidates → key, or None."""
    upd = update if update not in _VAGUE else None
    cands = [(product, upd)]
    m = _SPLIT.match(product)
    if m:
        cands.append((m.group(1), m.group(2)))        # _r2 in product → update field
    if upd:
        cands.append((product + "_" + upd, None))     # or update folded into product
    # MSRC bakes a version into some product names (odbc_driver_18_for_sql_server,
    # ole_db_driver_19_for_sql_server) that NVD carries without it. Try the stripped form
    # as a LAST resort — an embedded numeric token only (followed by "_"), so trailing years
    # that NVD keeps (office_2016, sql_server_2019) are left untouched.
    stripped = re.sub(r"_\d+(?=_)", "", product)
    if stripped != product:
        cands.append((stripped, upd))
    if _VP is not None:
        for prod, u in cands:
            if u and (vendor, prod, u) in _VPU:
                return _key(part, vendor, prod, u)
            if not u and (vendor, prod) in _VP:
                return _key(part, vendor, prod, None)
    return None


def canonical(cpe):
    """Real CPE 2.3 string → (canonical key, version), STRICT: key is None unless the
    (vendor, product[, update]) exists in the NVD catalog — so we only ever store CPEs a
    scanner can actually produce."""
    p = (cpe or "").lower().split(":")
    if len(p) < 6 or p[0] != "cpe":
        return None, None
    p = (p + ["*"] * 13)[:13]
    ver = p[5] if p[5] not in _VAGUE else None
    return _resolve(p[2], p[3], p[4], p[6]), ver


def from_name(value, vendor="microsoft"):
    """Human product name (no-CPE MSRC product) → NVD-validated canonical key, or None."""
    s = _QUAL.sub("", (value or "").lower()).replace(",", " ")
    update = None
    if re.search(r"\br2\b", s):
        update = "r2"
        s = re.sub(r"\br2\b", "", s)
    s = s.replace("version ", "").replace("(chromium-based)", "chromium")
    s = re.sub(r"\s+", " ", s).strip()
    product = re.sub(r"\s+", "_", s)
    part = "o" if product.startswith("windows") else "a"
    for prod in (product, product.replace("microsoft_", "")):
        k = _resolve(part, vendor, prod, update)
        if k:
            return k
    return None
