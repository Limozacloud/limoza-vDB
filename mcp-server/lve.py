"""Create a Local Vulnerability Entry (LVE) via a Hasura insert mutation.

The caller's token role must be `lve_writer` — Hasura rejects the insert otherwise, which
IS the write gate. On insert a DB trigger materialises the matching `affected` row, so the
new LVE is checked immediately by check_vulnerable / match_bulk (and the `lve` affected
extractor re-seeds it on every rebuild, so it survives a truncate).
"""
import datetime
import re

from matcher import _parse, _parse_cpe

_ID = re.compile(r"^LVE-\d{4}-(\d+)$")
_NEXT = "query($p:String!){ lve(where:{id:{_like:$p}}, order_by:{id:desc}, limit:1){ id } }"
_INS = "mutation($o:lve_insert_input!){ insert_lve_one(object:$o){ id } }"


async def create_lve(hasura, product, title, *, fixed=None, introduced=None,
                     last_affected=None, severity=None, description=None,
                     version_scheme=None, status="affected", created_by=None):
    if product.startswith("cpe:"):
        key, _ = _parse_cpe(product)
        if not key:
            raise ValueError("invalid cpe 2.3 string")
        ident = {"coord": "cpe", "cpe23": key}
    else:
        ptype, name, _, quals = _parse(product)
        ident = {"coord": "purl", "ecosystem": ptype, "package": name, "purl": product}
        if quals.get("distro"):
            ident["release"] = quals["distro"]

    year = datetime.datetime.now(datetime.timezone.utc).year
    prev = (await hasura.query(_NEXT, {"p": f"LVE-{year}-%"})).get("lve") or []
    n = (int(_ID.match(prev[0]["id"]).group(1)) + 1) if prev else 1
    lid = f"LVE-{year}-{n:04d}"

    obj = {"id": lid, "title": title, "description": description, "severity": severity,
           "introduced": introduced, "fixed": fixed, "last_affected": last_affected,
           "version_scheme": version_scheme or "generic", "status": status,
           "created_by": created_by, **ident}
    obj = {k: v for k, v in obj.items() if v is not None}
    await hasura.query(_INS, {"o": obj})
    return obj
