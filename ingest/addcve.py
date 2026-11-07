"""`vdb add-cve CVE-YYYY-N… [CVE-…]` — bring single, brand-new CVEs into the DB without waiting for `vdb daily`.

The daily run needs hours (the affected pass rebuilds ~50M rows); a CVE that was published an hour ago would
stay unknown until the next 05:00 run. This command:

  1. fetches the CVE Record v5 from the CVE Services API (the record the cvelistV5 git mirror will contain later),
  2. writes the cvelistv5-origin rows with the regular importer (so the daily run later simply overwrites them),
  3. derives the cvelistv5 `affected` rows (the cpe lane) for just these CVEs and swaps them in one transaction.

Not covered (the daily run fills them in): NVD configurations, vendor advisories, KEV/SSVC/EPSS (--scoring
refreshes those three, they are small). A CVE whose CNA gives no CPE ends up in `cve_record` without
`affected` rows — that is reported, not hidden.
"""
import json
import os
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

from ingest.core.cveid import normalize

_API = "https://cveawg.mitre.org/api/cve/"
ORIGIN = "cvelistv5"


def fetch_record(cve_id: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(_API + cve_id, headers={"User-Agent": "limoza-vdb add-cve"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def affected_rows(conn, record: dict) -> list:
    """The cvelistv5 cpe-lane rows of one record (same code path as the daily extractor)."""
    from ingest.affected import cpe_norm
    from ingest.affected.sources.cvelistv5 import _file_rows
    cpe_norm.load(conn)
    return list(_file_rows(record))


def _swap_affected(conn, cve_id: str, rows: list) -> None:
    from ingest.affected import flush
    with conn.cursor() as cur:
        cur.execute("DELETE FROM affected WHERE origin = %s AND cve_id = %s", (ORIGIN, cve_id))
        flush(cur, rows)
    conn.commit()


def add_one(conn, cve_id: str, dsn: str, amap: dict, fetch=fetch_record) -> dict:
    from ingest.records.cvelistv5.ingest import _delete_scope, _import_chunk, _write_orgs
    from ingest.records.cvelistv5.transform import parse

    raw = fetch(cve_id)
    record = parse(raw)
    state = (record.get("cveMetadata") or {}).get("state")
    if state != "PUBLISHED":                       # RESERVED / REJECTED records carry no usable data
        return {"cve_id": cve_id, "state": state, "records": 0, "affected": 0}

    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / f"{cve_id}.json"
        f.write_bytes(raw)
        _delete_scope(conn, [cve_id])
        n, adp_acc, cna_uuids = _import_chunk(([str(f)], dsn, amap))
    _write_orgs(conn, adp_acc, cna_uuids)

    rows = affected_rows(conn, record)
    _swap_affected(conn, cve_id, rows)
    return {"cve_id": cve_id, "state": state, "records": n, "affected": len(rows)}


def add_many(ids: list[str], fetch=fetch_record) -> list[dict]:
    """add_one for several ids on one connection; a failing CVE is reported in its result (key `error`), never raised."""
    from ingest.core.db import get_conn
    from ingest.records.cvelistv5.ingest import _assigner_map

    dsn, conn, out = os.environ["POSTGRES_DSN"], get_conn(), []
    try:
        amap = _assigner_map(conn)
        for cid in ids:
            try:
                out.append(add_one(conn, cid, dsn, amap, fetch))
            except urllib.error.HTTPError as e:
                conn.rollback()
                out.append({"cve_id": cid, "error": f"CVE Services answered HTTP {e.code}"
                            + (" (not published yet?)" if e.code == 404 else "")})
            except Exception as e:                  # one CVE failing must not stop the others
                conn.rollback()
                out.append({"cve_id": cid, "error": f"{type(e).__name__}: {e}"})
    finally:
        conn.close()
    return out


def run(args: list[str]) -> int:
    scoring = "--scoring" in args
    ids = [normalize(a) for a in args if not a.startswith("--")]
    if not ids or None in ids:
        print(__doc__)
        return 1

    failed = 0
    for res in add_many(ids):
        if "error" in res:
            failed += 1
            print(f"  ✗ {res['cve_id']}: {res['error']}")
            continue
        note = "" if res["affected"] else "  (no CPE in the record → no affected rows; vendor/NVD data comes with the daily run)"
        print(f"  {res['cve_id']}: state={res['state']} record={res['records']} affected={res['affected']}{note}")

    if scoring:
        from ingest.run import main
        for phase in ("sync", "ingest"):
            main([phase, "kev", "ssvc", "epss"])
    return 1 if failed else 0
