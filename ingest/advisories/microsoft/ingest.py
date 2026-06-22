"""Ingest Microsoft MSRC → cve_cvss/cve_cwe/cve_desc + cve_vendor + advisory (KBs).

origin/source='microsoft' (a CNA → source uuid on cve_*). advisory = KB articles
(KB↔CVE links); per-product KB detail = phase-3 affected.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.microsoft.transform import iter_vulns, parse

ORIGIN = "microsoft"
SOURCE = "microsoft"
BATCH  = 2_000
_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}


def _source_uuid(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT uuids[1] FROM cna WHERE lower(short_name) = %s", ("microsoft",))
        r = cur.fetchone()
        return r[0] if r and r[0] else None


def run(conn, dirs: dict) -> int:
    base = Path(dirs["microsoft"])
    files = sorted(base.glob("*.json"))
    if not files:
        print("  microsoft: no CVRF docs — run `sync microsoft` first")
        return 0
    src = _source_uuid(conn)
    print(f"  microsoft: {len(files)} CVRF docs · source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    cve_sev = {}
    seen_cvss, seen_cwe, seen_desc = set(), set(), set()
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for f in files:
            for rec in iter_vulns(parse(f.read_bytes()), src):
                cid = rec["cve_id"]
                b["spine"].append((cid,))
                for s, ver, sc, sev, vec in rec["cvss"]:
                    if (cid, vec) in seen_cvss:
                        continue
                    seen_cvss.add((cid, vec))
                    b["cvss"].append((cid, ORIGIN, s, ver, sc, sev, vec))
                for s, cw in rec["cwe"]:
                    if (cid, cw) in seen_cwe:
                        continue
                    seen_cwe.add((cid, cw))
                    b["cwe"].append((cid, ORIGIN, s, cw))
                if rec["desc"] and cid not in seen_desc:
                    seen_desc.add(cid)
                    b["desc"].append((cid, ORIGIN, src, "en", rec["desc"]))
                for kb, url in rec["kbs"].items():
                    b["advisory"].append((SOURCE, kb, url, None, None, None, None))
                    b["advisory_cve"].append((SOURCE, kb, cid))
                if rec["severity"]:
                    rk = _SRANK.get(rec["severity"].lower(), 0)
                    if rk > cve_sev.get(cid, (0, None))[0]:
                        cve_sev[cid] = (rk, rec["severity"])
                n += 1
                if n % BATCH == 0:
                    flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for cid, (_, sev) in cve_sev.items():
            vb["cve_vendor"].append((cid, SOURCE, Json({"severity": sev})))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  microsoft: {len(cve_sev):,} CVEs · cvss {len(seen_cvss):,} · cwe {len(seen_cwe):,}")
    return len(cve_sev)
