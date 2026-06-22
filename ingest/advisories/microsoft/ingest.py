"""Ingest Microsoft MSRC → cve_cvss/cve_cwe/cve_desc + cve_vendor + advisory (KBs).

origin/source='microsoft' (a CNA → source uuid on cve_*). advisory = KB articles
(KB↔CVE links); per-product KB detail = phase-3 affected.
"""
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.microsoft.transform import iter_vulns, parse, parse_document

ORIGIN = "microsoft"
SOURCE = "microsoft"
BATCH  = 2_000
_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}
_EXRANK = {"n/a": 0, "exploitation unlikely": 1, "exploitation less likely": 2,
           "exploitation more likely": 3, "exploitation detected": 4}


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

    cve_data = {}   # cid -> accumulator (severity/impact/exploit status, aggregated)
    seen_cvss, seen_cwe, seen_desc = set(), set(), set()
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for f in files:
            doc = parse(f.read_bytes())
            rel, title, pub, mod = parse_document(doc)
            if rel:
                url = f"https://msrc.microsoft.com/update-guide/releaseNote/{rel}"
                b["advisory"].append((SOURCE, rel, url, title, None, pub, mod))
            for rec in iter_vulns(doc, src):
                cid = rec["cve_id"]
                b["spine"].append((cid,))
                if rel:
                    b["advisory_cve"].append((SOURCE, rel, cid))
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
                acc = cve_data.setdefault(cid, {"_sev": 0, "_exp": -1})
                if rec["severity"]:
                    rk = _SRANK.get(rec["severity"].lower(), 0)
                    if rk > acc["_sev"]:
                        acc["_sev"], acc["severity"] = rk, rec["severity"]
                if rec["impact"] and "impact" not in acc:
                    acc["impact"] = rec["impact"]
                for k in ("exploited", "publicly_disclosed"):
                    val = rec[k]
                    if val == "Yes":
                        acc[k] = "Yes"
                    elif val and acc.get(k) != "Yes":
                        acc.setdefault(k, val)
                if rec["exploitability"]:
                    er = _EXRANK.get(rec["exploitability"].lower(), 0)
                    if er > acc["_exp"]:
                        acc["_exp"], acc["exploitability"] = er, rec["exploitability"]
                n += 1
                if n % BATCH == 0:
                    flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for cid, acc in cve_data.items():
            data = {k: v for k, v in acc.items() if not k.startswith("_")}
            if data:
                vb["cve_vendor"].append((cid, SOURCE, Json(data)))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  microsoft: {len(cve_data):,} CVEs · cvss {len(seen_cvss):,} · cwe {len(seen_cwe):,}")
    return len(cve_data)
