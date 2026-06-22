"""Ingest Oracle Linux OVAL → advisory/advisory_cve + cve_cvss + cve_vendor (origin/source='oracle').

Streams the 200+ MB XML with iterparse. Per ELSA: advisory + CVE links + per-CVE
CVSS (score + vector from the cvss3 attribute). cve_vendor severity = the highest
ELSA severity seen for each CVE. Per-package fix tests = phase-3 affected.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.oracle.transform import lt, parse_definition
from ingest.core.cvss import severity_from_score

ORIGIN = "oracle"
SOURCE = "oracle"
BATCH  = 2_000
_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}


def _source_uuid(conn):
    with conn.cursor() as cur:
        cur.execute("SELECT uuids[1] FROM cna WHERE lower(short_name) = %s", ("oracle",))
        r = cur.fetchone()
        return r[0] if r and r[0] else None


def run(conn, dirs: dict) -> int:
    f = Path(dirs["oracle"]) / "oval.xml"
    if not f.exists():
        print("  oracle: oval.xml not found — run `sync oracle` first")
        return 0
    src = _source_uuid(conn)
    print(f"  oracle: source uuid = {src}")

    delete_scope(conn, ORIGIN, SOURCE)

    b = new_bundle()
    n = 0
    cve_sev = {}                 # cve_id -> (rank, severity)
    seen_cvss = set()            # (cve_id, vector)
    with conn.cursor() as cur:
        for _, elem in ET.iterparse(str(f), events=("end",)):
            if lt(elem) != "definition":
                continue
            d = parse_definition(elem)
            elem.clear()
            if not d or not d["cves"]:
                continue
            eid, sev = d["elsa_id"], d["severity"]
            if eid:
                url = f"https://linux.oracle.com/errata/{eid}.html"
                b["advisory"].append((SOURCE, eid, url, d["title"], sev, d["issued"], None))
            for cid, cvss3 in d["cves"]:
                b["spine"].append((cid,))
                if eid:
                    b["advisory_cve"].append((SOURCE, eid, cid))
                if cvss3 and "/" in cvss3:
                    score_s, vec = cvss3.split("/", 1)
                    try:
                        score = float(score_s)
                    except ValueError:
                        score = None
                    if score is not None and vec.startswith("CVSS:") and (cid, vec) not in seen_cvss:
                        seen_cvss.add((cid, vec))
                        ver = vec.split("/", 1)[0].split(":", 1)[1]
                        b["cvss"].append((cid, ORIGIN, src, ver, score,
                                          severity_from_score(score, ver), vec))
                if sev:
                    rk = _SRANK.get(sev.lower(), 0)
                    if rk > cve_sev.get(cid, (0, None))[0]:
                        cve_sev[cid] = (rk, sev)
            n += 1
            if n % BATCH == 0:
                flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        # cve_vendor: one row per CVE with its highest ELSA severity
        vb = new_bundle()
        for cid, (_, sev) in cve_sev.items():
            vb["cve_vendor"].append((cid, SOURCE, Json({"severity": sev})))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  oracle: {n:,} ELSAs · {len(cve_sev):,} CVEs · {len(seen_cvss):,} cvss")
    return n
