"""Ingest per-repository GitHub advisories → advisory + advisory_cve + the CVE spine
(cve / desc / cvss / cwe / ref, origin='github_repo'), plus the affected packages into
cve_vendor.data (projected to the affected table by the github_repo affected extractor).

For a CVE we already have (cvelistv5/ghsa/nvd) this just adds a low-priority extra source.
For a CVE that is still RESERVED / repo-only (in no other feed), this is what creates the
`cve` row so it becomes queryable at all.
"""
import json
from pathlib import Path

from psycopg2.extras import Json

from ingest.advisories import delete_scope, flush, new_bundle
from ingest.advisories.github_repo import load_config
from ingest.advisories.github_repo.transform import transform

ORIGIN = SOURCE = "github_repo"
BATCH = 500


def run(conn, dirs: dict) -> int:
    base = Path(dirs["github_repo"])
    files = sorted(base.glob("*.json")) if base.exists() else []
    if not files:
        print("  github_repo: no synced advisories — run `sync github_repo` first")
        return 0

    delete_scope(conn, ORIGIN, SOURCE)

    cpe_by_repo = {c["repo"]: c.get("cpe") for c in load_config()}
    seen_cvss, seen_cwe, seen_desc, seen_ref = set(), set(), set(), set()
    cve_pkgs = {}
    b = new_bundle()
    n = 0
    with conn.cursor() as cur:
        for f in files:
            repo = f.stem.replace("__", "/")
            try:
                advs = json.loads(f.read_bytes())
            except Exception:
                continue
            for raw in advs:
                a = transform(raw, repo, cpe_by_repo.get(repo))
                if not a:
                    continue
                cid = a["cve"]
                b["advisory"].append((SOURCE, a["id"], a["url"], a["title"],
                                      a["severity"], a["published"], a["modified"]))
                b["advisory_cve"].append((SOURCE, a["id"], cid))
                b["spine"].append((cid,))
                if a["details"] and (cid, "en") not in seen_desc:
                    seen_desc.add((cid, "en"))
                    b["desc"].append((cid, ORIGIN, SOURCE, "en", a["details"]))
                for ver, sc, sev, vec in a["cvss"]:
                    if (cid, vec) in seen_cvss:
                        continue
                    seen_cvss.add((cid, vec))
                    b["cvss"].append((cid, ORIGIN, SOURCE, ver, sc, sev, vec))
                for cw in a["cwe"]:
                    if (cid, cw) in seen_cwe:
                        continue
                    seen_cwe.add((cid, cw))
                    b["cwe"].append((cid, ORIGIN, SOURCE, cw))
                for url in a["refs"]:
                    if (cid, url) in seen_ref:
                        continue
                    seen_ref.add((cid, url))
                    b["ref"].append((cid, ORIGIN, SOURCE, url, None))
                acc = cve_pkgs.setdefault(cid, {"packages": [], "ghsa": [], "_seen": set()})
                if a["id"] not in acc["ghsa"]:
                    acc["ghsa"].append(a["id"])
                for p in a["packages"]:
                    key = (p["purl"], p["ranges"])
                    if key not in acc["_seen"]:
                        acc["_seen"].add(key)
                        acc["packages"].append(p)
                n += 1
                if n % BATCH == 0:
                    flush(cur, b); conn.commit(); b = new_bundle()
        flush(cur, b); conn.commit()

        vb = new_bundle()
        for cid, acc in cve_pkgs.items():
            vb["cve_vendor"].append((cid, SOURCE, Json({"packages": acc["packages"], "ghsa": acc["ghsa"]})))
            if len(vb["cve_vendor"]) >= BATCH:
                flush(cur, vb); conn.commit(); vb = new_bundle()
        flush(cur, vb); conn.commit()

    print(f"  github_repo: {n:,} advisories · {len(cve_pkgs):,} CVEs")
    return n
