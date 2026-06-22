"""Parse Microsoft MSRC CVRF v3.0 documents (monthly).

Per CVE: CVSS (score+vector), CWE list, description (Notes Type 2), severity
(Threats Type 3), and the KB fixes (Remediations Type 2) → KB advisories.
KB↔product detail (which KB per Windows version) is phase-3 affected.
"""
import json
import re

from ingest.core.cveid import normalize
from ingest.core.cvss import severity_from_score

_SRANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}
_TAG = re.compile(r"<[^>]+>")


def parse(raw: bytes):
    return json.loads(raw)


def _clean(v):
    return re.sub(r"[ \t]+", " ", _TAG.sub(" ", v or "")).strip()


def iter_vulns(doc: dict, source):
    for v in doc.get("Vulnerability") or []:
        cid = normalize(v.get("CVE") or "")
        if not cid:
            continue

        cvss, seen = [], set()
        for s in v.get("CVSSScoreSets") or []:
            vec, score = s.get("Vector"), s.get("BaseScore")
            if vec and vec.startswith("CVSS") and score is not None and vec not in seen:
                seen.add(vec)
                ver = vec.split("/", 1)[0].split(":", 1)[1]
                cvss.append((source, ver, float(score), severity_from_score(score, ver), vec))

        cwe = [(source, c["ID"]) for c in (v.get("CWE") or [])
               if isinstance(c, dict) and str(c.get("ID", "")).startswith("CWE-")]

        desc = None
        for nt in v.get("Notes") or []:
            if nt.get("Type") == 2:
                t = _clean(nt.get("Value"))
                if t:
                    desc = t
                    break

        sev, rank, impact = None, 0, None
        exploited = disclosed = exploitability = None
        for t in v.get("Threats") or []:
            tp = t.get("Type")
            val = (t.get("Description") or {}).get("Value")
            if tp == 3:                                  # severity (max)
                rk = _SRANK.get((val or "").lower(), 0)
                if rk > rank:
                    rank, sev = rk, val
            elif tp == 0 and val and not impact:         # impact type (STRIDE-like)
                impact = val
            elif tp == 1 and val:                        # exploit status string
                d = {}
                for p in val.split(";"):
                    if ":" in p:
                        k, x = p.split(":", 1)
                        d[k.strip()] = x.strip()
                disclosed = disclosed or d.get("Publicly Disclosed")
                exploited = exploited or d.get("Exploited")
                exploitability = exploitability or d.get("Latest Software Release")

        yield {"cve_id": cid, "cvss": cvss, "cwe": cwe, "desc": desc,
               "severity": sev, "impact": impact, "exploited": exploited,
               "publicly_disclosed": disclosed, "exploitability": exploitability}


def parse_document(doc: dict):
    """Document-level advisory = the monthly release (Patch Tuesday).
    Returns (release_id, title, published, modified). KB→product fixes = phase 3."""
    tr = doc.get("DocumentTracking") or {}
    rel = ((tr.get("Identification") or {}).get("ID") or {}).get("Value")
    title = (doc.get("DocumentTitle") or {}).get("Value")
    return (rel, title, tr.get("InitialReleaseDate"), tr.get("CurrentReleaseDate"))
