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

        sev, rank = None, 0
        for t in v.get("Threats") or []:
            if t.get("Type") == 3:
                val = (t.get("Description") or {}).get("Value")
                rk = _SRANK.get((val or "").lower(), 0)
                if rk > rank:
                    rank, sev = rk, val

        kbs = {}
        for r in v.get("Remediations") or []:
            if r.get("Type") == 2:
                num = ((r.get("Description") or {}).get("Value") or "").strip()
                if num.isdigit():
                    kbs["KB" + num] = r.get("URL") or f"https://support.microsoft.com/help/{num}"

        yield {"cve_id": cid, "cvss": cvss, "cwe": cwe, "desc": desc,
               "severity": sev, "kbs": kbs}
