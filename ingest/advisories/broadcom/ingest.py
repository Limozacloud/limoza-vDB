"""Ingest Broadcom (VMware) advisories → advisory + advisory_cve + cve_vendor.

Enrichment only: the affected/fixed versions come from the L4 pass
(``ingest.affected.sources.broadcom``), which reads the same advisory pages.
"""
import json
import re
from datetime import datetime
from pathlib import Path

from ingest.advisories import delete_scope, flush, new_bundle, vendor_row
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "broadcom"
BATCH = 500


def _date(text):
    """'29 September 2025' → '2025-09-29' (None when unparsable)."""
    try:
        return datetime.strptime((text or "").strip(), "%d %B %Y").date().isoformat()
    except ValueError:
        return None


def run(conn, dirs: dict) -> int:
    base = Path(dirs["broadcom"])
    idx_file = base / "index.json"
    if not idx_file.exists():
        print("  broadcom: no data — run `sync broadcom` first")
        return 0
    index = json.loads(idx_file.read_bytes())

    delete_scope(conn, ORIGIN, SOURCE)
    b, n = new_bundle(), 0
    with conn.cursor() as cur:
        for e in index.values():
            adv = (e.get("documentId") or "").strip()
            if not adv:
                continue
            cids = [c for c in (normalize(x) for x in re.split(r"[,\s]+", e.get("affectedCve") or "")) if c]
            sev = (e.get("severity") or "").strip().lower() or None
            b["advisory"].append((SOURCE, adv, e.get("notificationUrl"), e.get("title"), sev,
                                  _date(e.get("published")), _date(e.get("updated"))))
            for cid in cids:
                b["spine"].append((cid,))
                b["advisory_cve"].append((SOURCE, adv, cid))
                data = {k: v for k, v in {"severity": sev, "advisory": adv, "title": e.get("title"),
                                          "url": e.get("notificationUrl")}.items() if v}
                b["cve_vendor"].append(vendor_row(SOURCE, cid, data))
            n += 1
            if n % BATCH == 0:
                flush(cur, b)
                conn.commit()
                b = new_bundle()
        flush(cur, b)
        conn.commit()
    print(f"  broadcom: {n:,} advisories")
    return n
