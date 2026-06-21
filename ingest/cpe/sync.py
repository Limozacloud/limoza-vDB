"""Download the NVD CPE Dictionary 2.0 feed and build cpe_dict.json.

Uses the bulk feed (one ~76 MB zip, split into chunk JSONs) instead of paginating
the API — far faster and not subject to the API's flaky 403/503 rate limiting.

  feed: https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip
  meta: https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta

Incremental: this is a full-dataset feed, so per-record diffing gains nothing.
Instead we GATE the whole run on the .meta lastModifiedDate — if it is unchanged
since the last sync, skip the download entirely (v1 "gate" strategy).
"""
import io
import json
import zipfile
from pathlib import Path

import httpx

from ingest.incremental import Gate
from ingest.retry import http_get

_FEED = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.zip"
_META = "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.meta"
# NVD serves the feeds only to browser-like clients.
_UA   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"


def _read_meta() -> dict:
    try:
        text = httpx.get(_META, headers={"User-Agent": _UA}, timeout=30, follow_redirects=True).text
        return dict(line.split(":", 1) for line in text.splitlines() if ":" in line)
    except Exception:
        return {}


def _index_into(products: list, idx: dict) -> None:
    for item in products:
        obj = item.get("cpe", {})
        name_id = obj.get("cpeNameId")
        uri = obj.get("cpeName", "")
        parts = uri.split(":")
        if not name_id or not uri or len(parts) < 6 or parts[1] != "2.3" or not parts[3]:
            continue
        title_en = next((t["title"] for t in obj.get("titles", []) if t.get("lang") == "en"), None)
        idx[name_id] = [
            uri, parts[2], parts[3], parts[4], parts[5], title_en,
            obj.get("deprecated", False), obj.get("created"), obj.get("lastModified"),
        ]


def run(dirs: dict):
    dest = Path(dirs["cpe"])
    dest.mkdir(parents=True, exist_ok=True)
    dict_path = dest / "cpe_dict.json"
    gate      = Gate(dest / ".sync_state.json")

    print("── sync cpe ──")

    # Full-dataset feed → gate the whole run on the .meta lastModifiedDate.
    marker = _read_meta().get("lastModifiedDate", "").strip()
    if gate.unchanged(marker) and dict_path.exists():
        print(f"  unchanged since {marker} — skipping (gate)")
        return {"status": "no_new_data", "message": f"unchanged since {marker} (gate)"}

    print(f"  downloading {_FEED} ...")
    blob = http_get(_FEED, headers={"User-Agent": _UA}, timeout=300).content
    print(f"  downloaded {len(blob) / 1e6:.1f} MB")

    # The feed zip splits products across several chunk JSONs — merge them all.
    idx, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        names = sorted(n for n in zf.namelist() if n.endswith(".json"))
        for n in names:
            products = json.loads(zf.read(n)).get("products", [])
            total += len(products)
            _index_into(products, idx)
    print(f"  parsed {total:,} products from {len(names)} chunk(s)")

    dict_path.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    gate.commit(marker)
    print(f"  indexed {len(idx):,} CPEs → {dict_path}")
    return len(idx)
