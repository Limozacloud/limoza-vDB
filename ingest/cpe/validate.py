"""CPE validation against the local NVD CPE dictionary.

Call load(cpe_dir) once at ingest startup. is_valid() then checks whether the
(vendor, product) pair from a CPE 2.3 URI exists in the dictionary.
Returns True unconditionally when the dictionary has not been loaded so that
imports work without CPE data present.
"""
from __future__ import annotations

from ingest import json_compat as json
from pathlib import Path
from typing import Optional

_vp: Optional[set] = None  # set of (vendor, product) tuples


def load(cpe_dir: str) -> None:
    global _vp
    if _vp is not None:
        return
    path = Path(cpe_dir) / "cpe_dict.json"
    if not path.exists():
        return
    print(f"  CPE: loading validator from {path} …")
    data: dict = json.loads(path.read_bytes())
    # entry: [uri, cpe_type, vendor, product, version, title_en, deprecated, created, modified]
    _vp = {(e[2], e[3]) for e in data.values()}
    print(f"  CPE: {len(_vp):,} (vendor, product) pairs loaded")


def is_valid(cpe: str) -> bool:
    if _vp is None:
        return True
    parts = cpe.split(":")
    if len(parts) < 5 or parts[1] != "2.3":
        return False
    return (parts[3], parts[4]) in _vp
