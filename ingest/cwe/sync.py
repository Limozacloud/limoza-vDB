"""Sync CWE weakness definitions from CWE-CAPEC/REST-API-wg (json_repo/W only)."""
from pathlib import Path

from ingest.gitsync import clone_or_pull

_REPO   = "https://github.com/CWE-CAPEC/REST-API-wg"
_SPARSE = ["json_repo/W"]


def run(dirs: dict) -> int:
    dest = Path(dirs["cwe"])
    print("── sync cwe ──")
    clone_or_pull(_REPO, dest, sparse=_SPARSE)

    w = dest / "json_repo" / "W"
    count = sum(1 for _ in w.glob("*.json")) if w.exists() else 0
    print(f"  done: {count:,} weakness definitions → {w}")
    return count
