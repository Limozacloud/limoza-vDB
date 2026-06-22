"""Sync AlmaLinux errata — one errata.full.json per major release."""
import urllib.error
import urllib.request
from pathlib import Path

_BASE    = "https://errata.almalinux.org"
_MAJORS  = ["8", "9", "10"]
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def run(dirs: dict):
    dest = Path(dirs["almalinux"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync almalinux ──")
    total = 0
    for m in _MAJORS:
        try:
            req = urllib.request.Request(f"{_BASE}/{m}/errata.full.json", headers=_HEADERS)
            data = urllib.request.urlopen(req, timeout=300).read()
            (dest / f"{m}.json").write_bytes(data)
            total += len(data)
            print(f"  AL{m}: {len(data) // 1024 // 1024} MB")
        except urllib.error.HTTPError as e:
            print(f"  AL{m}: skip ({e.code})")
        except Exception as e:
            print(f"  AL{m}: skip ({e})")
    return total
