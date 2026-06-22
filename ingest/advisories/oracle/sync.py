"""Sync Oracle Linux OVAL — one big bz2-compressed XML (all ELSA errata)."""
import bz2
import urllib.request
from pathlib import Path

_URL     = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def run(dirs: dict):
    dest = Path(dirs["oracle"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync oracle ──")
    req = urllib.request.Request(_URL, headers=_HEADERS)
    raw = bz2.decompress(urllib.request.urlopen(req, timeout=600).read())
    (dest / "oval.xml").write_bytes(raw)
    print(f"  oracle: {len(raw) // 1024 // 1024} MB XML")
    return len(raw)
