"""Sync Microsoft MSRC CVRF v3.0 — one JSON document per monthly release.

Incremental by presence: existing release files are kept; the two most recent are
always re-fetched (they get revised after Patch Tuesday).
"""
import json
import urllib.request
from pathlib import Path

_BASE    = "https://api.msrc.microsoft.com/cvrf/v3.0"
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "application/json"}
# .NET release metadata: MSRC lists some .NET fixes as SDK versions; the affected extractor maps
# them to the runtime version a host reports (see sources/microsoft.py).
_DOTNET_INDEX = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json"


def _get(url, timeout):
    return urllib.request.urlopen(urllib.request.Request(url, headers=_HEADERS), timeout=timeout).read()


def run(dirs: dict):
    dest = Path(dirs["microsoft"])
    dest.mkdir(parents=True, exist_ok=True)
    print("── sync microsoft (MSRC CVRF v3.0) ──")
    up = json.loads(_get(f"{_BASE}/updates", 60))
    releases = [v["ID"] for v in (up.get("value") or []) if v.get("ID")]
    # newest two by date → always refresh
    by_date = sorted((up.get("value") or []), key=lambda v: v.get("CurrentReleaseDate") or "", reverse=True)
    refresh = {v["ID"] for v in by_date[:2]}

    fetched = 0
    for rel in releases:
        fp = dest / f"{rel}.json"
        if fp.exists() and rel not in refresh:
            continue
        try:
            fp.write_bytes(_get(f"{_BASE}/cvrf/{rel}", 180))
            fetched += 1
        except Exception as e:
            print(f"  {rel}: skip ({e})")
    print(f"  microsoft: {len(releases)} releases · {fetched} fetched")
    _sync_dotnet(dest / "dotnet")
    return fetched


def _sync_dotnet(dest: Path):
    """Refresh the per-channel .NET releases.json (.NET 5+); keep old files on failure."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        channels = json.loads(_get(_DOTNET_INDEX, 60)).get("releases-index") or []
    except Exception as e:
        print(f"  dotnet release metadata: skip ({e})")
        return
    for ch in channels:
        ver, url = str(ch.get("channel-version") or ""), ch.get("releases.json")
        if not url or not ver.split(".")[0].isdigit() or int(ver.split(".")[0]) < 5:
            continue
        try:
            (dest / f"{ver}.json").write_bytes(_get(url, 180))
        except Exception as e:
            print(f"  dotnet {ver}: skip ({e})")
