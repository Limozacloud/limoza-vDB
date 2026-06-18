"""Sync Rocky Linux errata: updateinfo.xml (bulk history) + Apollo API (recent tail)."""
import gzip
import json
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# ── updateinfo.xml ────────────────────────────────────────────────────────────
_VERSIONS  = ["8", "9", "10"]
_REPOS     = ["BaseOS", "AppStream", "NFV"]
_BASE_URL  = "https://download.rockylinux.org/pub/rocky"
_ARCH      = "x86_64"
_NS        = {"r": "http://linux.duke.edu/metadata/repo"}

# ── Apollo API ────────────────────────────────────────────────────────────────
_APOLLO    = "https://apollo.build.resf.org/api/v3/advisories"
_PAGE_SIZE = 100

_HEADERS   = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)"}


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers=_HEADERS)
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def _etag(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers=_HEADERS, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.headers.get("ETag", "") or r.headers.get("Last-Modified", "")
    except Exception:
        return ""


def _updateinfo_url(version: str, repo: str) -> str | None:
    base = f"{_BASE_URL}/{version}/{repo}/{_ARCH}/os/repodata"
    try:
        data = _fetch(f"{base}/repomd.xml")
        root = ET.fromstring(data)
        for elem in root.findall("r:data", _NS):
            if elem.get("type") == "updateinfo":
                loc = elem.find("r:location", _NS)
                if loc is not None:
                    return f"{_BASE_URL}/{version}/{repo}/{_ARCH}/os/{loc.get('href', '')}"
    except Exception as e:
        print(f"  Rocky {version}/{repo}: repomd.xml failed: {e}")
    return None


def _sync_updateinfo(base: Path, checkpoint: dict) -> tuple[int, dict]:
    """Download updateinfo.xml files that have changed. Returns (count, new_ck)."""
    new_ck: dict = {}
    downloaded = 0

    for version in _VERSIONS:
        version_dir = base / version
        version_dir.mkdir(exist_ok=True)

        for repo in _REPOS:
            ui_url = _updateinfo_url(version, repo)
            if not ui_url:
                continue

            etag    = _etag(ui_url)
            ck_key  = f"{version}/{repo}"
            new_ck[ck_key] = etag

            if etag and etag == checkpoint.get(ck_key):
                continue

            dest_gz  = version_dir / f"{repo}.xml.gz"
            dest_xml = version_dir / f"{repo}.xml"
            print(f"  Rocky: downloading {version}/{repo}/updateinfo ...")
            try:
                dest_gz.write_bytes(_fetch(ui_url))
                with gzip.open(str(dest_gz), "rb") as fh:
                    dest_xml.write_bytes(fh.read())
                dest_gz.unlink(missing_ok=True)
                downloaded += 1
            except Exception as e:
                print(f"  Rocky {version}/{repo}: download failed: {e}")

    return downloaded, new_ck


def _sync_apollo(adv_dir: Path, last_synced: str) -> int:
    """Fetch recent advisories from Apollo API. Returns count of new files."""
    adv_dir.mkdir(exist_ok=True)
    downloaded = 0
    page = 1

    while True:
        url = f"{_APOLLO}/?page={page}&limit={_PAGE_SIZE}"
        if last_synced:
            url += f"&filters.publishedAfter={last_synced}"

        try:
            data = json.loads(_fetch(url))
        except Exception as e:
            print(f"  Rocky Apollo: page {page} failed: {e}")
            break

        advisories = data.get("advisories") or []
        if not advisories:
            break

        for adv in advisories:
            name = adv.get("name", "")
            if not name:
                continue
            filename = name.replace(":", "-") + ".json"
            (adv_dir / filename).write_bytes(json.dumps(adv, separators=(",", ":")).encode())
            downloaded += 1

        if len(advisories) < _PAGE_SIZE:
            break
        page += 1

    return downloaded


def sync(dirs: dict) -> None:
    base    = Path(dirs["rocky_errata"])
    adv_dir = base / "advisories"
    base.mkdir(parents=True, exist_ok=True)

    checkpoint_path = base / "checkpoint.json"
    checkpoint      = json.loads(checkpoint_path.read_bytes()) if checkpoint_path.exists() else {}
    last_synced     = checkpoint.get("apollo_synced", "")
    sync_started    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # updateinfo.xml (bulk history, mirror)
    xml_count, new_ck = _sync_updateinfo(base, checkpoint)

    # Apollo API (recent tail, always current)
    apollo_count = _sync_apollo(adv_dir, last_synced)

    new_ck["apollo_synced"] = sync_started
    checkpoint_path.write_bytes(json.dumps(new_ck, separators=(",", ":")).encode())

    total = xml_count + apollo_count
    if total:
        print(f"  Rocky: {xml_count} updateinfo + {apollo_count} Apollo advisories updated")
    else:
        print("  Rocky: no changes")
