"""Sync Broadcom (VMware) security advisories from the Broadcom support portal.

The portal lists advisories per segment as JSON (POST getSecurityAdvisoryList, no login) and serves
every advisory as an HTML page whose "Response Matrix" table carries the affected product versions and
the fixed version. Segments: VC (VMware Cloud Foundation family, incl. VMware Tools and Workstation),
VA (VMware Avi).

First run: all pages. Subsequent: an advisory is fetched again when its ``updated`` stamp changed or its
page is missing; an advisory whose download failed is not recorded and is asked for again next run.
Layout: <dir>/index.json (notificationId → list entry) and <dir>/advisories/<notificationId>.html
"""
import json
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_LIST = "https://support.broadcom.com/web/ecx/security-advisory/-/securityadvisory/getSecurityAdvisoryList"
_SEGMENTS = ("VC", "VA")
_PAGE_SIZE = 100
_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; limoza-ingest/1.0)", "Accept": "*/*"}
_RETRIES, _WAIT = 3, 5


def _request(req: urllib.request.Request) -> bytes:
    for attempt in range(_RETRIES):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except Exception:
            if attempt == _RETRIES - 1:
                raise
            time.sleep(_WAIT * (attempt + 1))


def _list_page(segment: str, page: int) -> dict:
    body = json.dumps({"pageNumber": page, "pageSize": _PAGE_SIZE, "searchVal": "", "segment": segment,
                       "sortInfo": {"column": "", "order": ""}}).encode()
    req = urllib.request.Request(_LIST, body, {**_HEADERS, "Content-Type": "application/json"})
    return json.loads(_request(req))["data"]


def list_all(segment: str) -> list:
    out, page = [], 0
    while True:
        data = _list_page(segment, page)
        out.extend(data.get("list") or [])
        info = data.get("pageInfo") or {}
        if page >= int(info.get("lastPage") or 0) or not data.get("list"):
            return out
        page += 1


def _fetch_page(entry: dict) -> bytes:
    page = _request(urllib.request.Request(entry["notificationUrl"], headers=_HEADERS))
    if len(page) < 1000:                                  # an error stub, not an advisory page
        raise ValueError(f"short response ({len(page)} bytes)")
    return page


def run(dirs: dict):
    base = Path(dirs["broadcom"])
    (base / "advisories").mkdir(parents=True, exist_ok=True)
    idx_file = base / "index.json"
    index = json.loads(idx_file.read_bytes()) if idx_file.exists() else {}

    print("── sync broadcom (VMware advisories) ──")
    entries = {}
    for seg in _SEGMENTS:
        for e in list_all(seg):
            if e.get("notificationId") and e.get("notificationUrl"):
                entries[str(e["notificationId"])] = e
    todo = [(k, e) for k, e in entries.items()
            if index.get(k, {}).get("updated") != e.get("updated") or not (base / "advisories" / f"{k}.html").exists()]
    print(f"  broadcom: {len(entries)} advisories listed, {len(todo)} to fetch")

    def _one(item):
        k, e = item
        try:
            (base / "advisories" / f"{k}.html").write_bytes(_fetch_page(e))
            return k, e, None
        except Exception as ex:
            return k, e, f"{e.get('documentId')}: {ex}"

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_one, todo))
    failed = [r[2] for r in results if r[2]]
    refetched = {r[0] for r in results}
    for k, e in entries.items():
        if k not in refetched and k in index:             # unchanged: keep the list metadata current
            index[k] = e
    for k, e, err in results:
        if not err:                                       # a failed download stays unrecorded → retried next run
            index[k] = e
    idx_file.write_text(json.dumps(index, ensure_ascii=False))
    if failed:
        print(f"  WARNING: {len(failed)}/{len(todo)} downloads failed, e.g. {failed[:3]}; retried next run")
    fetched = len(todo) - len(failed)
    if not fetched:
        return {"status": "no_new_data", "message": "no changed Broadcom advisories"}
    print(f"  fetched {fetched} advisories")
    return fetched
