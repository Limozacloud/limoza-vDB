import json
from pathlib import Path

import httpx

_URL     = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
_HEADERS = {"User-Agent": "Mozilla/5.0 CVE-Pipeline/1.0"}


def sync(dirs: dict) -> None:
    dest = Path(dirs["nuclei"])
    dest.mkdir(parents=True, exist_ok=True)
    out  = dest / "nuclei_index.json"

    print("── sync nuclei ──")
    print("  Downloading cves.json...")
    r = httpx.get(_URL, timeout=120, follow_redirects=True, headers=_HEADERS)
    r.raise_for_status()

    idx: dict[str, list] = {}
    for line in r.text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj    = json.loads(line)
            cve_id = obj.get("ID", "")
            if not cve_id.startswith("CVE-"):
                continue
            info = obj.get("Info") or {}
            cls_ = info.get("Classification") or {}
            fp   = obj.get("file_path", "")
            idx.setdefault(cve_id, []).append({
                "id":          cve_id,
                "kind":        "nuclei",
                "name":        info.get("Name", ""),
                "severity":    info.get("Severity", ""),
                "description": info.get("Description", ""),
                "cvss":        cls_.get("cvss-score"),
                "file_path":   fp,
                "url":         f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{fp}",
            })
        except Exception:
            pass

    out.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  Done. {len(idx)} CVEs with Nuclei templates → {out}")
