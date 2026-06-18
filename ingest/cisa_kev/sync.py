import json
import os
import subprocess
from pathlib import Path

_GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def sync(dirs: dict) -> None:
    dest     = Path(dirs["cisa_kev"])
    repo_dir = dest / "repo"
    out      = dest / "kev_index.json"

    print("── sync cisa_kev ──")
    if (repo_dir / ".git").exists():
        print("  Pulling...")
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=True, env=_GIT_ENV)
    else:
        print("  Cloning (depth=1)...")
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1",
            "https://github.com/cisagov/kev-data", str(repo_dir)
        ], check=True, env=_GIT_ENV)

    kev_file = repo_dir / "known_exploited_vulnerabilities.json"
    data     = json.loads(kev_file.read_bytes())

    idx = {
        v["cveID"]: {
            "date_added":         v.get("dateAdded"),
            "due_date":           v.get("dueDate"),
            "vendor_project":     v.get("vendorProject"),
            "product":            v.get("product"),
            "vulnerability_name": v.get("vulnerabilityName"),
            "short_description":  v.get("shortDescription"),
            "required_action":    v.get("requiredAction"),
            "known_ransomware":   v.get("knownRansomwareCampaignUse"),
            "notes":              v.get("notes"),
            "cwes":               v.get("cwes") or [],
        }
        for v in data.get("vulnerabilities", [])
    }

    out.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  Done. {len(idx)} KEV entries → {out}")
