import json
import subprocess
from pathlib import Path


def sync(dirs: dict) -> None:
    dest     = Path(dirs["cisa_ssvc"])
    repo_dir = dest / "repo"
    index    = dest / "ssvc_index.json"

    print("── sync cisa_ssvc ──")
    if (repo_dir / ".git").exists():
        print("  Pulling...")
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only"], check=True)
    else:
        print("  Cloning (depth=1)...")
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1", "--branch=develop",
            "https://github.com/cisagov/vulnrichment", str(repo_dir)
        ], check=True)

    print("  Building SSVC index...")
    idx: dict = {}
    for f in repo_dir.rglob("CVE-*.json"):
        try:
            data = json.loads(f.read_bytes())
            adp  = next((c for c in (data.get("containers", {}).get("adp") or [])
                         if (c.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"), None)
            if not adp:
                continue
            cve_id = (data.get("cveMetadata") or {}).get("cveId", "")
            if not cve_id:
                continue
            entry: dict = {}
            for m in (adp.get("metrics") or []):
                other   = m.get("other") or {}
                content = other.get("content") or {}
                if other.get("type") == "ssvc":
                    for opt in (content.get("options") or []):
                        if "Exploitation"     in opt: entry["ssvc_exploitation"]     = opt["Exploitation"]
                        if "Automatable"      in opt: entry["ssvc_automatable"]      = opt["Automatable"]
                        if "Technical Impact" in opt: entry["ssvc_technical_impact"] = opt["Technical Impact"]
                    entry["ssvc_timestamp"] = content.get("timestamp", "")
            if entry:
                idx[cve_id] = entry
        except Exception:
            pass

    index.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    print(f"  Done. {len(idx)} CVEs indexed → {index}")
