from ingest import json_compat as json
import re
import subprocess
from pathlib import Path


def sync(dirs: dict) -> None:
    dest     = Path(dirs["metasploit"])
    repo_dir = dest / "repo"
    index    = dest / "metasploit_index.json"

    print("── sync metasploit ──")
    if (repo_dir / ".git").exists():
        print("  Pulling metasploit-framework (modules only)...")
        subprocess.run(["git", "-C", str(repo_dir), "pull", "--ff-only", "--no-recurse-submodules"], check=True)
    else:
        print("  Cloning metasploit-framework (sparse, modules only)...")
        repo_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
            "https://github.com/rapid7/metasploit-framework.git", str(repo_dir)
        ], check=True)
        subprocess.run(["git", "sparse-checkout", "set", "modules/"], cwd=str(repo_dir), check=True)

    print("  Building CVE → module index...")
    cve_re  = re.compile(r"\[\s*'CVE'\s*,\s*'(\d{4}-\d+)'\s*\]")
    rank_re = re.compile(r"Rank\s*=\s*(\w+Ranking)", re.IGNORECASE)
    name_re = re.compile(r"['\"](Name)['\"]?\s*=>\s*['\"](.+?)['\"]")
    idx: dict[str, list] = {}

    for rb in (repo_dir / "modules").rglob("*.rb"):
        try:
            src   = rb.read_text(errors="replace")
            cves  = [f"CVE-{m}" for m in cve_re.findall(src)]
            if not cves:
                continue
            rel   = rb.relative_to(repo_dir / "modules")
            mtype = rel.parts[0] if rel.parts else "unknown"
            mpath = str(rel.with_suffix(""))
            rank  = (rank_re.search(src) or [None, ""])[1].replace("Ranking", "").lower()
            nm    = name_re.search(src)
            name  = nm.group(2) if nm else rb.stem
            for cve_id in cves:
                idx.setdefault(cve_id, []).append({
                    "module": mpath,
                    "name":   name,
                    "rank":   rank,
                    "type":   mtype,
                })
        except Exception:
            pass

    index.write_bytes(json.dumps(idx, separators=(",", ":")).encode())
    total = sum(len(v) for v in idx.values())
    print(f"  Done. {len(idx)} CVEs · {total} module entries → {index}")
