"""Fetch CISA SSVC decisions (cisagov/vulnrichment) and build a compact index.

The repo holds one CVE-*.json per CVE; we extract the CISA-ADP SSVC options into
ssvc_index.json ({cve: {exploitation, automatable, technical_impact}}).
"""
import json
from pathlib import Path

from ingest.core.gitsync import clone_or_pull, head
from ingest.core.incremental import Gate

_REPO = "https://github.com/cisagov/vulnrichment"


def run(dirs: dict):
    dest = Path(dirs["ssvc"])
    dest.mkdir(parents=True, exist_ok=True)
    repo  = dest / "repo"
    index = dest / "ssvc_index.json"
    gate  = Gate(dest / ".sync_state.json")

    print("── sync ssvc ──")
    clone_or_pull(_REPO, repo, branch="develop")

    # Gate the expensive 156k-file index scan on the post-pull HEAD.
    marker = head(repo)
    if gate.unchanged(marker) and index.exists():
        print(f"  unchanged ({marker[:8]}) — skipping index rebuild (gate)")
        return {"status": "no_new_data", "message": f"unchanged ({marker[:8]}) (gate)"}

    print("  building index...")
    idx: dict = {}
    for f in repo.rglob("CVE-*.json"):
        try:
            data = json.loads(f.read_bytes())
        except Exception:
            continue
        adp = next((c for c in (data.get("containers", {}).get("adp") or [])
                    if (c.get("providerMetadata") or {}).get("shortName") == "CISA-ADP"), None)
        if not adp:
            continue
        cve_id = (data.get("cveMetadata") or {}).get("cveId", "")
        if not cve_id:
            continue
        entry: dict = {}
        for m in (adp.get("metrics") or []):
            other = m.get("other") or {}
            if other.get("type") != "ssvc":
                continue
            for opt in ((other.get("content") or {}).get("options") or []):
                if "Exploitation"     in opt: entry["exploitation"]     = opt["Exploitation"]
                if "Automatable"      in opt: entry["automatable"]      = opt["Automatable"]
                if "Technical Impact" in opt: entry["technical_impact"] = opt["Technical Impact"]
        if entry:
            idx[cve_id] = entry

    index.write_text(json.dumps(idx, separators=(",", ":")))
    gate.commit(marker)
    print(f"  done: {len(idx):,} CVEs → {index}")
    return len(idx)
