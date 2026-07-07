"""Sync Node.js core security — sparse shallow clone of nodejs/security-wg.

Node.js CORE (the runtime) is not an npm package, so GHSA/OSV don't carry a
version-precise range for it and NVD often only enumerates sample versions. The
Node.js Security WG publishes the authoritative machine-readable core database at
``vuln/core/`` — one entry per advisory with the affected/patched release lines
(e.g. patched ``^22.23.0 || ^24.17.0 || ^26.3.1``). We take only ``vuln/core``;
git pull is the incremental (ingest re-reads all, delete_scope makes it idempotent).
"""
import subprocess
from pathlib import Path

_REPO   = "https://github.com/nodejs/security-wg"
_SPARSE = ["vuln/core"]


def run(dirs: dict):
    dest = Path(dirs["nodejs"])
    print("── sync nodejs ──")
    if (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "clone", "--depth=1", "--filter=blob:none", "--sparse",
                        _REPO, str(dest)], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", *_SPARSE], check=True)

    core = dest / "vuln" / "core"
    n = sum(1 for _ in core.glob("*.json")) if core.exists() else 0
    print(f"  nodejs: {n:,} core vuln files")
    return n
