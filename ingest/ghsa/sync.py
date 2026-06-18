import subprocess
from pathlib import Path


def sync(dirs: dict) -> None:
    dest = Path(dirs["ghsa"])

    print("── sync ghsa ──")
    if (dest / ".git").exists():
        print("  Pulling...")
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        print("  Cloning github/advisory-database (may take several minutes)...")
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1",
            "https://github.com/github/advisory-database", str(dest),
        ], check=True)

    reviewed   = sum(1 for _ in (dest / "advisories" / "github-reviewed").rglob("GHSA-*.json"))
    unreviewed = sum(1 for _ in (dest / "advisories" / "unreviewed").rglob("GHSA-*.json"))
    print(f"  Done. {reviewed} reviewed · {unreviewed} unreviewed advisories")
