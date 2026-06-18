import subprocess
from pathlib import Path


def sync(dirs: dict) -> None:
    dest = Path(dirs["poc_github"])
    print("── sync poc_github ──")
    if (dest / ".git").exists():
        print("  Pulling PoC-in-GitHub...")
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"], check=True)
    else:
        print("  Cloning PoC-in-GitHub...")
        dest.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            "git", "clone", "--depth=1",
            "https://github.com/nomi-sec/PoC-in-GitHub", str(dest)
        ], check=True)
    print("  Done.")
