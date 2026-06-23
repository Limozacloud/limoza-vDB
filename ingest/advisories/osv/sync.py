"""Sync OSV native ecosystem advisory DBs (NOT GHSA, NOT distros, NOT malware).

We pull the per-ecosystem all.zip for the ecosystems that have their OWN advisory
DB beyond GHSA, and the ingest keeps only those native ids:
  PyPI→PYSEC · Go→GO · crates.io→RUSTSEC · Hex→EEF · Packagist→DRUPAL
GHSA we already have (own repo); distros we have natively; MAL (malware) is skipped.
"""
import urllib.request
from pathlib import Path

_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
_ECOSYSTEMS = ["PyPI", "Go", "crates.io", "Hex", "Packagist"]


def run(dirs: dict):
    dest = Path(dirs["osv"]); dest.mkdir(parents=True, exist_ok=True)
    print("── sync osv (native ecosystem DBs) ──")
    n = 0
    for eco in _ECOSYSTEMS:
        url = f"{_BASE}/{eco}/all.zip"
        data = urllib.request.urlopen(
            urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=180).read()
        (dest / f"{eco}.zip").write_bytes(data)
        print(f"  {eco}: ok")
        n += 1
    print(f"  osv: {n} ecosystem exports")
    return n
