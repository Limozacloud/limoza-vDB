"""github_repo source — shared config loader.

config/github_repos.json entries are either a plain "owner/repo" string or an object
{"repo": "owner/repo", "cpe": "cpe:2.3:a:vendor:product"}. The optional CPE lets the
affected layer emit a coord='cpe' row so a scanner that reports the app by CPE (the usual
case for non-ecosystem software) actually matches — the synthetic pkg:github purl alone
never does. Give the CPE in canonical CPE 2.3 form (special chars escaped, e.g. notepad\\+\\+).
An entry may also set "branch_floors": true when the project versions each fix per release
branch (php-src: '<8.4.24' means 8.4.x before 8.4.24, not every older release) — see
_branch_floors in the github_repo affected extractor.
"""
import json
from pathlib import Path

_CONF = Path(__file__).resolve().parents[3] / "config" / "github_repos.json"


def load_config() -> list[dict]:
    """→ [{'repo': str, 'cpe': str|None, 'branch_floors': bool}, …]."""
    if not _CONF.exists():
        return []
    out = []
    for e in json.loads(_CONF.read_text()).get("repos") or []:
        if isinstance(e, str):
            out.append({"repo": e, "cpe": None, "branch_floors": False})
        elif isinstance(e, dict) and e.get("repo"):
            out.append({"repo": e["repo"], "cpe": e.get("cpe"),
                        "branch_floors": bool(e.get("branch_floors"))})
    return out
