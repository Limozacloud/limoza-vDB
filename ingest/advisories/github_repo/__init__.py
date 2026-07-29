"""github_repo source — shared config loader.

config/github_repos.json entries are either a plain "owner/repo" string or an object
{"repo": "owner/repo", "cpe": "cpe:2.3:a:vendor:product"}. The optional CPE lets the
affected layer emit a coord='cpe' row so a scanner that reports the app by CPE (the usual
case for non-ecosystem software) actually matches — the synthetic pkg:github purl alone
never does. Give the CPE in canonical CPE 2.3 form (special chars escaped, e.g. notepad\\+\\+).
"""
import json
from pathlib import Path

_CONF = Path(__file__).resolve().parents[3] / "config" / "github_repos.json"


def load_config() -> list[dict]:
    """→ [{'repo': str, 'cpe': str|None}, …]."""
    if not _CONF.exists():
        return []
    out = []
    for e in json.loads(_CONF.read_text()).get("repos") or []:
        if isinstance(e, str):
            out.append({"repo": e, "cpe": None})
        elif isinstance(e, dict) and e.get("repo"):
            out.append({"repo": e["repo"], "cpe": e.get("cpe")})
    return out
