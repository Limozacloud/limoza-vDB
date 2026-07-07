"""Node.js core security (nodejs/security-wg) → affected (coord=cpe).

The authoritative version-precise source for the Node.js RUNTIME — which GHSA/OSV
don't carry (node core is not an npm package) and NVD often only enumerates as
sample versions. Each core-vuln entry lists the fix PER RELEASE LINE in ``patched``:

    "patched": "^22.23.0 || ^24.17.0 || ^26.3.1"

Each token ``^X.Y.Z`` means "the X.x line is affected below X.Y.Z, fixed in X.Y.Z".
We emit one cpe-range row per line → introduced ``X.0.0``, fixed ``X.Y.Z`` against the
NVD-validated ``cpe:2.3:a:nodejs:node.js`` product. This is what closes e.g. node
24.15.0 (< 24.17.0) that NVD's exact-version enumeration misses. The rows coexist
with NVD's (same cpe23, source='nvd') — the matcher ORs both lanes.
"""
import json
import re
from pathlib import Path

from ingest.affected import cpe_norm, row
from ingest.affected import status as st
from ingest.core.cveid import normalize

ORIGIN = SOURCE = "nodejs"
_VER = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _lines(patched: str):
    """'^22.23.0 || ^24.17.0' → [('22.0.0','22.23.0'), ('24.0.0','24.17.0')].
    Each ||-token is one release line: introduced = <major>.0.0, fixed = the patch version."""
    out = []
    for tok in (patched or "").split("||"):
        m = _VER.search(tok)
        if m:
            out.append((f"{m.group(1)}.0.0", m.group(0)))
    return out


def _entries(base: Path):
    idx = base / "vuln" / "core" / "index.json"
    if not idx.exists():
        return
    d = json.loads(idx.read_bytes())
    yield from (d.values() if isinstance(d, dict) else d)


def extract(conn, dirs):
    cpe_norm.load(conn)
    cpe = cpe_norm.canonical("cpe:2.3:a:nodejs:node.js:0:*:*:*:*:*:*:*")[0]
    if not cpe:                                   # product not in the NVD dict → cannot validate
        return
    pkg = cpe.split(":")[4]
    base = Path(dirs["nodejs"])
    seen = set()
    for e in _entries(base):
        cids = [normalize(c) for c in (e.get("cve") or []) if normalize(c)]
        if not cids:
            continue
        lines = _lines(e.get("patched", ""))
        for cid in cids:
            for intro, fixed in lines:
                key = (cid, intro, fixed)
                if key in seen:
                    continue
                seen.add(key)
                yield row(cve_id=cid, coord="cpe", cpe23=cpe, package=pkg,
                          introduced=intro, fixed=fixed, version_scheme="generic",
                          status=st.FIXED, source=SOURCE, status_source="own", origin=ORIGIN)
