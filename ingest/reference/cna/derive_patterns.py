"""Derive cna.advisory_patterns (L2 upstream-advisory match/construct).

For each CNA, scan the references on the CVEs it assigned (origin='cvelistv5') and
pick the dominant non-aggregator host as the advisory pattern. If the CVE id appears
in the URL, also emit a {CVE}/{cve} template (construct fallback when no ref exists).

  advisory_patterns = [{"pattern": "<host>", "template": "<url with {CVE}>" | null}]

Runs AFTER cvelistv5 (needs cve_ref). A manual override file
(cna_advisory_patterns.json) is merged on top, keyed by cna_id, replacing the
derived list for that CNA.
"""
import collections
import json
from pathlib import Path
from urllib.parse import urlsplit

from psycopg2.extras import Json

_OVERRIDE = Path(__file__).parent / "cna_advisory_patterns.json"

# hosts that are aggregators / trackers / distros — never an upstream's own advisory
_SKIP = (
    "nvd.nist.gov", "cve.org", "cve.mitre.org", "exchange.xforce.ibmcloud.com",
    "vuldb.com", "cisa.gov", "securityfocus.com", "packetstormsecurity",
    "twitter.com", "x.com", "youtube.com", "github.com", "gitlab.com",
    "seclists.org", "openwall.com", "marc.info", "bugzilla.",
    "access.redhat.com", "rhn.redhat.com", "lists.", "security-tracker.debian.org",
    "ubuntu.com", "suse.com", "opensuse.org", "gentoo.org", "fedoraproject",
)
_MIN = 2   # host must back at least this many of the CNA's CVEs


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def run(conn) -> int:
    with conn.cursor() as cur:
        cur.execute("""
            SELECT rec.assigner, rec.cve_id, r.url
            FROM cve_ref r JOIN cve_record rec ON rec.cve_id = r.cve_id
            WHERE rec.assigner LIKE 'CNA%' AND r.origin = 'cvelistv5' AND r.url LIKE 'http%'
        """)
        hosts = collections.defaultdict(collections.Counter)   # cna -> host -> #cves
        tmpl  = collections.defaultdict(dict)                  # cna -> host -> template
        for asg, cve, url in cur:
            h = _host(url)
            if not h or any(s in h for s in _SKIP):
                continue
            hosts[asg][h] += 1
            if cve in url:
                tmpl[asg].setdefault(h, url.replace(cve, "{CVE}"))
            elif cve.lower() in url:
                tmpl[asg].setdefault(h, url.replace(cve.lower(), "{cve}"))

        derived = {}
        for asg, c in hosts.items():
            h, n = c.most_common(1)[0]
            if n >= _MIN:
                derived[asg] = [{"pattern": h, "template": tmpl[asg].get(h)}]

        override = json.loads(_OVERRIDE.read_text()) if _OVERRIDE.exists() else {}
        override = {k: v for k, v in override.items() if not k.startswith("_")}
        derived.update(override)   # manual wins

        for asg, pats in derived.items():
            cur.execute("UPDATE cna SET advisory_patterns = %s WHERE cna_id = %s",
                        (Json(pats), asg))
    conn.commit()
    print(f"  cna patterns: {len(derived)} CNAs ({len(override)} override)")
    return len(derived)


if __name__ == "__main__":
    import os
    import psycopg2
    conn = psycopg2.connect(os.environ["POSTGRES_DSN"])
    run(conn)
