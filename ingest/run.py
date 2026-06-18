"""
CVE Ingest Pipeline

COMMANDS

  sync <target> [...]          Download / update one or more data sources (or "all")
  pipeline <job>               Run sync then import for a job defined in schedule.json
  import <vendor...>           Import vendor data into the database
  schema                       Apply database schema (tables, indexes, triggers, backfill)
  truncate [--yes] [table...]  Truncate tables. Specific tables: no prompt. All tables: --yes required.
  hasura-init                  Track all tables and create relationships in Hasura
  create-token [--ttl DAYS]    Create a read-only JWT (default TTL: 1 day)

──────────────────────────────────────────────────────────────

SYNC TARGETS

  redhat        Red Hat CVE data via Hydra REST API (incremental, checkpoint-based)
  suse_vex      SUSE CSAF-VEX archive from ftp.suse.com  (~391 MB, incremental)
  cisa_ssvc     CISA SSVC + KEV data  (cisagov/vulnrichment)
  cisa_kev      CISA Known Exploited Vulnerabilities feed
  bsi           BSI WID advisory index
  epss          FIRST EPSS scores  (~337k CVEs)
  exploitdb     Exploit-DB  (gitlab.com/exploit-database/exploitdb)
  nuclei        Nuclei CVE templates  (single JSON download)
  poc_github    PoC-in-GitHub  (nomi-sec/PoC-in-GitHub)
  ghsa          GitHub Advisory Database  (github/advisory-database)
  metasploit    Metasploit modules  (sparse clone, modules/ only)
  microsoft     MSRC monthly CVRF bulletins
  cpe           NVD CPE Dictionary  (~1.7M CPEs, NVD API 2.0) — saves cpe_raw.json
  cpe_index     Parse cpe_raw.json → cpe_dict.json  (no download)

IMPORT VENDORS

  OS / Distro
  nvd           NVD CVE data
  redhat        Red Hat CVE data  (requires: sync redhat)
  suse          SUSE CSAF VEX
  ubuntu        Ubuntu OpenVEX (security-metadata.canonical.com)
  debian        Debian security tracker
  alpine        Alpine secdb
  almalinux     AlmaLinux errata
  rocky         Rocky Linux errata
  oracle        Oracle Linux OVAL
  microsoft     Microsoft MSRC  (requires: sync microsoft)

  Exploit Intelligence
  exploitdb     Exploit-DB scripts + shellcodes  (requires: sync exploitdb)
  poc_github    GitHub PoC repos  (requires: sync poc_github)
  ghsa          GitHub Security Advisories  (requires: sync ghsa)
  osv           OSV package ecosystem advisories  (requires: sync osv)
  nuclei        Nuclei detection templates  (requires: sync nuclei)
  metasploit    Metasploit modules  (requires: sync metasploit)

  Scoring / Advisory
  epss          FIRST EPSS scores  (requires: sync epss)
  cisa_ssvc     CISA SSVC decision points  (requires: sync cisa_ssvc)
  cisa_kev      CISA Known Exploited Vulnerabilities  (requires: sync cisa_kev)
  bsi           BSI WID advisories  (requires: sync bsi)
  cpe           NVD CPE Dictionary  (requires: sync cpe + sync cpe_index)

──────────────────────────────────────────────────────────────

EXAMPLES

  docker compose run --rm ingest sync nvd
  docker compose run --rm ingest sync exploitdb

  docker compose run --rm ingest import redhat
  docker compose run --rm ingest import redhat --cve CVE-2024-3094
  docker compose run --rm ingest import nvd redhat suse ubuntu
  docker compose run --rm ingest import all

"""
import json
import os
import sys
from pathlib import Path

from ingest.db import get_conn, sync_schema
from ingest.utils import timer_start, timer_step, timer_summary
from ingest import nvd, epss, microsoft, bsi, ghsa, osv
from ingest import cisa_kev as _cisa_kev_vendor
from ingest import cisa_ssvc
from ingest import exploitdb, poc_github, nuclei, metasploit
from ingest import redhat, suse, ubuntu, oracle, debian
from ingest import alpine, almalinux, rocky
from ingest.nvd       import sync as _s_nvd
from ingest.epss      import sync as _s_epss
from ingest.microsoft import sync as _s_microsoft
from ingest.cisa_kev  import sync as _s_cisa_kev
from ingest.cisa_ssvc import sync as _s_cisa_ssvc
from ingest.bsi       import sync as _s_bsi
from ingest.ghsa      import sync as _s_ghsa
from ingest.redhat    import sync as _s_redhat
from ingest.suse      import sync as _s_suse
import types as _types
from ingest.cpe import sync as _s_cpe                                      # module with .sync()
_s_cpe_index = _types.SimpleNamespace(sync=_s_cpe.sync_index)             # adapts .sync_index() → .sync()
from ingest.exploitdb  import sync as _s_exploitdb
from ingest.nuclei     import sync as _s_nuclei
from ingest.metasploit import sync as _s_metasploit
from ingest.poc_github import sync as _s_poc_github
from ingest.ubuntu    import sync as _s_ubuntu
from ingest.cwe       import sync as _s_cwe
from ingest.oracle    import sync as _s_oracle
from ingest.debian    import sync as _s_debian
from ingest.alpine    import sync as _s_alpine
from ingest.almalinux import sync as _s_almalinux
from ingest.rocky     import sync as _s_rocky
from ingest.osv       import sync as _s_osv
from ingest.osv       import compare as _osv_compare

VENDORS = {
    # 1. CVE base
    "nvd":          nvd.ingest,
    # 2. Scoring & advisory (small, fast)
    "epss":         epss.ingest,
    "cisa_kev":     _cisa_kev_vendor.ingest,
    "cisa_ssvc":    cisa_ssvc.ingest,
    "bsi":          bsi.ingest,
    # 3. Vendor fix data (large)
    "redhat":       redhat.ingest,
    "suse":         suse.ingest,
    "ubuntu":       ubuntu.ingest,
    "debian":       debian.ingest,
    "alpine":       alpine.ingest,
    "almalinux":    almalinux.ingest,
    "rocky":        rocky.ingest,
    "oracle":       oracle.ingest,
    "microsoft":    microsoft.ingest,
    # 4. Upstream / package ecosystem
    "osv":          osv.ingest,
    # 5. Exploit intelligence
    "exploitdb":    exploitdb.ingest,
    "poc_github":   poc_github.ingest,
    "ghsa":         ghsa.ingest,
    "nuclei":       nuclei.ingest,
    "metasploit":   metasploit.ingest,
}

SYNCS = {
    # migrated — sync lives in vendor module
    "nvd":        _s_nvd,
    "epss":       _s_epss,
    "microsoft":  _s_microsoft,
    "cisa_kev":   _s_cisa_kev,
    "cisa_ssvc":  _s_cisa_ssvc,
    "bsi":        _s_bsi,
    "ghsa":       _s_ghsa,
    "redhat":     _s_redhat,
    "suse":       _s_suse,
    "ubuntu":     _s_ubuntu,
    "oracle":     _s_oracle,
    "debian":     _s_debian,
    "alpine":     _s_alpine,
    "almalinux":  _s_almalinux,
    "rocky":      _s_rocky,
    "exploitdb":  _s_exploitdb,
    "nuclei":     _s_nuclei,
    "metasploit": _s_metasploit,
    "poc_github": _s_poc_github,
    "cpe":        _s_cpe,
    "cpe_index":  _s_cpe_index,
    "osv":        _s_osv,
    "cwe":        _s_cwe,
}

# (sync_command, path_that_must_exist) — checked before each ingest run
VENDOR_REQUIRES: dict[str, tuple[str, str]] = {
    "nvd":        ("sync nvd",         "{nvd}/api"),
    "redhat":     ("sync redhat",      "{redhat}/checkpoint.json"),
    "suse":       ("sync suse",        "{suse_vex}/checkpoint.json"),
    "ubuntu":     ("sync ubuntu",      "{ubuntu_usn}/.git"),
    "debian":     ("sync debian",      "{debian_tracker}/checkpoint.json"),
    "alpine":     ("sync alpine",     "{alpine_secdb}/checkpoint.json"),
    "almalinux":  ("sync almalinux", "{almalinux_errata}/checkpoint.json"),
    "rocky":      ("sync rocky",     "{rocky_errata}/checkpoint.json"),
    "oracle":     ("sync oracle",      "{oracle_oval}/checkpoint.json"),
    "microsoft":  ("sync microsoft",  "{msrc}/cvrf"),
    "exploitdb":  ("sync exploitdb",  "{exploitdb}/exploitdb_index.json"),
    "poc_github": ("sync poc_github", "{poc_github}"),
    "ghsa":       ("sync ghsa",       "{ghsa}/advisories"),
    "osv":        ("sync osv",        "{osv}/osv_index.json"),
    "nuclei":     ("sync nuclei",     "{nuclei}/nuclei_index.json"),
    "metasploit": ("sync metasploit", "{metasploit}/metasploit_index.json"),
    "cpe":        ("sync cpe_index",   "{cpe}/cpe_dict.json"),
    "epss":       ("sync epss",       "{epss}/epss.json"),
    "cisa_ssvc":  ("sync cisa_ssvc",  "{cisa_ssvc}/ssvc_index.json"),
    "bsi":          ("sync bsi",       "{bsi}/bsi_index.json"),
    "cisa_kev":   ("sync cisa_kev",   "{cisa_kev}/kev_index.json"),
}


def _check_requires(vendor: str, dirs: dict) -> bool:
    if vendor not in VENDOR_REQUIRES:
        return True
    sync_cmd, path_tpl = VENDOR_REQUIRES[vendor]
    path = Path(path_tpl.format(**dirs))
    if not path.exists():
        print(f"  ✗ {vendor}: data missing — run `{sync_cmd}` first")
        print(f"    expected: {path}")
        return False
    return True


DIRS = {
    "nvd":      os.environ.get("NVD_DIR",      "/data/nvd"),
    "redhat":   os.environ.get("REDHAT_DIR",   "/data/redhat"),
    "msrc":     os.environ.get("MSRC_DIR",     "/data/msrc"),
    "suse_vex": os.environ.get("SUSE_VEX_DIR", "/data/suse-vex"),
    "ubuntu_usn":      os.environ.get("UBUNTU_USN_DIR",        "/data/ubuntu-usn"),
    "oracle_oval":     os.environ.get("ORACLE_OVAL_DIR",       "/data/oracle-oval"),
    "debian_tracker":  os.environ.get("DEBIAN_TRACKER_DIR",   "/data/debian-tracker"),
    "alpine_secdb":    os.environ.get("ALPINE_SECDB_DIR",     "/data/alpine-secdb"),
    "almalinux_errata": os.environ.get("ALMALINUX_ERRATA_DIR", "/data/almalinux-errata"),
    "rocky_errata":    os.environ.get("ROCKY_ERRATA_DIR",     "/data/rocky-errata"),
    "epss":       os.environ.get("EPSS_DIR",               "/data/epss"),
    "cisa_ssvc":  os.environ.get("CISA_SSVC_DIR",          "/data/cisa-ssvc"),
    "bsi":        os.environ.get("BSI_DIR",                "/data/bsi"),
    "cisa_kev":   os.environ.get("CISA_KEV_DIR",           "/data/cisa-kev"),
    "exploitdb":  os.environ.get("EXPLOITDB_DIR",          "/data/exploitdb"),
    "nuclei":     os.environ.get("NUCLEI_DIR",             "/data/nuclei"),
    "poc_github": os.environ.get("POC_GITHUB_DIR",         "/data/poc-github"),
    "ghsa":       os.environ.get("GHSA_DIR",               "/data/ghsa"),
    "metasploit": os.environ.get("METASPLOIT_DIR",         "/data/metasploit"),
    "cpe":        os.environ.get("CPE_DIR",                "/data/cpe"),
    "osv":        os.environ.get("OSV_DIR",                "/data/osv"),
    "cwe_db":     os.environ.get("CWE_DB_DIR",            "/data/cwe-db"),
}


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(1)

    command = args[0]

    # ── sync ──────────────────────────────────────────────────────────────────
    if command == "sync":
        targets = [a.rstrip(",") for a in args[1:] if not a.startswith("--")]
        if not targets:
            print("Usage: sync <target> [target ...]")
            print(f"Available: {', '.join(SYNCS)}")
            sys.exit(1)
        if targets == ["all"]:
            targets = list(SYNCS.keys())
        unknown = [t for t in targets if t not in SYNCS]
        if unknown:
            print(f"Unknown sync target(s): {', '.join(unknown)}")
            print(f"Available: {', '.join(SYNCS)}")
            sys.exit(1)
        timer_start()
        for target in targets:
            with timer_step(f"sync {target}"):
                SYNCS[target].sync(DIRS)
        timer_summary()
        return

    # ── import ────────────────────────────────────────────────────────────────
    if command == "import":
        cve_filter = None
        if "--cve" in args:
            idx = args.index("--cve")
            if idx + 1 >= len(args):
                print("Error: --cve requires a value (e.g. --cve CVE-2024-1234)")
                sys.exit(1)
            cve_filter = args[idx + 1]
            print(f"Filter: {cve_filter}")
        vendor_args = [a for a in args[1:] if not a.startswith("--") and a != cve_filter]

        targets = vendor_args if vendor_args else list(VENDORS.keys())
        if targets == ["all"]:
            targets = list(VENDORS.keys())

        sync_schema()
        timer_start()
        for v in targets:
            if v not in VENDORS:
                print(f"Unknown vendor: {v!r}. Available: {', '.join(VENDORS)}")
                continue
            if not _check_requires(v, DIRS):
                continue
            print(f"\n── {v} ──")
            conn = get_conn()
            try:
                with timer_step(f"import {v}"):
                    VENDORS[v](conn, DIRS, cve_filter=cve_filter)
            finally:
                conn.close()
        timer_summary()
        return

    # ── pipeline ──────────────────────────────────────────────────────────────
    if command == "pipeline":
        job_name = args[1] if len(args) > 1 else ""
        if not job_name:
            print("Usage: pipeline <job-name>")
            sys.exit(1)

        config_path = os.environ.get("SCHEDULE_CONFIG", "/config/schedule.json")
        config      = json.loads(Path(config_path).read_text())
        job         = next((j for j in config["jobs"] if j["name"] == job_name), None)
        if not job:
            names = [j["name"] for j in config["jobs"]]
            print(f"Unknown job: {job_name!r}. Available: {', '.join(names)}")
            sys.exit(1)

        sync_targets   = job.get("sync", [])
        import_vendors = job.get("import", [])

        print(f"\n══ pipeline: {job_name} ══")
        timer_start()

        if sync_targets:
            print(f"\n── sync: {', '.join(sync_targets)} ──")
            unknown = [t for t in sync_targets if t not in SYNCS]
            if unknown:
                print(f"Unknown sync targets: {', '.join(unknown)}")
                sys.exit(1)
            for target in sync_targets:
                with timer_step(f"sync {target}"):
                    SYNCS[target].sync(DIRS)

        if import_vendors:
            print(f"\n── import: {', '.join(import_vendors)} ──")
            sync_schema()
            conn = get_conn()
            for v in import_vendors:
                if v not in VENDORS:
                    print(f"Unknown vendor: {v!r}")
                    continue
                if not _check_requires(v, DIRS):
                    continue
                print(f"\n── {v} ──")
                with timer_step(f"import {v}"):
                    VENDORS[v](conn, DIRS)
            conn.close()

        timer_summary()
        print(f"\n══ pipeline: {job_name} done ══")
        return

    # ── create-token ──────────────────────────────────────────────────────────
    if command == "create-token":
        import datetime, secrets
        import jwt as pyjwt

        ttl = 1
        if "--ttl" in args:
            idx = args.index("--ttl")
            ttl = int(args[idx + 1])

        secret = os.environ.get("HASURA_JWT_SECRET")
        if not secret:
            print("Error: HASURA_JWT_SECRET not set in environment")
            sys.exit(1)

        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "jti": secrets.token_hex(16),
            "iat": now,
            "exp": now + datetime.timedelta(days=ttl),
            "https://hasura.io/jwt/claims": {
                "x-hasura-allowed-roles": ["readonly"],
                "x-hasura-default-role":  "readonly",
            },
        }
        token = pyjwt.encode(payload, secret, algorithm="HS256")
        print(token)
        print(f"\nTTL: {ttl} days — expires {(now + datetime.timedelta(days=ttl)).strftime('%Y-%m-%d')}", file=sys.stderr)
        return

    # ── hasura-init ───────────────────────────────────────────────────────────
    if command == "hasura-init":
        import urllib.request
        url    = os.environ.get("HASURA_GRAPHQL_URL", "http://hasura:8080")
        secret = os.environ.get("HASURA_ADMIN_SECRET", "changeme")
        headers = {"X-Hasura-Admin-Secret": secret, "Content-Type": "application/json"}

        def _hasura(payload):
            req = urllib.request.Request(
                f"{url}/v1/metadata",
                data=json.dumps(payload).encode(),
                headers=headers,
                method="POST",
            )
            try:
                with urllib.request.urlopen(req) as r:
                    return json.loads(r.read())
            except urllib.error.HTTPError as e:
                body = json.loads(e.read())
                code = body.get("code", "")
                if code in ("already-tracked", "already-exists", "already-untracked"):
                    return body
                raise RuntimeError(body.get("error", str(body))) from None

        CHILD_TABLES = [
            "lve_titles", "lve_descriptions",
            "lve_cvss", "lve_cwes", "lve_references",
            "lve_advisories", "lve_upstream", "lve_packages",
            "lve_mitigations", "lve_impacts",
            "lve_exploits", "lve_history",
        ]
        ALL_TABLES = ["lve", "lve_cve", "notices", "cwe"] + CHILD_TABLES

        print("Tracking tables...")
        for t in ALL_TABLES:
            try:
                _hasura({"type": "pg_track_table", "args": {
                    "source": "default", "table": {"schema": "public", "name": t},
                }})
                print(f"  ✓ {t}")
            except RuntimeError as e:
                print(f"  ✗ {t}: {e}")

        print("Creating object relationship (lve → lve_cve)...")
        try:
            _hasura({"type": "pg_create_object_relationship", "args": {
                "source": "default",
                "table": {"schema": "public", "name": "lve"},
                "name": "cve",
                "using": {"foreign_key_constraint_on": {
                    "table": {"schema": "public", "name": "lve_cve"},
                    "column": "lve_id",
                }},
            }})
            print("  ✓ lve → cve")
        except RuntimeError as e:
            print(f"  ✗ lve → cve: {e}")

        print("Creating object relationship (lve_cve → lve)...")
        try:
            _hasura({"type": "pg_create_object_relationship", "args": {
                "source": "default",
                "table": {"schema": "public", "name": "lve_cve"},
                "name": "lve",
                "using": {"foreign_key_constraint_on": "lve_id"},
            }})
            print("  ✓ lve_cve → lve")
        except RuntimeError as e:
            print(f"  ✗ lve_cve → lve: {e}")

        print("Creating array relationships (lve → children)...")
        for t in CHILD_TABLES:
            rel_name = t[len("lve_"):]  # e.g. "lve_titles" → "titles"
            try:
                _hasura({"type": "pg_create_array_relationship", "args": {
                    "source": "default",
                    "table": {"schema": "public", "name": "lve"},
                    "name": rel_name,
                    "using": {"foreign_key_constraint_on": {
                        "table": {"schema": "public", "name": t},
                        "column": "lve_id",
                    }},
                }})
                print(f"  ✓ lve → {rel_name}")
            except RuntimeError as e:
                print(f"  ✗ lve → {rel_name}: {e}")

        print("Creating object relationships (children → lve)...")
        for t in CHILD_TABLES:
            try:
                _hasura({"type": "pg_create_object_relationship", "args": {
                    "source": "default",
                    "table": {"schema": "public", "name": t},
                    "name": "lve",
                    "using": {"foreign_key_constraint_on": "lve_id"},
                }})
                print(f"  ✓ {t} → lve")
            except RuntimeError as e:
                print(f"  ✗ {t} → lve: {e}")

        print("Creating object relationship (lve_cwes → cwe dictionary)...")
        try:
            _hasura({"type": "pg_create_object_relationship", "args": {
                "source": "default",
                "table": {"schema": "public", "name": "lve_cwes"},
                "name": "cwe",
                "using": {"manual_configuration": {
                    "remote_table": {"schema": "public", "name": "cwe"},
                    "column_mapping": {"cwe_id": "cwe_id"},
                }},
            }})
            print("  ✓ lve_cwes → cwe")
        except RuntimeError as e:
            print(f"  ✗ lve_cwes → cwe: {e}")

        print("Setting readonly permissions...")
        for t in ALL_TABLES:
            try:
                _hasura({"type": "pg_create_select_permission", "args": {
                    "source": "default",
                    "table": {"schema": "public", "name": t},
                    "role": "readonly",
                    "permission": {"columns": "*", "filter": {}, "allow_aggregations": True},
                }})
                print(f"  ✓ {t} (readonly)")
            except RuntimeError as e:
                print(f"  ✗ {t}: {e}")
        print("Reloading Hasura metadata...")
        _hasura({"type": "reload_metadata", "args": {"reload_remote_schemas": False}})
        print("Hasura init done.")
        return

    # ── schema ────────────────────────────────────────────────────────────────
    if command == "schema":
        print("Applying database schema...")
        sync_schema()
        print("Schema sync complete.")
        return

    # ── truncate ──────────────────────────────────────────────────────────────
    if command == "truncate":
        ALL_TABLES = [
            "lve_history", "lve_exploits", "lve_impacts", "lve_mitigations",
            "lve_packages", "lve_upstream",
            "lve_advisories", "lve_references", "lve_cwes", "lve_cvss",
            "lve_descriptions", "lve_titles", "lve_cve", "notices", "lve",
            "cwe",
        ]
        yes = "--yes" in args
        tables = [a for a in args[1:] if not a.startswith("--")]

        if not tables:
            if not yes:
                print("Error: truncating all tables requires --yes")
                sys.exit(1)
            tables = ALL_TABLES

        unknown = [t for t in tables if t not in ALL_TABLES]
        if unknown:
            print(f"Unknown table(s): {', '.join(unknown)}")
            print(f"Available: {', '.join(ALL_TABLES)}")
            sys.exit(1)

        conn = get_conn()
        with conn.cursor() as cur:
            for t in tables:
                cur.execute(f"TRUNCATE TABLE {t} CASCADE")
                print(f"  ✓ {t}")
        conn.commit()
        conn.close()
        print(f"Truncated {len(tables)} table(s).")
        return


    # ── verify ───────────────────────────────────────────────────────────────
    if command == "verify":
        cve_id = args[1].upper() if len(args) > 1 else ""
        if not cve_id.startswith("CVE-"):
            print("Usage: verify <CVE-ID>")
            print("Example: verify CVE-2026-41651")
            sys.exit(1)
        print(f"Verifying {cve_id}...")
        _osv_compare.verify(cve_id, DIRS)
        return

    print(f"Unknown command: {command!r}")
    print(__doc__)
    sys.exit(1)


if __name__ == "__main__":
    main()
