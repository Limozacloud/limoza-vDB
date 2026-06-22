"""v2 ingest CLI.

  python -m ingest.run schema                  apply schema.sql
  python -m ingest.run sync   [target...]      download source data (default: all)
  python -m ingest.run ingest [target...]      write downloaded data into the DB

A target is a source key (epss, kev, …, exploitdb, …) or a group (exploits).
Each source has a module dir with sync.py/ingest.py exposing run(); a sync run()
returns an int (items), None, or {"status":"no_new_data","message":...} when gated.
Ingest counts are read from the source's table before/after. Every phase is timed,
recorded in sync_log, and isolated — one source failing never aborts the rest.

Data dirs default to $DATA_DIR/<key> (DATA_DIR defaults to /data).
"""
import datetime
import importlib
import os
import sys

# key -> (module, table, source_value)
#   table        = the DB table the ingest writes to
#   source_value = filters the row count to this source (shared tables); None = whole table
SOURCES = {
    "epss":       ("ingest.scoring.epss",        "epss", None),
    "kev":        ("ingest.scoring.kev",         "kev",  None),
    "ssvc":       ("ingest.scoring.ssvc",        "ssvc", None),
    "cna":        ("ingest.reference.cna",       "cna",  None),
    "cpe":        ("ingest.reference.cpe",       "cpe",  None),
    "cwe":        ("ingest.reference.cwe",       "cwe",  None),
    "source_urls":("ingest.reference.source_urls","source_url", None),
    "cvelistv5":  ("ingest.records.cvelistv5",   "cve_record", None),
    "redhat":     ("ingest.advisories.redhat",   "advisory", "redhat"),
    "suse":       ("ingest.advisories.suse",     "advisory", "suse"),
    "ubuntu":     ("ingest.advisories.ubuntu",   "advisory", "ubuntu"),
    "debian":     ("ingest.advisories.debian",   "cve_vendor", "debian"),
    "oracle":     ("ingest.advisories.oracle",   "advisory", "oracle"),
    "almalinux":  ("ingest.advisories.almalinux","advisory", "almalinux"),
    "rocky":      ("ingest.advisories.rocky",    "advisory", "rocky"),
    "microsoft":  ("ingest.advisories.microsoft","advisory", "microsoft"),
    "ghsa":       ("ingest.advisories.ghsa",     "advisory", "ghsa"),
    "osv":        ("ingest.advisories.osv",      "advisory", None),
    "exploitdb":  ("ingest.exploits.exploitdb",  "exploits", "exploitdb"),
    "metasploit": ("ingest.exploits.metasploit", "exploits", "metasploit"),
    "nuclei":     ("ingest.exploits.nuclei",     "exploits", "nuclei"),
    "poc_github": ("ingest.exploits.poc_github", "exploits", "poc_github"),
}

GROUPS = {
    "reference":  ["cna", "cpe", "cwe", "source_urls"],
    "scoring":    ["epss", "kev", "ssvc"],
    "records":    ["cvelistv5"],
    "advisories": ["redhat", "suse", "ubuntu", "debian", "oracle", "almalinux", "rocky", "microsoft", "ghsa", "osv"],
    "exploits":   ["exploitdb", "metasploit", "nuclei", "poc_github"],
}


def _dirs() -> dict:
    base = os.environ.get("DATA_DIR", "/data")
    return {key: os.path.join(base, key) for key in SOURCES}


def _expand(targets) -> list:
    out = []
    for t in targets:
        out.extend(GROUPS.get(t, [t]))
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1

    cmd, raw_targets = argv[0], (argv[1:] or list(SOURCES))

    if cmd == "schema":
        from ingest.core.db import apply_schema
        apply_schema()
        return 0

    if cmd == "hasura-init":
        return _hasura_init()

    if cmd == "create-token":
        return _create_token(argv[1:])

    if cmd not in ("sync", "ingest"):
        print(f"unknown command: {cmd}\n{__doc__}")
        return 1

    targets = _expand(raw_targets)
    unknown = [t for t in targets if t not in SOURCES]
    if unknown:
        print(f"unknown target(s): {', '.join(unknown)}")
        return 1

    from ingest.core.db import get_conn, log_run, table_count

    dirs = _dirs()
    conn = get_conn()
    failures = 0
    try:
        for t in targets:
            module, table, source_value = SOURCES[t]
            mod = importlib.import_module(f"{module}.{cmd}")
            started = datetime.datetime.now(datetime.timezone.utc)
            try:
                if cmd == "sync":
                    _log_sync(conn, t, mod.run(dirs), started, log_run)
                else:
                    before = table_count(conn, table, source_value)
                    mod.run(conn, dirs)
                    after = table_count(conn, table, source_value)
                    delta = after - before
                    note = f"{delta:+,} added" if delta else "no row change"
                    log_run(conn, t, "ingest", "success", count_before=before,
                            count_after=after, message=f"{after:,} total · {note}",
                            started_at=started)
            except Exception as e:
                conn.rollback()  # clear any aborted txn so the log insert succeeds
                failures += 1
                log_run(conn, t, cmd, "failed", message=f"{type(e).__name__}: {e}",
                        started_at=started)
                print(f"  ✗ {t} {cmd} failed: {type(e).__name__}: {e}")
    finally:
        conn.close()

    return 1 if failures else 0


def _log_sync(conn, source, result, started, log_run) -> None:
    """Normalise a sync run()'s return value into a sync_log row."""
    if isinstance(result, dict):  # gated → {"status": "no_new_data", "message": ...}
        log_run(conn, source, "sync", result.get("status", "no_new_data"),
                message=result.get("message"), started_at=started)
    else:
        items = result if isinstance(result, int) else None
        msg   = f"fetched {items:,}" if items is not None else "fetched"
        log_run(conn, source, "sync", "success", items=items, message=msg, started_at=started)


def _create_token(args) -> int:
    """Mint an HS256 JWT for Hasura, role 'readonly' (stdlib only, no PyJWT).
    Usage: vdb create-token [--ttl <days>]   (default 1)."""
    import base64
    import datetime
    import hashlib
    import hmac
    import json
    import secrets as _secrets

    ttl = 1
    if "--ttl" in args:
        ttl = int(args[args.index("--ttl") + 1])
    secret = os.environ.get("HASURA_JWT_SECRET")
    if not secret:
        print("Error: HASURA_JWT_SECRET not set in environment")
        return 1

    now = datetime.datetime.now(datetime.timezone.utc)
    exp = now + datetime.timedelta(days=ttl)
    payload = {
        "jti": _secrets.token_hex(16),
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": ["readonly"],
            "x-hasura-default-role":  "readonly",
        },
    }

    def _seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")

    signing = _seg({"alg": "HS256", "typ": "JWT"}) + b"." + _seg(payload)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=")
    print((signing + b"." + sig).decode())
    print(f"\nrole=readonly · TTL {ttl}d · expires {exp:%Y-%m-%d}", file=sys.stderr)
    return 0


def _hasura_init() -> int:
    """Track all V2 tables in Hasura + wire CVE-spine relationships (manual, no FKs)
    + grant select to anonymous/readonly + reload. Idempotent."""
    import json
    import urllib.error
    import urllib.request

    base   = os.environ.get("HASURA_GRAPHQL_URL", "http://hasura:8080")
    secret = os.environ.get("HASURA_ADMIN_SECRET", "")
    headers = {"X-Hasura-Admin-Secret": secret, "Content-Type": "application/json"}

    def call(payload):
        req = urllib.request.Request(f"{base}/v1/metadata", data=json.dumps(payload).encode(),
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = json.loads(e.read())
            if body.get("code", "") in ("already-tracked", "already-exists", "already-untracked"):
                return body
            raise RuntimeError(body.get("error", str(body))) from None

    def attempt(label, payload):
        try:
            call(payload); print(f"  ✓ {label}")
        except RuntimeError as e:
            print(f"  ✗ {label}: {e}")

    def manual(remote, mapping):
        return {"manual_configuration": {"remote_table": {"schema": "public", "name": remote},
                                         "column_mapping": mapping}}

    SPINE = "cve"
    ONE  = {"cve_record": "record", "epss": "epss", "kev": "kev", "ssvc": "ssvc"}   # 1:1 (PK cve_id)
    MANY = {"cve_cvss": "cvss", "cve_cwe": "cwes", "cve_desc": "descriptions",
            "cve_ref": "refs", "cve_solution": "solutions", "cve_workaround": "workarounds",
            "cve_impact": "impacts", "cve_alias": "aliases", "cve_vendor": "vendors",
            "advisory_cve": "advisory_cve", "exploits": "exploits"}
    OTHER = ["advisory", "adp", "cna", "cpe", "cwe", "sync_log", "cve_level"]
    ALL = [SPINE] + list(ONE) + list(MANY) + OTHER

    print("Tracking tables...")
    for t in ALL:
        attempt(t, {"type": "pg_track_table", "args": {"source": "default",
                    "table": {"schema": "public", "name": t}}})

    print("Tracking functions...")
    attempt("cve_levels()", {"type": "pg_track_function", "args": {"source": "default",
            "function": {"schema": "public", "name": "cve_levels"}}})

    print("Relationships (cve ↔ children)...")
    for t, rel in {**ONE, **MANY}.items():
        kind = "pg_create_object_relationship" if t in ONE else "pg_create_array_relationship"
        attempt(f"cve.{rel}", {"type": kind, "args": {"source": "default",
                "table": {"schema": "public", "name": SPINE}, "name": rel,
                "using": manual(t, {"cve_id": "cve_id"})}})
        attempt(f"{t}.cve", {"type": "pg_create_object_relationship", "args": {"source": "default",
                "table": {"schema": "public", "name": t}, "name": "cve",
                "using": manual(SPINE, {"cve_id": "cve_id"})}})

    print("Relationships (advisory ↔ advisory_cve, cve_cwe → cwe)...")
    attempt("advisory_cve.advisory", {"type": "pg_create_object_relationship", "args": {"source": "default",
            "table": {"schema": "public", "name": "advisory_cve"}, "name": "advisory",
            "using": manual("advisory", {"source": "source", "advisory_id": "advisory_id"})}})
    attempt("advisory.cves", {"type": "pg_create_array_relationship", "args": {"source": "default",
            "table": {"schema": "public", "name": "advisory"}, "name": "cves",
            "using": manual("advisory_cve", {"source": "source", "advisory_id": "advisory_id"})}})
    attempt("cve_cwe.cwe", {"type": "pg_create_object_relationship", "args": {"source": "default",
            "table": {"schema": "public", "name": "cve_cwe"}, "name": "cwe",
            "using": manual("cwe", {"cwe_id": "cwe_id"})}})

    print("Permissions (readonly select)...")
    for role in ("readonly",):
        for t in ALL:
            attempt(f"{t} [{role}]", {"type": "pg_create_select_permission", "args": {"source": "default",
                    "table": {"schema": "public", "name": t}, "role": role,
                    "permission": {"columns": "*", "filter": {}, "allow_aggregations": True}}})

    print("Reloading metadata...")
    call({"type": "reload_metadata", "args": {"reload_remote_schemas": False}})
    print("Hasura init done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
