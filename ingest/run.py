"""v2 ingest CLI.

  python -m ingest.run schema                  apply schema.sql
  python -m ingest.run sync   [target...]      download source data (default: all)
  python -m ingest.run ingest [target...]      write downloaded data into the DB
  python -m ingest.run daily                   full pipeline: schema → sync → ingest → affected → hasura-init

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

    if cmd == "affected":
        return _affected(argv[1:])

    if cmd == "match":
        return _match(argv[1:])

    if cmd == "daily":
        return _daily()

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


def _daily() -> int:
    """Full pipeline (the scheduler's job): schema → sync → ingest → affected → hasura-init.

    Runs every phase regardless of per-source sync/ingest failures (those are isolated and
    logged in sync_log); a hard failure in schema / affected / hasura-init propagates. This
    is one command on purpose — the scheduler invokes `vdb daily`, not a shell pipeline.
    """
    from ingest.core.db import apply_schema
    print("== daily: schema ==", flush=True)
    apply_schema()
    print("== daily: sync ==", flush=True)
    main(["sync"])
    print("== daily: ingest ==", flush=True)
    main(["ingest"])
    print("== daily: affected ==", flush=True)
    _affected()
    print("== daily: hasura-init ==", flush=True)
    return _hasura_init()


def _log_sync(conn, source, result, started, log_run) -> None:
    """Normalise a sync run()'s return value into a sync_log row."""
    if isinstance(result, dict):  # gated → {"status": "no_new_data", "message": ...}
        log_run(conn, source, "sync", result.get("status", "no_new_data"),
                message=result.get("message"), started_at=started)
    else:
        items = result if isinstance(result, int) else None
        msg   = f"fetched {items:,}" if items is not None else "fetched"
        log_run(conn, source, "sync", "success", items=items, message=msg, started_at=started)


def _match(args) -> int:
    """Hold a scanned component against the affected table.
    Usage: vdb match <purl@version> [release]
      e.g. vdb match pkg:rpm/redhat/openssl@1.0.1e-30.el6_6.1
           vdb match pkg:deb/ubuntu/curl@7.81.0-1?distro=jammy
           vdb match pkg:pypi/django@2.0"""
    if not args:
        print(_match.__doc__)
        return 1
    from ingest.core.db import get_conn
    from ingest.match import match

    purl = args[0]
    release = args[1] if len(args) > 1 else None
    conn = get_conn()
    try:
        findings = match(conn, purl, None, release)
    finally:
        conn.close()
    if not findings:
        print("no vulnerable CVEs")
        return 0
    print(f"{len(findings)} vulnerable CVE(s):")
    for cid in sorted(findings):
        hits = findings[cid]
        fixed = next((f for _, _, f in hits if f), None)
        srcs = ",".join(sorted({s for s, _, _ in hits}))
        print(f"  {cid}  fixed={fixed or '-'}  [{srcs}]")
    return 0


def _affected(targets=None) -> int:
    """Central L4 pass: derive the affected-version layer from synced/ingested data.
    Optional targets restrict the run to specific extractors (e.g. `vdb affected suse`)."""
    import datetime

    from ingest.affected.run import run as run_affected
    from ingest.core.db import get_conn, log_run

    conn = get_conn()
    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        before = _table_total(conn, "affected")
        run_affected(conn, _dirs(), only=targets or None)
        after = _table_total(conn, "affected")
        log_run(conn, "affected", "ingest", "success", count_before=before,
                count_after=after, message=f"{after:,} total", started_at=started)
    finally:
        conn.close()
    return 0


def _table_total(conn, table) -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {table}")
        return cur.fetchone()[0]


def _create_token(args) -> int:
    """Mint an HS256 JWT for Hasura (stdlib only, no PyJWT).
    Usage: vdb create-token [--ttl <days>] [--role <role>]   (default: 1 day, readonly).
    A non-readonly role (e.g. lve_writer) also carries readonly, so it can read + write."""
    import base64
    import datetime
    import hashlib
    import hmac
    import json
    import secrets as _secrets

    ttl = 1
    if "--ttl" in args:
        ttl = int(args[args.index("--ttl") + 1])
    role = "readonly"
    if "--role" in args:
        role = args[args.index("--role") + 1]
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
            "x-hasura-allowed-roles": sorted({role, "readonly"}),
            "x-hasura-default-role":  role,
        },
    }

    def _seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")

    signing = _seg({"alg": "HS256", "typ": "JWT"}) + b"." + _seg(payload)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=")
    print((signing + b"." + sig).decode())
    print(f"\nrole={role} · TTL {ttl}d · expires {exp:%Y-%m-%d}", file=sys.stderr)
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
            "advisory_cve": "advisory_cve", "exploits": "exploits", "affected": "affected"}
    OTHER = ["advisory", "adp", "cna", "cpe", "cwe", "sync_log", "cve_level", "lve"]
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

    print("Permissions (select)...")
    for role in ("readonly", "lve_writer"):           # lve_writer = readonly + insert on lve
        for t in ALL:
            attempt(f"{t} [{role}]", {"type": "pg_create_select_permission", "args": {"source": "default",
                    "table": {"schema": "public", "name": t}, "role": role,
                    "permission": {"columns": "*", "filter": {}, "allow_aggregations": True}}})

    print("Permission (lve_writer insert on lve)...")
    attempt("lve [lve_writer insert]", {"type": "pg_create_insert_permission", "args": {"source": "default",
            "table": {"schema": "public", "name": "lve"}, "role": "lve_writer",
            "permission": {"columns": ["id", "title", "description", "severity", "coord",
                                       "ecosystem", "package", "purl", "cpe23", "release",
                                       "introduced", "fixed", "last_affected",
                                       "version_scheme", "status", "created_by"],
                           "check": {}}}})

    print("Reloading metadata...")
    call({"type": "reload_metadata", "args": {"reload_remote_schemas": False}})
    print("Hasura init done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
