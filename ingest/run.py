"""v2 ingest CLI.

  python -m ingest.run schema                  apply schema.sql
  python -m ingest.run sync   [target...]      download source data (default: all)
  python -m ingest.run ingest [target...]      write downloaded data into the DB
  python -m ingest.run daily                   full pipeline: schema → sync → ingest → affected → hasura-init
  python -m ingest.run api                     serve the REST API (POST /match · POST /lve · /healthz)

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
    "nvd":        ("ingest.records.nvd",         "cve_desc",   "nvd"),
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
    "nodejs":     ("ingest.advisories.nodejs",   "cve_vendor", "nodejs"),
    "exploitdb":  ("ingest.exploits.exploitdb",  "exploits", "exploitdb"),
    "metasploit": ("ingest.exploits.metasploit", "exploits", "metasploit"),
    "nuclei":     ("ingest.exploits.nuclei",     "exploits", "nuclei"),
    "poc_github": ("ingest.exploits.poc_github", "exploits", "poc_github"),
}

GROUPS = {
    "reference":  ["cna", "cpe", "cwe", "source_urls"],
    "scoring":    ["epss", "kev", "ssvc"],
    "records":    ["cvelistv5", "nvd"],
    "advisories": ["redhat", "suse", "ubuntu", "debian", "oracle", "almalinux", "rocky", "microsoft", "ghsa", "osv", "nodejs"],
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

    if cmd == "api":
        from ingest.api import main as api_main
        return api_main()

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
    from ingest.match import remediation
    print(f"{len(findings)} vulnerable CVE(s):")
    for cid in sorted(findings):
        hits = findings[cid]
        fixed = next((f for _, _, f, _, _ in hits if f), None)
        kb = next((k for _, _, _, k, _ in hits if k), None)
        srcs = ",".join(sorted({s for s, _, _, _, _ in hits}))
        print(f"  {cid}  fixed={fixed or '-'}{('  ' + kb) if kb else ''}  [{srcs}]")
    rem = remediation(findings)
    if rem and rem.get("fixed"):
        print(f"→ remediation: upgrade to {rem['fixed']}"
              f"{('  ' + rem['fix_kb']) if rem.get('fix_kb') else ''}"
              f"  (closes {rem['closes']}, unfixed {rem['unfixed']})  [{rem['cve']}]")
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
    Usage: vdb create-token [--ttl <days>] [--role <role[,role2,…]>]   (default: 1 day, readonly).
    --role accepts several comma-separated roles (e.g. lve_writer,curation_writer) → one token that
    holds them all; readonly is always included, and the first given role is the default role."""
    import base64
    import datetime
    import hashlib
    import hmac
    import json
    import secrets as _secrets

    ttl = 1
    if "--ttl" in args:
        ttl = int(args[args.index("--ttl") + 1])
    roles = ["readonly"]
    if "--role" in args:
        roles = [r.strip() for r in args[args.index("--role") + 1].split(",") if r.strip()] or roles
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
            "x-hasura-allowed-roles": sorted(set(roles) | {"readonly"}),
            "x-hasura-default-role":  roles[0],
        },
    }

    def _seg(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")

    signing = _seg({"alg": "HS256", "typ": "JWT"}) + b"." + _seg(payload)
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing, hashlib.sha256).digest()).rstrip(b"=")
    print((signing + b"." + sig).decode())
    print(f"\nroles={','.join(sorted(set(roles) | {'readonly'}))} · default={roles[0]} · "
          f"TTL {ttl}d · expires {exp:%Y-%m-%d}", file=sys.stderr)
    return 0


# cve.composite: one JSONB field per CVE with the priority-resolved description/cvss/cwes plus the
# single-source epss/kev/ssvc — so a consumer gets "the one value that matters" without walking the
# multi-source arrays. __PRIO__ is replaced with the SOURCE_PRIORITY array at hasura-init time (env
# driven — change the env + re-run `vdb hasura-init`, no re-ingest). cwes: highest-priority origin
# that has REAL (catalog) CWEs; NVD placeholders (NVD-CWE-noinfo/-Other, not in the cwe table) drop
# out via the INNER JOIN. cvss: newest version first, then source priority.
_COMPOSITE_SQL = """
CREATE OR REPLACE FUNCTION cve_composite(c cve) RETURNS jsonb
LANGUAGE sql STABLE AS $fn$
SELECT jsonb_build_object(
  'description', (
    SELECT jsonb_build_object('value', d.value, 'origin', d.origin, 'source', d.source)
    FROM cve_desc d
    WHERE d.cve_id = c.cve_id AND d.lang = 'en' AND coalesce(d.value,'') <> ''
    ORDER BY array_position(__PRIO__, d.origin) NULLS LAST
    LIMIT 1),
  'cvss', (
    SELECT jsonb_build_object('version', v.version, 'base_score', v.base_score,
                              'severity', v.severity, 'vector', v.vector,
                              'origin', v.origin, 'source', v.source)
    FROM cve_cvss v
    WHERE v.cve_id = c.cve_id
    ORDER BY array_position(ARRAY['4.0','3.1','3.0','2.0']::text[], v.version) NULLS LAST,
             array_position(__PRIO__, v.origin) NULLS LAST
    LIMIT 1),
  'cwes', (
    SELECT jsonb_agg(DISTINCT jsonb_build_object(
             'cwe_id', cw.cwe_id, 'origin', cw.origin, 'source', cw.source,
             'name', cat.name, 'abstraction', cat.abstraction,
             'description', cat.description, 'extended_description', cat.extended_description,
             'likelihood_of_exploit', cat.likelihood_of_exploit,
             'common_consequences', cat.common_consequences,
             'potential_mitigations', cat.potential_mitigations,
             'modes_of_introduction', cat.modes_of_introduction,
             'detection_methods', cat.detection_methods,
             'related_attack_patterns', cat.related_attack_patterns,
             'related_weaknesses', cat.related_weaknesses))
    FROM cve_cwe cw
    JOIN cwe cat ON cat.cwe_id = cw.cwe_id
    WHERE cw.cve_id = c.cve_id
      AND cw.origin = (
          SELECT cw2.origin FROM cve_cwe cw2
          JOIN cwe cat2 ON cat2.cwe_id = cw2.cwe_id
          WHERE cw2.cve_id = c.cve_id
          ORDER BY array_position(__PRIO__, cw2.origin) NULLS LAST
          LIMIT 1)),
  'epss', (SELECT jsonb_build_object('score', e.score, 'percentile', e.percentile, 'date', e.date)
           FROM epss e WHERE e.cve_id = c.cve_id),
  'kev',  (SELECT jsonb_build_object('date_added', k.date_added, 'due_date', k.due_date,
                                     'known_ransomware', k.known_ransomware, 'required_action', k.required_action,
                                     'vendor_project', k.vendor_project, 'product', k.product,
                                     'vulnerability_name', k.vulnerability_name, 'short_description', k.short_description)
           FROM kev k WHERE k.cve_id = c.cve_id),
  'ssvc', (SELECT jsonb_build_object('exploitation', s.exploitation, 'automatable', s.automatable,
                                     'technical_impact', s.technical_impact)
           FROM ssvc s WHERE s.cve_id = c.cve_id)
);
$fn$;
"""


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
            "advisory_cve": "advisory_cve", "exploits": "exploits", "affected": "affected",
            "curation": "curations"}                     # per-CVE overrides (audit: cve.curations)
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

    print("Composite computed field (cve.composite)...")
    prio = [s.strip() for s in os.environ.get(
        "SOURCE_PRIORITY", "nvd,cvelistv5,redhat,suse,ubuntu,debian,ghsa,microsoft").split(",") if s.strip()]
    prio_arr = "ARRAY[" + ",".join("'" + s.replace("'", "''") + "'" for s in prio) + "]::text[]"
    from ingest.core.db import get_conn
    dbc = get_conn()
    try:
        with dbc.cursor() as cur:
            cur.execute(_COMPOSITE_SQL.replace("__PRIO__", prio_arr))
        dbc.commit()
        print(f"  ✓ function cve_composite (priority: {','.join(prio)})")
    except Exception as e:
        print(f"  ✗ function cve_composite: {e}")
    finally:
        dbc.close()
    attempt("cve.composite [computed field]", {"type": "pg_add_computed_field", "args": {
            "source": "default", "table": {"schema": "public", "name": "cve"}, "name": "composite",
            "definition": {"function": {"schema": "public", "name": "cve_composite"}}}})

    print("Permissions (select)...")
    for role in ("readonly", "lve_writer", "curation_writer"):   # writers = readonly + own insert
        for t in ALL:
            perm = {"columns": "*", "filter": {}, "allow_aggregations": True}
            if t == "cve":                          # expose the composite computed field to the role
                perm["computed_fields"] = ["composite"]
                # drop+recreate so an existing permission picks up computed_fields (create alone is a
                # no-op when the permission already exists); harmless "not exists" on a fresh DB.
                attempt(f"cve drop [{role}]", {"type": "pg_drop_select_permission", "args": {
                        "source": "default", "table": {"schema": "public", "name": "cve"}, "role": role}})
            attempt(f"{t} [{role}]", {"type": "pg_create_select_permission", "args": {"source": "default",
                    "table": {"schema": "public", "name": t}, "role": role, "permission": perm}})

    print("Permission (lve_writer insert on lve)...")
    attempt("lve [lve_writer insert]", {"type": "pg_create_insert_permission", "args": {"source": "default",
            "table": {"schema": "public", "name": "lve"}, "role": "lve_writer",
            "permission": {"columns": ["id", "title", "description", "severity", "coord",
                                       "ecosystem", "package", "purl", "cpe23", "release",
                                       "introduced", "fixed", "last_affected",
                                       "version_scheme", "status", "created_by"],
                           "check": {}}}})

    print("Permission (curation_writer insert on curation)...")
    attempt("curation [curation_writer insert]", {"type": "pg_create_insert_permission", "args":
            {"source": "default", "table": {"schema": "public", "name": "curation"},
             "role": "curation_writer",
             "permission": {"columns": ["cve_id", "action", "coord", "ecosystem", "package",
                                        "cpe23", "release", "source", "status", "fixed",
                                        "introduced", "last_affected", "reason", "created_by",
                                        "expires_at"], "check": {}}}})

    print("Reloading metadata...")
    call({"type": "reload_metadata", "args": {"reload_remote_schemas": False}})
    print("Hasura init done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
