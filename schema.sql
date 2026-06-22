-- ════════════════════════════════════════════════════════════════════════════
-- limoza-vDB v2 schema
--
-- Design: CVE is the central id — no synthetic LVDB ids. Every source writes
-- its own table independently (no shared spine row, no lock contention, no
-- ordering dependency). Two data shapes:
--
--   1. CVE-keyed enrichment  (PK = cve_id):  epss, kev, ssvc
--   2. standalone dictionaries (own key):    cna, cpe, cwe
-- ════════════════════════════════════════════════════════════════════════════

-- ── ADP dictionary ────────────────────────────────────────────────────────────
-- Authorized Data Publishers (CISA-ADP, the CVE Program container, …). Unlike
-- CNAs these aren't in the partner list, but every adp container carries a
-- providerMetadata {orgId, shortName, dateUpdated}. Collected as a byproduct of
-- the cvelistv5 scan (distinct by orgId UUID). cve_* source fields reference this
-- by UUID for ADP-authored rows (logical ref, no FK).
CREATE TABLE IF NOT EXISTS adp (
    uuid         TEXT PRIMARY KEY,     -- providerMetadata.orgId
    short_name   TEXT,
    last_updated TIMESTAMPTZ,          -- newest providerMetadata.dateUpdated seen
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_adp_short_name ON adp (short_name);

-- ── Advisories ────────────────────────────────────────────────────────────────
-- Vendor/distro security bulletins (RHSA, USN, GHSA, …). source = the ISSUER
-- name (NOT a cna_id — issuers aren't always CNAs, e.g. Debian). One shared
-- schema across all advisory sources (subfolders under ingest/advisories/).
-- The issuer's per-CVE enrichment (cvss/cwe/ref/workaround/impact) lands in the
-- cve_* tables with origin=<source>; only the advisory object + CVE links + the
-- per-CVE vendor blob live here. Affected/version status = phase 3.
CREATE TABLE IF NOT EXISTS advisory (
    source       TEXT NOT NULL,    -- 'redhat'
    advisory_id  TEXT NOT NULL,    -- 'RHSA-2024:2011'
    url          TEXT,
    title        TEXT,             -- not in RedHat VEX → may be NULL
    severity     TEXT,             -- per-advisory severity (GHSA etc.) → may be NULL
    published    TIMESTAMPTZ,
    modified     TIMESTAMPTZ,
    vendor_data  JSONB,            -- per-advisory source-specific extras
    PRIMARY KEY (source, advisory_id)
);

CREATE TABLE IF NOT EXISTS advisory_cve (
    source       TEXT NOT NULL,
    advisory_id  TEXT NOT NULL,
    cve_id       TEXT NOT NULL,
    PRIMARY KEY (source, advisory_id, cve_id)
);
CREATE INDEX IF NOT EXISTS idx_advisory_cve_cve ON advisory_cve (cve_id);

-- Per-CVE vendor assessment (RedHat severity, Ubuntu priority, …). One row per
-- (cve, source); everything source-specific (incl. severity) goes in data JSONB,
-- to be promoted to columns later if needed.
CREATE TABLE IF NOT EXISTS cve_vendor (
    cve_id  TEXT NOT NULL,
    source  TEXT NOT NULL,         -- 'redhat'
    data    JSONB,                 -- {"severity":"Important", ...}
    PRIMARY KEY (cve_id, source)
);
CREATE INDEX IF NOT EXISTS idx_cve_vendor_cve ON cve_vendor (cve_id);

-- ── CVE spine ─────────────────────────────────────────────────────────────────
-- Thin, shared registry of every known CVE id. Created by ANY source that
-- mentions a CVE (`ON CONFLICT DO NOTHING`) — nobody owns it. No foreign keys:
-- cve_id is the only join key, so the CHECK enforces the canonical form
-- (importers also pass ids through core.cveid.normalize at the boundary).
-- A cve row with no cve_record = "known to someone, not yet in the CVE List".
CREATE TABLE IF NOT EXISTS cve (
    cve_id     TEXT PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]+$'),
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── CVE record (cvelistV5, 1 row / CVE) ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS cve_record (
    cve_id         TEXT PRIMARY KEY,
    state          TEXT,                 -- PUBLISHED | REJECTED | RESERVED
    assigner       TEXT,                 -- CNA short name (→ cna.short_name)
    date_reserved  TIMESTAMPTZ,
    date_published TIMESTAMPTZ,
    date_updated   TIMESTAMPTZ,
    title          TEXT,
    exploit_note   TEXT,                 -- CNA prose ("Exploitable with…" / "not aware of…")
    synced_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cve_record_assigner ON cve_record (assigner);
CREATE INDEX IF NOT EXISTS idx_cve_record_published ON cve_record (date_published DESC NULLS LAST);

-- ── CVE info (N / CVE, multi-source) ──────────────────────────────────────────
-- origin = the importer that wrote the row (delete-scope on re-import);
-- source = who authored the data (cna | <adp shortname> | nvd | …) for display.
CREATE TABLE IF NOT EXISTS cve_cvss (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id     TEXT NOT NULL,
    origin     TEXT NOT NULL,
    source     TEXT,
    version    TEXT,                     -- 2.0 | 3.0 | 3.1 | 4.0
    base_score DOUBLE PRECISION,
    severity   TEXT,
    vector     TEXT,
    UNIQUE (cve_id, source, vector)
);
CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve ON cve_cvss (cve_id);

CREATE TABLE IF NOT EXISTS cve_cwe (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    cwe_id  TEXT NOT NULL,               -- CWE-79
    UNIQUE (cve_id, source, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve ON cve_cwe (cve_id);

CREATE TABLE IF NOT EXISTS cve_desc (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    lang    TEXT,
    value   TEXT NOT NULL,
    UNIQUE (cve_id, source, lang)
);
CREATE INDEX IF NOT EXISTS idx_cve_desc_cve ON cve_desc (cve_id);

CREATE TABLE IF NOT EXISTS cve_ref (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    url     TEXT NOT NULL,
    type    TEXT,
    UNIQUE (cve_id, source, url)
);
CREATE INDEX IF NOT EXISTS idx_cve_ref_cve ON cve_ref (cve_id);

-- remediation / mitigation prose (same shape as cve_desc; separate tables per
-- concept so other sources — vendors, distros — slot in via their `source`).
CREATE TABLE IF NOT EXISTS cve_solution (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    lang    TEXT,
    value   TEXT NOT NULL,
    UNIQUE (cve_id, source, lang)
);
CREATE INDEX IF NOT EXISTS idx_cve_solution_cve ON cve_solution (cve_id);

CREATE TABLE IF NOT EXISTS cve_workaround (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    lang    TEXT,
    value   TEXT NOT NULL,
    UNIQUE (cve_id, source, lang)
);
CREATE INDEX IF NOT EXISTS idx_cve_workaround_cve ON cve_workaround (cve_id);

CREATE TABLE IF NOT EXISTS cve_impact (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id      TEXT NOT NULL,
    origin      TEXT NOT NULL,
    source      TEXT,
    capec_id    TEXT,                    -- CAPEC-592
    description TEXT,
    UNIQUE (cve_id, source, capec_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_impact_cve ON cve_impact (cve_id);

CREATE TABLE IF NOT EXISTS cve_alias (
    id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id  TEXT NOT NULL,
    origin  TEXT NOT NULL,
    source  TEXT,
    alias   TEXT NOT NULL,              -- GHSA-xxx, JVNDB-…, etc.
    UNIQUE (cve_id, alias)
);
CREATE INDEX IF NOT EXISTS idx_cve_alias_cve   ON cve_alias (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_alias_alias ON cve_alias (alias);

-- ── Sync log ──────────────────────────────────────────────────────────────────
-- One row per sync/ingest run per source. Powers the dashboard's freshness
-- ("last successful X") and error views. Written by ingest/run.py around every
-- phase, success or failure.
--   status      success      = did work / wrote data
--               no_new_data  = checked, source unchanged (gate) — nothing to do
--               failed       = raised an error
--   items       sync phase: entries fetched/indexed (NULL for ingest)
--   count_before/after  ingest phase: DB rows before/after (NULL for sync);
--                       delta = count_after - count_before
--   message     always populated: the reasoning/summary (or the error text)
CREATE TABLE IF NOT EXISTS sync_log (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source       TEXT NOT NULL,                        -- epss, kev, cpe, ...
    phase        TEXT NOT NULL CHECK (phase  IN ('sync','ingest')),
    status       TEXT NOT NULL CHECK (status IN ('success','no_new_data','failed')),
    items        INTEGER,                              -- sync: entries fetched/indexed
    count_before INTEGER,                              -- ingest: DB rows before
    count_after  INTEGER,                              -- ingest: DB rows after
    message      TEXT,                                 -- reasoning / summary / error
    started_at   TIMESTAMPTZ NOT NULL,
    finished_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_sync_log_source ON sync_log (source, phase, finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_sync_log_error  ON sync_log (finished_at DESC) WHERE status = 'failed';
-- "Latest run per (source, phase)" for the dashboard is a query
-- (DISTINCT ON (source, phase) ... ORDER BY finished_at DESC), not a DB view.

-- ── EPSS ──────────────────────────────────────────────────────────────────────
-- FIRST EPSS exploit-prediction scores. One row per CVE, full daily snapshot.
-- Pattern: pure UPSERT — entries are never deleted upstream, only re-scored.
CREATE TABLE IF NOT EXISTS epss (
    cve_id     TEXT PRIMARY KEY,
    score      DOUBLE PRECISION NOT NULL,
    percentile DOUBLE PRECISION,
    date       DATE,
    synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_epss_score ON epss (score DESC);

-- ── CISA KEV ──────────────────────────────────────────────────────────────────
-- CISA Known Exploited Vulnerabilities. ~1.6k rows, full snapshot.
-- Pattern: DELETE + INSERT — CISA can withdraw entries, so the table is rebuilt
-- to match the source each sync. DELETE (not TRUNCATE) keeps the dashboard
-- readable during the swap (ROW EXCLUSIVE lock, MVCC old-rows until commit).
CREATE TABLE IF NOT EXISTS kev (
    cve_id             TEXT PRIMARY KEY,
    date_added         DATE,
    due_date           DATE,
    known_ransomware   BOOLEAN,
    required_action    TEXT,
    vendor_project     TEXT,
    product            TEXT,
    vulnerability_name TEXT,
    short_description  TEXT,
    notes              TEXT,
    synced_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kev_date_added ON kev (date_added DESC);

-- ── CISA SSVC ─────────────────────────────────────────────────────────────────
-- CISA SSVC decision points (from cisagov/vulnrichment). Subset of CVEs.
-- Pattern: DELETE + INSERT (ROW EXCLUSIVE, dashboard stays readable during swap).
CREATE TABLE IF NOT EXISTS ssvc (
    cve_id           TEXT PRIMARY KEY,
    exploitation     TEXT CHECK (exploitation     IN ('none','poc','active')),
    automatable      TEXT CHECK (automatable      IN ('yes','no')),
    technical_impact TEXT CHECK (technical_impact IN ('partial','total')),
    synced_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── CNA dictionary ────────────────────────────────────────────────────────────
-- CVE Numbering Authorities (CVEProject/cve-website CNAsList.json). ~520 rows.
-- Pattern: UPSERT + SOFT sweep — advisories reference cna.short_name, so a CNA
-- dropped from the list is marked active=false, never hard-deleted.
CREATE TABLE IF NOT EXISTS cna (
    short_name        TEXT PRIMARY KEY,
    cna_id            TEXT,
    organization_name TEXT,
    scope             TEXT,
    advisory_url      TEXT,
    aliases           TEXT[],            -- record-shortName variants → this CNA (from cna_mapping.json)
    uuids             TEXT[],            -- all providerMetadata.orgIds seen (from corpus) → cve_* source join
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_cna_cna_id  ON cna (cna_id);
CREATE INDEX IF NOT EXISTS idx_cna_uuids   ON cna USING GIN (uuids);
CREATE INDEX IF NOT EXISTS idx_cna_aliases ON cna USING GIN (aliases);

-- ── CPE dictionary ────────────────────────────────────────────────────────────
-- NVD CPE 2.3 dictionary (~1.7M entries). Pattern: UPSERT — entries are
-- deprecated (deprecated=true), never deleted.
CREATE TABLE IF NOT EXISTS cpe (
    cpe_name_id  TEXT        PRIMARY KEY,
    cpe_uri      TEXT        NOT NULL,
    type         TEXT,                    -- 'a' application, 'o' OS, 'h' hardware
    vendor       TEXT,
    product      TEXT,
    version      TEXT,
    title_en     TEXT,
    deprecated   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ,
    modified_at  TIMESTAMPTZ,
    ingested_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe (vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_type           ON cpe (type);

-- ── CWE dictionary ────────────────────────────────────────────────────────────
-- CWE weakness definitions (CWE-CAPEC json_repo/W). ~940 rows. Pattern: UPSERT —
-- weaknesses are deprecated/obsoleted, never deleted.
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id                  TEXT PRIMARY KEY,        -- "CWE-79"
    name                    TEXT,
    abstraction             TEXT,                    -- Base / Variant / Class / Pillar
    description             TEXT,
    extended_description    TEXT,
    likelihood_of_exploit   TEXT,
    common_consequences     JSONB,
    potential_mitigations   JSONB,
    modes_of_introduction   JSONB,
    detection_methods       JSONB,
    related_attack_patterns JSONB,
    related_weaknesses      JSONB,
    synced_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── Exploits ──────────────────────────────────────────────────────────────────
-- Exploit intelligence from 4 homogeneous sources (exploitdb, metasploit, nuclei,
-- poc_github), keyed by CVE. Identical shape across sources → one table with a
-- `source` column. Per-source extras (verified, rank, severity, stars …) live in
-- metadata. Pattern: per source DELETE WHERE source=X + INSERT (dashboard-safe).
-- "has this CVE an exploit?" = EXISTS (SELECT 1 FROM exploits WHERE cve_id = ...).
CREATE TABLE IF NOT EXISTS exploits (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id     TEXT NOT NULL,
    source     TEXT NOT NULL,        -- exploitdb | metasploit | nuclei | poc_github
    source_id  TEXT,                 -- EDB id / msf module / repo full_name / template id
    name       TEXT,
    url        TEXT NOT NULL,
    metadata   JSONB,                -- per-source extras
    synced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, source, url)     -- one PoC can map to several CVEs → cve_id in key
);

CREATE INDEX IF NOT EXISTS idx_exploits_cve    ON exploits (cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_source ON exploits (source);
