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
    active            BOOLEAN NOT NULL DEFAULT TRUE,
    synced_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

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
