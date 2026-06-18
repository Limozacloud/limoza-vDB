-- ── LVE Spine ─────────────────────────────────────────────────────────────────
CREATE SEQUENCE IF NOT EXISTS lve_seq START 1;

CREATE TABLE IF NOT EXISTS lve (
    lve_id      TEXT PRIMARY KEY,
    aliases     TEXT[] NOT NULL DEFAULT '{}',
    has_exploit BOOLEAN NOT NULL DEFAULT FALSE,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION lve_assign_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.lve_id IS NULL OR NEW.lve_id = '' THEN
        NEW.lve_id := 'LVDB-' || LPAD(nextval('lve_seq')::TEXT, 8, '0');
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER lve_before_insert
    BEFORE INSERT ON lve
    FOR EACH ROW EXECUTE FUNCTION lve_assign_id();

CREATE INDEX IF NOT EXISTS idx_lve_aliases     ON lve USING GIN (aliases);
CREATE INDEX IF NOT EXISTS idx_lve_has_exploit ON lve (has_exploit) WHERE has_exploit = TRUE;

-- ── CVE Data (NVD only) ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_cve (
    lve_id               TEXT PRIMARY KEY REFERENCES lve(lve_id) ON DELETE CASCADE,
    cve_id               TEXT UNIQUE NOT NULL,
    status               TEXT CHECK (status IN ('cve_assigned','cve_reserved','cve_pending','cve_rejected')),
    published            TIMESTAMPTZ,
    updated              TIMESTAMPTZ,
    epss_score           DOUBLE PRECISION,
    epss_percentile      DOUBLE PRECISION,
    epss_date            DATE,
    kev_date_added       DATE,
    kev_due_date         DATE,
    kev_known_ransomware BOOLEAN,
    kev_required_action  TEXT,
    ssvc_exploitation    TEXT CHECK (ssvc_exploitation    IN ('none','poc','active')),
    ssvc_automatable     TEXT CHECK (ssvc_automatable     IN ('yes','no')),
    ssvc_technical_impact TEXT CHECK (ssvc_technical_impact IN ('partial','total'))
);

CREATE INDEX IF NOT EXISTS idx_lve_cve_cve_id ON lve_cve (cve_id);

-- ── Titles ────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_titles (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    UNIQUE (lve_id, source, advisory_ref)
);

-- ── Descriptions ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_descriptions (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    UNIQUE (lve_id, source, advisory_ref)
);

-- ── CVSS ──────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_cvss (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT             NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    version      TEXT             NOT NULL,
    score        DOUBLE PRECISION NOT NULL,
    vector       TEXT             NOT NULL,
    severity     TEXT             CHECK (severity IN ('critical','high','medium','low','informational')),
    source       TEXT             NOT NULL,
    advisory_ref TEXT,
    product_id   TEXT,
    UNIQUE (lve_id, vector, source)
);

CREATE INDEX IF NOT EXISTS idx_lve_cvss_score ON lve_cvss (score DESC);

-- ── CWEs ──────────────────────────────────────────────────────────────────────
-- Per-LVE weakness references: "this LVE is CWE-NNN, according to source X".
CREATE TABLE IF NOT EXISTS lve_cwes (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    cwe_id       TEXT NOT NULL,
    name         TEXT,
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    UNIQUE (lve_id, cwe_id, source)
);

-- ── CWE Dictionary ─────────────────────────────────────────────────────────────
-- Shared weakness definitions (one row per CWE, ~940 total), enriched from the
-- CWE-CAPEC json_repo/W/*.json clone. Populated on-reference: whenever an
-- lve_cwes row is written, the full definition for that cwe_id is upserted here.
-- lve_cwes.cwe_id references this loosely — NO foreign key, because sources may
-- cite CWE ids absent from the synced Weakness set (categories, CWE-NVD-noinfo).
-- The rich fields exist so an LLM can author mitigation guidance from the DB alone.
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id                  TEXT PRIMARY KEY,        -- "CWE-79"
    name                    TEXT,                    -- weakness name
    abstraction             TEXT,                    -- Base / Variant / Class / Pillar
    description             TEXT,                    -- short Description
    extended_description    TEXT,                    -- ExtendedDescription
    likelihood_of_exploit   TEXT,                    -- High / Medium / Low
    common_consequences     JSONB,                   -- [{scope[], impact[], note}]
    potential_mitigations   JSONB,                   -- [{phase[], strategy, description, effectiveness}]
    modes_of_introduction   JSONB,                   -- [{phase, note}]
    detection_methods       JSONB,                   -- [{method, description, effectiveness}]
    related_attack_patterns JSONB,                   -- ["CAPEC-63", ...]
    related_weaknesses      JSONB,                   -- [{nature, cwe_id, view_id}]
    synced_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── References ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_references (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    url          TEXT NOT NULL,
    type         TEXT NOT NULL,
    source       TEXT,
    advisory_ref TEXT,
    UNIQUE (lve_id, url, source)
);

-- ── Advisories ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_advisories (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    advisory_id  TEXT NOT NULL,
    source       TEXT NOT NULL,
    url          TEXT,
    published    TIMESTAMPTZ,
    updated      TIMESTAMPTZ,
    vendor_data  JSONB,
    UNIQUE (lve_id, advisory_id)
);

-- ── Upstream projects ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_upstream (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    upstream_id  TEXT NOT NULL,
    purl         TEXT NOT NULL,
    fix_version  TEXT,
    fix_commit   TEXT,
    ranges       JSONB,
    versions     TEXT[],
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    UNIQUE (lve_id, upstream_id)
);

-- ── Packages ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_packages (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id            TEXT    NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    name              TEXT,
    purl              TEXT    NOT NULL,
    affected_state    TEXT    NOT NULL DEFAULT 'unknown'
                          CHECK (affected_state IN ('affected','not_affected','not_applicable','unknown')),
    remediation_state TEXT    NOT NULL DEFAULT 'unknown'
                          CHECK (remediation_state IN ('fixed','will_not_fix','pending','none','unknown')),
    status_raw        TEXT,
    vex_justification TEXT    CHECK (vex_justification IN (
                          'component_not_present',
                          'vulnerable_code_not_present',
                          'vulnerable_code_not_in_execute_path',
                          'vulnerable_code_cannot_be_controlled_by_adversary',
                          'inline_mitigations_already_exist'
                      )),
    ranges            JSONB,
    source            TEXT    NOT NULL,
    advisory_ref      TEXT,
    upstream_ref      TEXT,
    severity          TEXT    CHECK (severity IN ('critical','high','medium','low','informational')),
    vendor_data       JSONB,
    UNIQUE (lve_id, purl, source)
);

CREATE INDEX IF NOT EXISTS idx_lve_packages_purl              ON lve_packages (purl);
CREATE INDEX IF NOT EXISTS idx_lve_packages_affected_state    ON lve_packages (affected_state);
CREATE INDEX IF NOT EXISTS idx_lve_packages_remediation_state ON lve_packages (remediation_state);

-- ── Mitigations ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_mitigations (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    purls        TEXT[],
    UNIQUE (lve_id, source, advisory_ref)
);

-- ── Impacts ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_impacts (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id       TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    value        TEXT NOT NULL,
    source       TEXT NOT NULL,
    advisory_ref TEXT,
    UNIQUE (lve_id, source, advisory_ref)
);

-- ── Exploits ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_exploits (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id    TEXT NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    source    TEXT NOT NULL,
    source_id TEXT,
    name      TEXT,
    url       TEXT NOT NULL,
    metadata  JSONB,
    UNIQUE (lve_id, url)
);

-- ── Notices ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notices (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    handled_at TIMESTAMPTZ,
    type       TEXT NOT NULL,
    source     TEXT NOT NULL,
    message    TEXT NOT NULL,
    metadata   JSONB,
    UNIQUE (type, source, message)
);

CREATE INDEX IF NOT EXISTS idx_notices_unhandled ON notices (created_at DESC) WHERE handled_at IS NULL;

-- ── History ───────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS lve_history (
    id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    lve_id    TEXT        NOT NULL REFERENCES lve(lve_id) ON DELETE CASCADE,
    date      TIMESTAMPTZ NOT NULL,
    event     TEXT        NOT NULL,
    source    TEXT        NOT NULL,
    detail    TEXT
);

-- detail is part of the key so per-advisory / per-package events that share the
-- same (date, event, source) — e.g. several advisory_added rows from one import —
-- coexist instead of colliding. COALESCE keeps NULL-detail events idempotent
-- (a bare nullable column would be treated as NULLS DISTINCT).
CREATE UNIQUE INDEX IF NOT EXISTS idx_lve_history_unique ON lve_history (lve_id, date, event, source, COALESCE(detail, ''));
CREATE INDEX IF NOT EXISTS idx_lve_history_lve_id ON lve_history (lve_id, date DESC);

-- ── Migrations ────────────────────────────────────────────────────────────────
ALTER TABLE lve_packages ADD COLUMN IF NOT EXISTS affected_state TEXT NOT NULL DEFAULT 'unknown'
    CHECK (affected_state IN ('affected','not_affected','not_applicable','unknown'));
ALTER TABLE lve_packages ADD COLUMN IF NOT EXISTS remediation_state TEXT NOT NULL DEFAULT 'unknown'
    CHECK (remediation_state IN ('fixed','will_not_fix','pending','none','unknown'));
ALTER TABLE lve_packages ADD COLUMN IF NOT EXISTS status_raw TEXT;
ALTER TABLE lve_packages ADD COLUMN IF NOT EXISTS vex_justification TEXT
    CHECK (vex_justification IN (
        'component_not_present','vulnerable_code_not_present',
        'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary',
        'inline_mitigations_already_exist'
    ));
DO $$ BEGIN ALTER TABLE lve_packages DROP COLUMN fix_status;
EXCEPTION WHEN undefined_column THEN NULL; END $$;
DROP INDEX IF EXISTS idx_lve_packages_fix_status;
ALTER TABLE lve_upstream ADD COLUMN IF NOT EXISTS versions TEXT[];
DO $$ BEGIN ALTER TABLE lve_history DROP COLUMN IF EXISTS field; EXCEPTION WHEN undefined_column THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE lve_history DROP COLUMN IF EXISTS old_value; EXCEPTION WHEN undefined_column THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE lve_history DROP COLUMN IF EXISTS new_value; EXCEPTION WHEN undefined_column THEN NULL; END $$;
