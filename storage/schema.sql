-- Risk Drift Framework SQLite schema, version 1.
-- Timestamps are ISO-8601 UTC strings ('YYYY-MM-DDTHH:MM:SSZ').
-- data_origin separates real host evidence ('HOST') from labelled synthetic
-- demonstration/test data ('SYNTHETIC'); the dashboard always shows it.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    asset_id     TEXT PRIMARY KEY,
    hostname     TEXT,
    ip_address   TEXT,
    criticality  TEXT NOT NULL CHECK (criticality IN ('Low','Medium','High','Critical')),
    description  TEXT,
    data_origin  TEXT NOT NULL DEFAULT 'HOST' CHECK (data_origin IN ('HOST','SYNTHETIC')),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_criticality_history (
    history_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id     TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    criticality  TEXT NOT NULL CHECK (criticality IN ('Low','Medium','High','Critical')),
    changed_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_crit_hist_asset ON asset_criticality_history(asset_id, changed_at);

CREATE TABLE IF NOT EXISTS assessment_runs (
    run_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id          TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    started_at        TEXT NOT NULL,
    completed_at      TEXT,
    status            TEXT NOT NULL CHECK (status IN ('COMPLETE','PARTIAL','FAILED')),
    collector_version TEXT,
    policy_version    TEXT,
    opa_version       TEXT,
    policy_params_hash TEXT,
    data_origin       TEXT NOT NULL CHECK (data_origin IN ('HOST','SYNTHETIC')),
    evidence_hash     TEXT,
    error_message     TEXT
);
CREATE INDEX IF NOT EXISTS ix_runs_asset_time ON assessment_runs(asset_id, started_at);

CREATE TABLE IF NOT EXISTS config_snapshots (
    snapshot_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id              INTEGER NOT NULL UNIQUE REFERENCES assessment_runs(run_id) ON DELETE CASCADE,
    asset_id            TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    collected_at        TEXT NOT NULL,
    normalized_evidence TEXT NOT NULL,   -- canonical JSON, timestamps removed
    evidence_hash       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS check_results (
    result_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           INTEGER NOT NULL REFERENCES assessment_runs(run_id) ON DELETE CASCADE,
    asset_id         TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    check_id         TEXT NOT NULL,
    title            TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('COMPLIANT','NON_COMPLIANT','UNKNOWN','ERROR')),
    collector_status TEXT,
    expected         TEXT,
    actual           TEXT,     -- JSON
    reason           TEXT,
    remediation      TEXT,
    evidence         TEXT,     -- JSON (normalized, no secrets)
    evidence_hash    TEXT,
    UNIQUE (run_id, check_id)
);
CREATE INDEX IF NOT EXISTS ix_results_asset_check ON check_results(asset_id, check_id);

CREATE TABLE IF NOT EXISTS config_drift_events (
    drift_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    run_id           INTEGER NOT NULL REFERENCES assessment_runs(run_id) ON DELETE CASCADE,
    previous_run_id  INTEGER REFERENCES assessment_runs(run_id) ON DELETE SET NULL,
    check_id         TEXT,
    category         TEXT NOT NULL CHECK (category IN (
                        'BASELINE','CONFIGURATION_CHANGE','COMPLIANCE_TRANSITION','NEW_NON_COMPLIANCE',
                        'CORRECTED','MISSING_EVIDENCE','EVIDENCE_RESTORED','ASSESSMENT_FAILED',
                        'ASSESSMENT_INCOMPLETE','POLICY_CHANGE','TOOL_VERSION_CHANGE')),
    priority         TEXT NOT NULL CHECK (priority IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
    previous_status  TEXT,
    current_status   TEXT,
    previous_value   TEXT,  -- JSON (safe, normalized)
    current_value    TEXT,  -- JSON
    explanation      TEXT NOT NULL,
    detected_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_drift_asset_time ON config_drift_events(asset_id, detected_at);
CREATE INDEX IF NOT EXISTS ix_drift_run ON config_drift_events(run_id);

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    scan_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    source_report_id TEXT,
    source_file      TEXT NOT NULL,
    file_sha256      TEXT NOT NULL UNIQUE,
    report_format    TEXT NOT NULL CHECK (report_format IN ('GREENBONE_XML','GREENBONE_CSV')),
    scanner_version  TEXT,
    scan_started_at  TEXT,
    scan_ended_at    TEXT,
    imported_at      TEXT NOT NULL,
    finding_count    INTEGER NOT NULL DEFAULT 0,
    duplicate_count  INTEGER NOT NULL DEFAULT 0,
    skipped_count    INTEGER NOT NULL DEFAULT 0,
    data_origin      TEXT NOT NULL CHECK (data_origin IN ('HOST','SYNTHETIC')),
    UNIQUE (asset_id, source_report_id)
);
CREATE INDEX IF NOT EXISTS ix_scans_asset_time ON vulnerability_scans(asset_id, scan_ended_at);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    finding_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES vulnerability_scans(scan_id) ON DELETE CASCADE,
    asset_id        TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    finding_key     TEXT NOT NULL,     -- nvt_oid|host|port : dedup key
    result_id       TEXT,
    host            TEXT,
    port            TEXT,
    nvt_oid         TEXT,
    name            TEXT,
    cves            TEXT NOT NULL DEFAULT '[]',  -- JSON list
    cvss_score      REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    cvss_vector     TEXT,
    severity_label  TEXT,
    qod             INTEGER,
    description     TEXT,
    solution        TEXT,
    status          TEXT NOT NULL DEFAULT 'OPEN',
    UNIQUE (scan_id, finding_key)
);
CREATE INDEX IF NOT EXISTS ix_findings_asset ON vulnerability_findings(asset_id);

CREATE TABLE IF NOT EXISTS risk_scores (
    score_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id       TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    run_id         INTEGER REFERENCES assessment_runs(run_id) ON DELETE SET NULL,
    scan_id        INTEGER REFERENCES vulnerability_scans(scan_id) ON DELETE SET NULL,
    calculated_at  TEXT NOT NULL,
    model_version  TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('COMPLETE','PARTIAL','UNKNOWN')),
    score          REAL CHECK (score IS NULL OR (score >= 0 AND score <= 100)),
    score_lower    REAL,
    score_upper    REAL,
    band           TEXT,
    v_score        REAL, c_score REAL, d_score REAL, a_score REAL,
    available_components TEXT NOT NULL,  -- e.g. "VCDA"
    weights        TEXT NOT NULL,        -- JSON
    components     TEXT NOT NULL,        -- JSON details per component
    warnings       TEXT NOT NULL DEFAULT '[]',
    criticality    TEXT,
    data_origin    TEXT NOT NULL CHECK (data_origin IN ('HOST','SYNTHETIC'))
);
CREATE INDEX IF NOT EXISTS ix_scores_asset_time ON risk_scores(asset_id, calculated_at);

CREATE TABLE IF NOT EXISTS risk_drift_events (
    event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id          TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    score_id          INTEGER NOT NULL UNIQUE REFERENCES risk_scores(score_id) ON DELETE CASCADE,
    previous_score_id INTEGER REFERENCES risk_scores(score_id) ON DELETE SET NULL,
    previous_score    REAL,
    current_score     REAL,
    delta             REAL,
    direction         TEXT NOT NULL CHECK (direction IN ('BASELINE','INCREASED','DECREASED','UNCHANGED','NOT_COMPARABLE')),
    significant       INTEGER NOT NULL DEFAULT 0,
    component_deltas  TEXT,   -- JSON: weighted contribution of each component to delta
    model_version     TEXT NOT NULL,
    detected_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_rdrift_asset ON risk_drift_events(asset_id, detected_at);

CREATE TABLE IF NOT EXISTS risk_explanations (
    explanation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    score_id       INTEGER NOT NULL REFERENCES risk_scores(score_id) ON DELETE CASCADE,
    drift_event_id INTEGER REFERENCES risk_drift_events(event_id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('SCORE','DRIFT')),
    component      TEXT,
    factor         TEXT NOT NULL,
    detail         TEXT NOT NULL,
    evidence_ref   TEXT,   -- e.g. 'vulnerability_findings:12', 'check_results:40'
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_expl_score ON risk_explanations(score_id);
