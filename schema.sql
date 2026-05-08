CREATE TABLE IF NOT EXISTS scan_history (
    id             INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    image_name     TEXT      NOT NULL,
    decision       TEXT      NOT NULL CHECK(decision IN ('APPROVED', 'WARNING', 'REJECTED')),
    reason         TEXT      NOT NULL,
    source         TEXT      NOT NULL,
    critical_vulns INTEGER   DEFAULT 0,
    high_vulns     INTEGER   DEFAULT 0,
    medium_vulns   INTEGER   DEFAULT 0,
    low_vulns      INTEGER   DEFAULT 0,
    image_size_mb  REAL      DEFAULT 0,
    secrets_found  INTEGER   DEFAULT 0,
    ai_provider    TEXT,
    scanned_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_exceptions (
    id          INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id      TEXT      NOT NULL UNIQUE,
    reason      TEXT      NOT NULL,
    approved_by TEXT,
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active   INTEGER   DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_scan_history_image      ON scan_history(image_name);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned_at ON scan_history(scanned_at);
CREATE INDEX IF NOT EXISTS idx_cve_exceptions_cve_id   ON cve_exceptions(cve_id);

CREATE TABLE IF NOT EXISTS code_scan_history (
    id             INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    project_name   TEXT      NOT NULL,
    commit_sha     TEXT,
    branch         TEXT,
    decision       TEXT      NOT NULL CHECK(decision IN ('PASSED', 'WARNING', 'BLOCKED')),
    critical_count INTEGER   DEFAULT 0,
    high_count     INTEGER   DEFAULT 0,
    medium_count   INTEGER   DEFAULT 0,
    low_count      INTEGER   DEFAULT 0,
    files_analyzed INTEGER   DEFAULT 0,
    ai_provider    TEXT,
    scanned_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_code_scan_project    ON code_scan_history(project_name);
CREATE INDEX IF NOT EXISTS idx_code_scan_scanned_at ON code_scan_history(scanned_at);