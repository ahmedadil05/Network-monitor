-- =============================================================
-- schema.sql
-- Network Monitor - Database Schema (PostgreSQL)
-- Entities derived strictly from Section 4.5 (Class Diagram)
-- and Section 4.2.3 (Data Layer description)
-- =============================================================

-- ---------------------------------------------------------------
-- Table: users
-- Source: Section 4.5.1 (User Class)
-- Attributes: user_id, username, password_hash, role
-- Roles: administrator, analyst, viewer
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id      SERIAL PRIMARY KEY,
    username     VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role         VARCHAR(50) NOT NULL DEFAULT 'viewer',
    created_at   TIMESTAMP NOT NULL DEFAULT NOW(),
    CHECK (role IN ('administrator', 'analyst', 'viewer'))
);

-- ---------------------------------------------------------------
-- Table: raw_log_files
-- Source: Section 4.2.3 (log files may be stored or referenced)
-- Tracks ingested dataset files
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_log_files (
    file_id      SERIAL PRIMARY KEY,
    file_name    VARCHAR(255) NOT NULL,
    upload_time  TIMESTAMP NOT NULL DEFAULT NOW(),
    row_count    INTEGER DEFAULT 0,
    processed    INTEGER NOT NULL DEFAULT 0,   -- 0=pending, 1=done
    uploaded_by  INTEGER REFERENCES users(user_id) ON DELETE SET NULL
);

-- ---------------------------------------------------------------
-- Table: log_entries
-- Source: Section 4.5.2 (LogEntry Class)
-- Attributes: log_id, timestamp, source_ip, destination_ip,
--             event_type, message
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_entries (
    log_id          SERIAL PRIMARY KEY,
    file_id         INTEGER REFERENCES raw_log_files(file_id) ON DELETE CASCADE,
    timestamp       VARCHAR(255),
    source_ip       VARCHAR(45),
    destination_ip  VARCHAR(45),
    event_type      VARCHAR(100),
    message         TEXT,
    -- Numerical features for anomaly detection
    duration        REAL DEFAULT 0,
    protocol_type   VARCHAR(50),
    service         VARCHAR(50),
    flag            VARCHAR(50),
    src_bytes       INTEGER DEFAULT 0,
    dst_bytes       INTEGER DEFAULT 0,
    land            INTEGER DEFAULT 0,
    wrong_fragment  INTEGER DEFAULT 0,
    urgent          INTEGER DEFAULT 0,
    -- Original label from dataset (if present)
    original_label  VARCHAR(100),
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------
-- Table: anomaly_results
-- Source: Section 4.5.5 (AnomalyResult Class)
-- Attributes: result_id, log_id (FK), anomaly_score,
--             detection_time, status
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomaly_results (
    result_id       SERIAL PRIMARY KEY,
    log_id          INTEGER NOT NULL REFERENCES log_entries(log_id) ON DELETE CASCADE,
    anomaly_score   REAL NOT NULL,
    severity        VARCHAR(50) NOT NULL,   -- HIGH / MEDIUM / LOW (FLAG-06)
    detection_time  TIMESTAMP NOT NULL DEFAULT NOW(),
    status          VARCHAR(50) NOT NULL DEFAULT 'OPEN',  -- OPEN / REVIEWED / DISMISSED
    explanation     TEXT,  -- Human-readable explanation (Section 4.6 explainability)
    CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
    CHECK (status IN ('OPEN', 'REVIEWED', 'DISMISSED'))
);

-- ---------------------------------------------------------------
-- Table: audit_log
-- Tracks admin actions for accountability
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    log_id      SERIAL PRIMARY KEY,
    user_id     INTEGER REFERENCES users(user_id) ON DELETE SET NULL,
    action      VARCHAR(255) NOT NULL,
    resource    VARCHAR(255),
    details     TEXT,
    timestamp   TIMESTAMP NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------
-- Indexes for query performance
-- ---------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_log_entries_file_id    ON log_entries(file_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_log_id ON anomaly_results(log_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_severity ON anomaly_results(severity);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_status   ON anomaly_results(status);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id       ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp     ON audit_log(timestamp);
