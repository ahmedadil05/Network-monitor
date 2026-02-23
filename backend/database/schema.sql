-- =============================================================
-- schema.sql
-- Network Monitor - Database Schema
-- Entities derived strictly from Section 4.5 (Class Diagram)
-- and Section 4.2.3 (Data Layer description)
-- =============================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------
-- Table: users
-- Source: Section 4.5.1 (User Class)
-- Attributes: user_id, username, password_hash, role
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT    NOT NULL UNIQUE,
    password_hash TEXT   NOT NULL,
    role         TEXT    NOT NULL DEFAULT 'administrator',
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------
-- Table: raw_log_files
-- Source: Section 4.2.3 (log files may be stored or referenced)
-- Tracks ingested dataset files
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_log_files (
    file_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    file_name    TEXT    NOT NULL,
    upload_time  TEXT    NOT NULL DEFAULT (datetime('now')),
    row_count    INTEGER DEFAULT 0,
    processed    INTEGER NOT NULL DEFAULT 0,   -- 0=pending, 1=done
    uploaded_by  INTEGER REFERENCES users(user_id)
);

-- ---------------------------------------------------------------
-- Table: log_entries
-- Source: Section 4.5.2 (LogEntry Class)
-- Attributes: log_id, timestamp, source_ip, destination_ip,
--             event_type, message
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_entries (
    log_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER REFERENCES raw_log_files(file_id),
    timestamp       TEXT,
    source_ip       TEXT,
    destination_ip  TEXT,
    event_type      TEXT,
    message         TEXT,
    -- Numerical features for anomaly detection
    duration        REAL    DEFAULT 0,
    protocol_type   TEXT,
    service         TEXT,
    flag            TEXT,
    src_bytes       INTEGER DEFAULT 0,
    dst_bytes       INTEGER DEFAULT 0,
    land            INTEGER DEFAULT 0,
    wrong_fragment  INTEGER DEFAULT 0,
    urgent          INTEGER DEFAULT 0,
    -- Original label from dataset (if present)
    original_label  TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ---------------------------------------------------------------
-- Table: anomaly_results
-- Source: Section 4.5.5 (AnomalyResult Class)
-- Attributes: result_id, log_id (FK), anomaly_score,
--             detection_time, status
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomaly_results (
    result_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id          INTEGER NOT NULL REFERENCES log_entries(log_id),
    anomaly_score   REAL    NOT NULL,
    severity        TEXT    NOT NULL,   -- HIGH / MEDIUM / LOW (FLAG-06)
    detection_time  TEXT    NOT NULL DEFAULT (datetime('now')),
    status          TEXT    NOT NULL DEFAULT 'OPEN',  -- OPEN / REVIEWED / DISMISSED
    explanation     TEXT    -- Human-readable explanation (Section 4.6 explainability)
);

-- ---------------------------------------------------------------
-- Indexes for query performance
-- ---------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_log_entries_file_id    ON log_entries(file_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_log_id ON anomaly_results(log_id);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_severity ON anomaly_results(severity);
CREATE INDEX IF NOT EXISTS idx_anomaly_results_status   ON anomaly_results(status);
