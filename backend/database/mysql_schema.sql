-- =============================================================
-- mysql_schema.sql
-- Network Monitor - Database Schema for MySQL/WampServer
-- =============================================================

SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------
-- Table: users
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(50)  NOT NULL DEFAULT 'administrator',
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Table: raw_log_files
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS raw_log_files (
    file_id      INT AUTO_INCREMENT PRIMARY KEY,
    file_name    VARCHAR(255) NOT NULL,
    upload_time  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    row_count    INT DEFAULT 0,
    processed    TINYINT(1)   NOT NULL DEFAULT 0,
    uploaded_by  INT,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Table: log_entries
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_entries (
    log_id          INT AUTO_INCREMENT PRIMARY KEY,
    file_id         INT,
    timestamp       DATETIME,
    source_ip       VARCHAR(45),
    destination_ip  VARCHAR(45),
    event_type      VARCHAR(100),
    message         TEXT,
    duration        DOUBLE DEFAULT 0,
    protocol_type   VARCHAR(20),
    service         VARCHAR(50),
    flag            VARCHAR(20),
    src_bytes       BIGINT DEFAULT 0,
    dst_bytes       BIGINT DEFAULT 0,
    land            INT DEFAULT 0,
    wrong_fragment  INT DEFAULT 0,
    urgent          INT DEFAULT 0,
    original_label  VARCHAR(100),
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (file_id) REFERENCES raw_log_files(file_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Table: anomaly_results
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomaly_results (
    result_id       INT AUTO_INCREMENT PRIMARY KEY,
    log_id          INT NOT NULL,
    anomaly_score   DOUBLE NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    detection_time  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status          VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    explanation     TEXT,
    FOREIGN KEY (log_id) REFERENCES log_entries(log_id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------
CREATE INDEX idx_log_entries_file_id    ON log_entries(file_id);
CREATE INDEX idx_anomaly_results_log_id ON anomaly_results(log_id);
CREATE INDEX idx_anomaly_results_severity ON anomaly_results(severity);
CREATE INDEX idx_anomaly_results_status   ON anomaly_results(status);

SET FOREIGN_KEY_CHECKS = 1;
