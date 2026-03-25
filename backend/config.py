"""
config.py
Application configuration constants.
Technology stack selected per FLAG-01..03 resolution:
  - Python/Flask, SQLite, Isolation Forest (scikit-learn)
"""
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-prod")

    # SQLite database (local deployment per Section 3.4.6)
    DATABASE_PATH = os.path.join(BASE_DIR, "backend", "database", "network_monitor.db")
    DATABASE_SCHEMA = os.path.join(BASE_DIR, "backend", "database", "schema.sql")

    # Dataset storage (publicly available, locally stored per Section 3.4.7)
    DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
    UPLOAD_EXTENSIONS = {".csv", ".txt", ".log"}
    MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB max file size

    # Anomaly detection (FLAG-04: Isolation Forest)
    # Contamination = expected proportion of anomalies in data
    ANOMALY_CONTAMINATION = 0.1   # 10% anomaly assumption; adjustable
    ANOMALY_RANDOM_STATE = 42

    # FLAG-06: Severity thresholds derived from Isolation Forest score distribution
    # Isolation Forest scores: more negative = more anomalous
    SEVERITY_HIGH_THRESHOLD = -0.10    # score < -0.10  → HIGH
    SEVERITY_MEDIUM_THRESHOLD = 0.05   # score < 0.05   → MEDIUM
    # score >= 0.05 → LOW

    # Pagination
    ANOMALIES_PER_PAGE = 25

    # Session
    SESSION_COOKIE_SECURE = False      # Set True in production HTTPS
    SESSION_COOKIE_HTTPONLY = True
