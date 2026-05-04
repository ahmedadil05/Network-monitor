# AI-Powered Log Anomaly Detection and Visualization for Network Monitoring

**B.Sc. Graduation Project — Üsküdar University 2026**
Ahmed Adil Badawi Mohammed | 220209970
Supervisor: Asst. Prof. Dr. Salim Jibrin Danbatta

---

## Technology Stack

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| Language | Python 3.10+ | FLAG-01: open-source, undergraduate-level |
| Web Framework | Flask 3.0 | FLAG-02: lightweight, no enterprise overhead |
| Database | PostgreSQL | FLAG-03: relational, robust for local and cloud deployment |
| ML Algorithm | Isolation Forest (scikit-learn) | FLAG-04: unsupervised, explainable, resource-efficient |
| Dataset | NSL-KDD (UCI) | FLAG-05: referenced in project citations |
| Visualisation | Chart.js 4 | Open-source, browser-native |
| Architecture | Three-Tier Web (Section 4.2) | As specified in document |

---

## Project Structure

```
network-monitor/
  ├── backend/
  │   ├── auth/                  # Authentication routes (Section 4.4.2)
  │   ├── ingestion/             # Log file reading & pipeline orchestration
  │   ├── preprocessing/         # LogProcessor — parse, filter, normalise (Section 4.5.3)
  │   ├── detection/             # AnomalyDetector — Isolation Forest (Section 4.5.4)
  │   ├── models/                # User, LogEntry, AnomalyResult (Section 4.5)
  │   ├── dashboard/             # DashboardController + routes (Section 4.5.6)
  │   ├── database/              # PostgreSQL schema, connection management
  │   ├── app.py                 # Flask application factory
  │   ├── config.py              # Configuration constants
  │   └── requirements.txt
  ├── frontend/
  │   ├── templates/             # Jinja2 HTML templates (5 screens)
  │   └── static/                # CSS, JS
  ├── datasets/                  # Place NSL-KDD CSV files here
  ├── tests/
  │   ├── unit/                  # LogProcessor, AnomalyDetector, Auth tests
  │   └── integration/           # End-to-end pipeline + use case tests
  ├── run.py                     # Development server entry point
  └── pytest.ini
```

---

## 1. Installation

### Requirements
- Python 3.10 or higher
- pip

### Steps

```bash
# 1. Clone or extract the project
cd network-monitor

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r backend/requirements.txt
```

---

## 2. Dataset Setup (NSL-KDD)

The system is designed for the **NSL-KDD** dataset (FLAG-05).

```bash
# Download from:
# https://www.unb.ca/cic/datasets/nsl.html
# or: http://kdd.ics.uci.edu/databases/kddcup99/

# Place the file in the datasets/ folder:
cp KDDTrain+.txt datasets/KDDTrain+.csv
```

Any CSV file following the NSL-KDD column format will be accepted.

---

## 3. Running the Application

```bash
# From the project root:
python run.py
```

Open your browser at: **http://127.0.0.1:5000**

**Default credentials:**
- Username: `admin`
- Password: `admin123`

The PostgreSQL schema is created automatically on first run using `backend/database/schema.sql`.

---

## 4. Usage Workflow

1. **Login** at `/login` with administrator credentials.
2. **Upload** a dataset file at `/upload` (NSL-KDD CSV).
3. The system automatically:
   - Parses and preprocesses the log data (LogProcessor)
   - Runs Isolation Forest anomaly detection (AnomalyDetector)
   - Stores results in the PostgreSQL database
4. **View the Dashboard** at `/dashboard` for summary charts and statistics.
5. **Review Anomalies** at `/anomalies` — filter by severity or status.
6. **Inspect Detail** — click any anomaly for full explainable output.
7. **Update Status** — mark anomalies as REVIEWED or DISMISSED.

---

## 5. Running Tests

```bash
# All tests
pytest

# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# With coverage (if coverage is installed)
pip install pytest-cov
pytest --cov=backend tests/
```

---

## 6. Database Schema

The database is initialised automatically. Tables:

| Table | Source |
|-------|--------|
| `users` | Section 4.5.1 — User class |
| `raw_log_files` | Section 4.2.3 — Data layer |
| `log_entries` | Section 4.5.2 — LogEntry class |
| `anomaly_results` | Section 4.5.5 — AnomalyResult class |

Schema definition: `backend/database/schema.sql`

---

## 7. Configuration

Edit `backend/config.py` to adjust:

- `ANOMALY_CONTAMINATION` — expected anomaly proportion (default: 0.10)
- `SEVERITY_HIGH_THRESHOLD` — score threshold for HIGH severity (default: -0.10)
- `SEVERITY_MEDIUM_THRESHOLD` — score threshold for MEDIUM severity (default: 0.05)
- `ANOMALIES_PER_PAGE` — pagination size (default: 25)
- `SECRET_KEY` — change this for any non-local deployment

---

## 8. System Architecture

Three-Tier Web Architecture (Section 4.2):

```
[Browser] ← HTTP → [Flask Routes] ← → [Application Layer] ← → [PostgreSQL DB]
Presentation Layer   auth/dashboard     LogProcessor             Users
                                        AnomalyDetector          LogEntries
                                        DashboardController      AnomalyResults
```

No external APIs are used. All data processing is self-contained (Section 3.4.7).

---

## 9. Deployment Notes

Per Section 3.4.6, the system is designed for **local or controlled academic deployment**.

For any environment beyond development:
- Set `SECRET_KEY` to a strong random value via environment variable
- Set `SESSION_COOKIE_SECURE = True` if running with HTTPS
- Do **not** use `debug=True` in production

---

## Known Limitations (Table 4.1 reference)

- Real-time ingestion is not supported (batch file upload only)
- No advanced threat intelligence integration
- No enterprise-scale horizontal scaling
- NSL-KDD timestamps are sequential placeholders (dataset limitation)
- Severity thresholds (FLAG-06) are configurable defaults; tuning may be needed per dataset
