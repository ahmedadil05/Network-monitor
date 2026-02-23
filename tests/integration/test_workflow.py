"""
tests/integration/test_workflow.py
Integration tests — full pipeline and use case flows.
Source: Section 4.3 workflow, Section 3.4.5, Table 3.5.
"""
import unittest, sys, os, sqlite3, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.preprocessing.log_processor import LogProcessor, NSL_KDD_COLUMNS
from backend.detection.anomaly_detector import AnomalyDetector

def row(**kw):
    d = {"duration":"0","protocol_type":"tcp","service":"http","flag":"SF",
         "src_bytes":"500","dst_bytes":"1000","land":"0","wrong_fragment":"0",
         "urgent":"0","hot":"0","num_failed_logins":"0","logged_in":"1",
         "num_compromised":"0","root_shell":"0","su_attempted":"0","num_root":"0",
         "num_file_creations":"0","num_shells":"0","num_access_files":"0",
         "num_outbound_cmds":"0","is_host_login":"0","is_guest_login":"0",
         "count":"1","srv_count":"1","serror_rate":"0.0","srv_serror_rate":"0.0",
         "rerror_rate":"0.0","srv_rerror_rate":"0.0","same_srv_rate":"1.0",
         "diff_srv_rate":"0.0","srv_diff_host_rate":"0.0","dst_host_count":"1",
         "dst_host_srv_count":"1","dst_host_same_srv_rate":"1.0",
         "dst_host_diff_srv_rate":"0.0","dst_host_same_src_port_rate":"1.0",
         "dst_host_srv_diff_host_rate":"0.0","dst_host_serror_rate":"0.0",
         "dst_host_srv_serror_rate":"0.0","dst_host_rerror_rate":"0.0",
         "dst_host_srv_rerror_rate":"0.0","label":"normal","difficulty_level":"0"}
    d.update(kw)
    return ",".join(d[c] for c in NSL_KDD_COLUMNS)

csv = lambda *rows: "\n".join(rows)


class TestPreprocessDetectPipeline(unittest.TestCase):
    """Section 4.3: ingest → preprocess → detect → store"""

    def test_pipeline_produces_entries(self):
        entries = LogProcessor(1).process(csv(*[row() for _ in range(30)]))
        self.assertEqual(len(entries), 30)

    def test_pipeline_end_to_end(self):
        normal = [row() for _ in range(40)]
        bad = [row(label="neptune", src_bytes="9999999", wrong_fragment="5", land="1", urgent="3")]
        entries = LogProcessor(1).process(csv(*(normal + bad)))
        for i, e in enumerate(entries): e.log_id = i + 1
        results = AnomalyDetector(contamination=0.1).detect(entries)
        self.assertIsInstance(results, list)

    def test_result_log_ids_valid(self):
        entries = LogProcessor(1).process(csv(*[row() for _ in range(30)], row(src_bytes="5000000")))
        for i, e in enumerate(entries): e.log_id = i + 100
        results = AnomalyDetector(contamination=0.1).detect(entries)
        valid = {e.log_id for e in entries}
        for r in results:
            self.assertIn(r.log_id, valid)

    def test_all_entries_have_timestamps(self):
        entries = LogProcessor(1).process(csv(*[row() for _ in range(10)]))
        for e in entries:
            self.assertIsNotNone(e.timestamp)
            self.assertGreater(len(e.timestamp), 0)

    def test_multiple_protocols(self):
        entries = LogProcessor(1).process(csv(
            row(protocol_type="tcp"), row(protocol_type="udp"), row(protocol_type="icmp")
        ))
        self.assertEqual(len(entries), 3)
        self.assertEqual({e.protocol_type for e in entries}, {"tcp","udp","icmp"})

    def test_large_input(self):
        entries = LogProcessor(1).process(csv(*[row(src_bytes=str(100+i)) for i in range(500)]))
        self.assertEqual(len(entries), 500)
        for i, e in enumerate(entries): e.log_id = i + 1
        results = AnomalyDetector(contamination=0.1).detect(entries)
        self.assertGreater(len(results), 0)


class TestUseCases(unittest.TestCase):
    """Use case HTTP-level tests using Flask test client."""

    @classmethod
    def setUpClass(cls):
        from backend.config import Config
        cls.db_fd, cls.db_path = tempfile.mkstemp(suffix=".db")

        class TestConfig(Config):
            TESTING = True
            DATABASE_PATH = cls.db_path
            SECRET_KEY = "test-secret-key"

        from backend.app import create_app
        cls.flask_app = create_app(TestConfig)
        with cls.flask_app.app_context():
            from backend.database.db import get_db
            db = get_db()
            with open(TestConfig.DATABASE_SCHEMA) as f:
                db.executescript(f.read())
            db.commit()
            from backend.models.user import User
            User.create("testadmin", "testpass")

    @classmethod
    def tearDownClass(cls):
        os.close(cls.db_fd)
        os.unlink(cls.db_path)

    def setUp(self):
        self.client = self.flask_app.test_client()

    def _login(self):
        return self.client.post("/login", data={"username":"testadmin","password":"testpass"}, follow_redirects=True)

    def test_unauth_redirects_to_login(self):
        r = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_valid_login(self):
        r = self._login()
        self.assertEqual(r.status_code, 200)

    def test_invalid_login(self):
        r = self.client.post("/login", data={"username":"testadmin","password":"wrong"}, follow_redirects=True)
        self.assertIn(b"Invalid", r.data)

    def test_dashboard_after_login(self):
        self._login()
        r = self.client.get("/dashboard")
        self.assertEqual(r.status_code, 200)

    def test_anomalies_page(self):
        self._login()
        r = self.client.get("/anomalies")
        self.assertEqual(r.status_code, 200)

    def test_upload_page(self):
        self._login()
        r = self.client.get("/upload")
        self.assertEqual(r.status_code, 200)

    def test_logout(self):
        self._login()
        r = self.client.get("/logout", follow_redirects=False)
        self.assertEqual(r.status_code, 302)

    def test_chart_data_json(self):
        self._login()
        r = self.client.get("/api/chart-data")
        self.assertEqual(r.status_code, 200)
        self.assertIn("application/json", r.content_type)

if __name__ == "__main__":
    unittest.main()
