"""
tests/unit/test_anomaly_detector.py
Unit tests for AnomalyDetector — Section 3.4.5, Table 3.5.
"""
import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.models.log_entry import LogEntry
from backend.detection.anomaly_detector import AnomalyDetector

def entry(log_id=1, src_bytes=500, dst_bytes=1000, duration=0.0,
          protocol="tcp", service="http", flag="SF",
          land=0, wrong_fragment=0, urgent=0, label="normal"):
    return LogEntry(
        log_id=log_id, file_id=1,
        timestamp="2024-01-01 00:00:00",
        source_ip="10.0.0.1", destination_ip="192.168.1.1",
        event_type=label, message=f"entry {log_id}",
        duration=duration, protocol_type=protocol, service=service, flag=flag,
        src_bytes=src_bytes, dst_bytes=dst_bytes, land=land,
        wrong_fragment=wrong_fragment, urgent=urgent, original_label=label,
    )

def normal_entries(n=50):
    return [entry(log_id=i, src_bytes=200+i, dst_bytes=400+i) for i in range(n)]

def anomalous(log_id=999):
    return entry(log_id=log_id, src_bytes=9_999_999, dst_bytes=0, duration=0,
                 land=1, wrong_fragment=5, urgent=3, label="neptune")

class TestBasic(unittest.TestCase):
    def test_returns_list(self):
        self.assertIsInstance(AnomalyDetector().detect(normal_entries(20)), list)
    def test_empty_input(self):
        self.assertEqual(AnomalyDetector().detect([]), [])
    def test_result_has_required_fields(self):
        entries = normal_entries(30) + [anomalous()]
        results = AnomalyDetector(contamination=0.1).detect(entries)
        if results:
            r = results[0]
            self.assertIsNotNone(r.log_id)
            self.assertIsInstance(r.anomaly_score, float)
            self.assertIn(r.severity, ("HIGH","MEDIUM","LOW"))
            self.assertIsNotNone(r.detection_time)
            self.assertEqual(r.status, "OPEN")
    def test_explanation_non_empty(self):
        entries = normal_entries(30) + [anomalous()]
        results = AnomalyDetector(contamination=0.1).detect(entries)
        if results:
            self.assertGreater(len(results[0].explanation), 10)
    def test_log_ids_valid(self):
        entries = normal_entries(30) + [anomalous(log_id=777)]
        for i, e in enumerate(entries): e.log_id = i + 1
        results = AnomalyDetector(contamination=0.1).detect(entries)
        valid = {e.log_id for e in entries}
        for r in results:
            self.assertIn(r.log_id, valid)

class TestSeverity(unittest.TestCase):
    def _sev(self, score): return AnomalyDetector._classify_severity(score, -0.10, 0.05)
    def test_high(self):   self.assertEqual(self._sev(-0.5), "HIGH")
    def test_medium(self): self.assertEqual(self._sev(-0.05), "MEDIUM")
    def test_low(self):    self.assertEqual(self._sev(0.10), "LOW")
    def test_valid_values(self):
        for s in [-0.5,-0.1,0.0,0.1]:
            self.assertIn(self._sev(s), ("HIGH","MEDIUM","LOW"))

class TestExplainability(unittest.TestCase):
    def test_land_in_explanation(self):
        e = entry(land=1)
        exp = AnomalyDetector._explain(e, -0.5, "HIGH")
        self.assertIn("land", exp.lower())
    def test_high_src_bytes(self):
        e = entry(src_bytes=5_000_000)
        exp = AnomalyDetector._explain(e, -0.4, "HIGH")
        self.assertIn("source bytes", exp.lower())
    def test_wrong_fragment(self):
        e = entry(wrong_fragment=3)
        exp = AnomalyDetector._explain(e, -0.3, "MEDIUM")
        self.assertIn("fragment", exp.lower())
    def test_always_non_empty(self):
        self.assertGreater(len(AnomalyDetector._explain(entry(), -0.2, "MEDIUM")), 0)

if __name__ == "__main__":
    unittest.main()
