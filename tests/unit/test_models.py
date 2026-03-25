"""
tests/unit/test_models.py
Unit tests for data models: LogEntry, AnomalyResult, User
"""
import unittest
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.models.log_entry import LogEntry
from backend.models.anomaly_result import AnomalyResult


class TestLogEntry(unittest.TestCase):
    def test_create_minimal(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="NORMAL",
            message="Test message"
        )
        self.assertEqual(entry.timestamp, "2024-01-01 12:00:00")
        self.assertEqual(entry.event_type, "NORMAL")
        self.assertIsNone(entry.log_id)
        self.assertIsNone(entry.file_id)

    def test_create_full(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="neptune",
            message="Potential neptune attack",
            duration=1.5,
            protocol_type="tcp",
            service="http",
            flag="SF",
            src_bytes=1000,
            dst_bytes=2000,
            land=0,
            wrong_fragment=0,
            urgent=0,
            original_label="neptune",
            log_id=42,
            file_id=1,
        )
        self.assertEqual(entry.duration, 1.5)
        self.assertEqual(entry.protocol_type, "tcp")
        self.assertEqual(entry.service, "http")
        self.assertEqual(entry.src_bytes, 1000)
        self.assertEqual(entry.dst_bytes, 2000)
        self.assertEqual(entry.log_id, 42)
        self.assertEqual(entry.file_id, 1)

    def test_defaults(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="NORMAL",
            message="Test"
        )
        self.assertEqual(entry.duration, 0.0)
        self.assertEqual(entry.protocol_type, "tcp")
        self.assertEqual(entry.service, "other")
        self.assertEqual(entry.flag, "SF")
        self.assertEqual(entry.src_bytes, 0)
        self.assertEqual(entry.dst_bytes, 0)
        self.assertEqual(entry.land, 0)
        self.assertEqual(entry.original_label, "unknown")

    def test_to_feature_dict(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="NORMAL",
            message="Test",
            duration=5.0,
            src_bytes=100,
            dst_bytes=200,
            land=1,
            wrong_fragment=2,
            urgent=3,
        )
        features = entry.to_feature_dict()
        self.assertEqual(features["duration"], 5.0)
        self.assertEqual(features["src_bytes"], 100)
        self.assertEqual(features["dst_bytes"], 200)
        self.assertEqual(features["land"], 1)
        self.assertEqual(features["wrong_fragment"], 2)
        self.assertEqual(features["urgent"], 3)
        self.assertNotIn("protocol_type", features)
        self.assertNotIn("service", features)

    def test_to_db_tuple(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="NORMAL",
            message="Test message",
            duration=1.0,
            protocol_type="tcp",
            service="http",
            flag="SF",
            src_bytes=100,
            dst_bytes=200,
            land=0,
            wrong_fragment=0,
            urgent=0,
            original_label="normal",
            file_id=5,
        )
        tup = entry.to_db_tuple()
        self.assertEqual(tup[0], 5)  # file_id
        self.assertEqual(tup[1], "2024-01-01 12:00:00")  # timestamp
        self.assertEqual(tup[2], "192.168.1.1")  # source_ip
        self.assertEqual(tup[3], "10.0.0.1")  # destination_ip
        self.assertEqual(tup[4], "NORMAL")  # event_type
        self.assertEqual(len(tup), 16)

    def test_repr(self):
        entry = LogEntry(
            timestamp="2024-01-01 12:00:00",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            event_type="NORMAL",
            message="Test",
            log_id=10,
        )
        repr_str = repr(entry)
        self.assertIn("LogEntry", repr_str)
        self.assertIn("id=10", repr_str)


class TestAnomalyResult(unittest.TestCase):
    def test_create_minimal(self):
        result = AnomalyResult(
            log_id=1,
            anomaly_score=-0.5,
            severity="HIGH",
            explanation="Unusual traffic pattern detected"
        )
        self.assertEqual(result.log_id, 1)
        self.assertEqual(result.anomaly_score, -0.5)
        self.assertEqual(result.severity, "HIGH")
        self.assertEqual(result.status, "OPEN")
        self.assertIsNotNone(result.detection_time)
        self.assertIsNone(result.result_id)

    def test_create_full(self):
        result = AnomalyResult(
            log_id=42,
            anomaly_score=-0.25,
            severity="MEDIUM",
            explanation="High byte transfer",
            detection_time="2024-01-01 12:00:00",
            status="REVIEWED",
            result_id=100,
        )
        self.assertEqual(result.result_id, 100)
        self.assertEqual(result.detection_time, "2024-01-01 12:00:00")
        self.assertEqual(result.status, "REVIEWED")

    def test_detection_time_auto_generated(self):
        before = datetime.now().strftime("%Y-%m-%d")
        result = AnomalyResult(
            log_id=1,
            anomaly_score=-0.5,
            severity="HIGH",
            explanation="Test"
        )
        self.assertTrue(result.detection_time.startswith(before))

    def test_severity_values(self):
        for severity in ["HIGH", "MEDIUM", "LOW"]:
            result = AnomalyResult(
                log_id=1,
                anomaly_score=-0.5,
                severity=severity,
                explanation="Test"
            )
            self.assertEqual(result.severity, severity)

    def test_status_values(self):
        for status in ["OPEN", "REVIEWED", "DISMISSED"]:
            result = AnomalyResult(
                log_id=1,
                anomaly_score=-0.5,
                severity="HIGH",
                explanation="Test",
                status=status,
            )
            self.assertEqual(result.status, status)

    def test_to_db_tuple(self):
        result = AnomalyResult(
            log_id=5,
            anomaly_score=-0.123456,
            severity="HIGH",
            explanation="Test explanation",
            detection_time="2024-01-01 12:00:00",
            status="OPEN",
            result_id=99,
        )
        tup = result.to_db_tuple()
        self.assertEqual(tup[0], 5)  # log_id
        self.assertEqual(tup[1], -0.123456)  # anomaly_score
        self.assertEqual(tup[2], "HIGH")  # severity
        self.assertEqual(tup[3], "2024-01-01 12:00:00")  # detection_time
        self.assertEqual(tup[4], "OPEN")  # status
        self.assertEqual(tup[5], "Test explanation")  # explanation
        self.assertEqual(len(tup), 6)

    def test_repr(self):
        result = AnomalyResult(
            log_id=42,
            anomaly_score=-0.9876,
            severity="HIGH",
            explanation="Test",
            result_id=1,
        )
        repr_str = repr(result)
        self.assertIn("AnomalyResult", repr_str)
        self.assertIn("id=1", repr_str)
        self.assertIn("severity=HIGH", repr_str)


class TestLogEntryFromDbRow(unittest.TestCase):
    def test_from_db_row(self):
        class MockRow:
            def __init__(self):
                self._data = {
                    "log_id": 10,
                    "file_id": 2,
                    "timestamp": "2024-01-01 12:00:00",
                    "source_ip": "192.168.1.1",
                    "destination_ip": "10.0.0.1",
                    "event_type": "neptune",
                    "message": "Test message",
                    "duration": 5.5,
                    "protocol_type": "udp",
                    "service": "dns",
                    "flag": "S0",
                    "src_bytes": 500,
                    "dst_bytes": 0,
                    "land": 0,
                    "wrong_fragment": 0,
                    "urgent": 0,
                    "original_label": "neptune",
                }
            def __getitem__(self, key):
                return self._data.get(key)

        entry = LogEntry.from_db_row(MockRow())
        self.assertEqual(entry.log_id, 10)
        self.assertEqual(entry.file_id, 2)
        self.assertEqual(entry.timestamp, "2024-01-01 12:00:00")
        self.assertEqual(entry.source_ip, "192.168.1.1")
        self.assertEqual(entry.event_type, "neptune")
        self.assertEqual(entry.duration, 5.5)
        self.assertEqual(entry.protocol_type, "udp")
        self.assertEqual(entry.service, "dns")
        self.assertEqual(entry.src_bytes, 500)
        self.assertEqual(entry.dst_bytes, 0)

    def test_from_db_row_with_none_values(self):
        class MockRow:
            def __init__(self):
                self._data = {
                    "log_id": 1,
                    "file_id": None,
                    "timestamp": "2024-01-01 12:00:00",
                    "source_ip": "192.168.1.1",
                    "destination_ip": "10.0.0.1",
                    "event_type": "NORMAL",
                    "message": "Test",
                    "duration": None,
                    "protocol_type": None,
                    "service": None,
                    "flag": None,
                    "src_bytes": None,
                    "dst_bytes": None,
                    "land": None,
                    "wrong_fragment": None,
                    "urgent": None,
                    "original_label": None,
                }
            def __getitem__(self, key):
                return self._data.get(key)

        entry = LogEntry.from_db_row(MockRow())
        self.assertEqual(entry.duration, 0.0)
        self.assertEqual(entry.protocol_type, "tcp")
        self.assertEqual(entry.service, "other")
        self.assertEqual(entry.flag, "SF")
        self.assertEqual(entry.src_bytes, 0)
        self.assertEqual(entry.dst_bytes, 0)
        self.assertEqual(entry.original_label, "unknown")


class TestAnomalyResultFromDbRow(unittest.TestCase):
    def test_from_db_row(self):
        class MockRow:
            def __init__(self):
                self._data = {
                    "result_id": 55,
                    "log_id": 10,
                    "anomaly_score": -0.789,
                    "severity": "MEDIUM",
                    "detection_time": "2024-01-01 12:00:00",
                    "status": "REVIEWED",
                    "explanation": "Unusual pattern",
                }
            def __getitem__(self, key):
                return self._data.get(key)

        result = AnomalyResult.from_db_row(MockRow())
        self.assertEqual(result.result_id, 55)
        self.assertEqual(result.log_id, 10)
        self.assertEqual(result.anomaly_score, -0.789)
        self.assertEqual(result.severity, "MEDIUM")
        self.assertEqual(result.detection_time, "2024-01-01 12:00:00")
        self.assertEqual(result.status, "REVIEWED")
        self.assertEqual(result.explanation, "Unusual pattern")


if __name__ == "__main__":
    unittest.main()
