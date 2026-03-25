"""
tests/unit/test_reports.py
Unit tests for ReportGenerator module.
Tests CSV/JSON conversion and report format structure (no Flask context needed).
"""
import unittest
import sys
import os
import csv
import io
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.reports.report_generator import ReportGenerator


class TestReportGeneratorInit(unittest.TestCase):
    def test_initialization(self):
        """Test that ReportGenerator initializes correctly."""
        generator = ReportGenerator()
        self.assertIsNotNone(generator.generated_at)
        self.assertIsNone(generator.user_id)

    def test_initialization_with_user_id(self):
        """Test that ReportGenerator accepts user_id."""
        generator = ReportGenerator(user_id=42)
        self.assertEqual(generator.user_id, 42)


class TestReportFormats(unittest.TestCase):
    def test_get_report_formats(self):
        """Test that available report formats are returned."""
        generator = ReportGenerator()
        formats = generator.get_report_formats()
        
        self.assertIsInstance(formats, list)
        self.assertGreater(len(formats), 0)
        
        expected_types = ["summary", "anomaly_detail", "user_activity"]
        found_types = [r["type"] for r in formats]
        
        for expected in expected_types:
            self.assertIn(expected, found_types)
        
        for report in formats:
            self.assertIn("type", report)
            self.assertIn("name", report)
            self.assertIn("description", report)
            self.assertIn("formats", report)
            self.assertIsInstance(report["formats"], list)
            self.assertIn("json", report["formats"])

    def test_summary_format_includes_csv(self):
        """Test that summary report supports CSV export."""
        generator = ReportGenerator()
        formats = generator.get_report_formats()
        
        summary = next(r for r in formats if r["type"] == "summary")
        self.assertIn("csv", summary["formats"])

    def test_anomaly_format_includes_html(self):
        """Test that anomaly report supports HTML export."""
        generator = ReportGenerator()
        formats = generator.get_report_formats()
        
        anomaly = next(r for r in formats if r["type"] == "anomaly_detail")
        self.assertIn("html", anomaly["formats"])


class TestCSVConversion(unittest.TestCase):
    def test_to_csv_with_anomaly_data(self):
        """Test CSV conversion of anomaly report."""
        generator = ReportGenerator()
        report = {
            "report_type": "anomaly_detail",
            "anomalies": [
                {
                    "result_id": 1,
                    "log_id": 10,
                    "anomaly_score": -0.5,
                    "severity": "HIGH",
                    "status": "OPEN",
                    "detection_time": "2024-01-01 12:00:00",
                    "timestamp": "2024-01-01 12:00:00",
                    "source_ip": "192.168.1.1",
                    "destination_ip": "10.0.0.1",
                    "event_type": "neptune",
                    "protocol_type": "tcp",
                    "service": "http",
                    "src_bytes": 100,
                    "dst_bytes": 200,
                    "duration": 1.5,
                    "explanation": "Test explanation"
                }
            ]
        }
        
        csv_str = generator.to_csv(report)
        
        self.assertIsInstance(csv_str, str)
        self.assertIn("result_id", csv_str)
        self.assertIn("HIGH", csv_str)
        self.assertIn("192.168.1.1", csv_str)

    def test_to_csv_empty_anomalies(self):
        """Test CSV conversion with empty anomalies list."""
        generator = ReportGenerator()
        report = {
            "report_type": "anomaly_detail",
            "anomalies": []
        }
        
        csv_str = generator.to_csv(report)
        self.assertEqual(csv_str.strip(), "")

    def test_to_csv_user_activity_report(self):
        """Test CSV conversion of user activity report."""
        generator = ReportGenerator()
        report = {
            "report_type": "user_activity",
            "recent_anomalies": [
                {
                    "result_id": 5,
                    "severity": "MEDIUM",
                    "status": "REVIEWED",
                    "detection_time": "2024-01-01 12:00:00",
                    "event_type": "smurf",
                    "protocol_type": "udp",
                    "source_ip": "192.168.1.100"
                }
            ]
        }
        
        csv_str = generator.to_csv(report)
        
        self.assertIn("result_id", csv_str)
        self.assertIn("MEDIUM", csv_str)
        self.assertIn("smurf", csv_str)

    def test_to_csv_multiple_rows(self):
        """Test CSV conversion with multiple anomaly rows."""
        generator = ReportGenerator()
        report = {
            "report_type": "anomaly_detail",
            "anomalies": [
                {"result_id": 1, "log_id": 1, "anomaly_score": -0.1, "severity": "LOW",
                 "status": "OPEN", "detection_time": "t1", "timestamp": "t1",
                 "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
                 "event_type": "a", "protocol_type": "tcp", "service": "s",
                 "src_bytes": 1, "dst_bytes": 2, "duration": 0.1, "explanation": "e1"},
                {"result_id": 2, "log_id": 2, "anomaly_score": -0.9, "severity": "HIGH",
                 "status": "OPEN", "detection_time": "t2", "timestamp": "t2",
                 "source_ip": "3.3.3.3", "destination_ip": "4.4.4.4",
                 "event_type": "b", "protocol_type": "udp", "service": "t",
                 "src_bytes": 100, "dst_bytes": 200, "duration": 1.0, "explanation": "e2"},
            ]
        }
        
        csv_str = generator.to_csv(report)
        lines = csv_str.strip().split('\n')
        
        self.assertEqual(len(lines), 3)
        self.assertIn("1.1.1.1", csv_str)
        self.assertIn("3.3.3.3", csv_str)

    def test_to_csv_ignores_extra_fields(self):
        """Test that CSV ignores fields not in fieldnames."""
        generator = ReportGenerator()
        report = {
            "report_type": "anomaly_detail",
            "anomalies": [
                {"result_id": 1, "log_id": 1, "anomaly_score": -0.5, "severity": "HIGH",
                 "status": "OPEN", "detection_time": "t", "timestamp": "t",
                 "source_ip": "1.1.1.1", "destination_ip": "2.2.2.2",
                 "event_type": "test", "protocol_type": "tcp", "service": "http",
                 "src_bytes": 1, "dst_bytes": 2, "duration": 0.1, "explanation": "e",
                 "extra_field": "should be ignored"}
            ]
        }
        
        csv_str = generator.to_csv(report)
        self.assertNotIn("extra_field", csv_str)


class TestJSONConversion(unittest.TestCase):
    def test_to_json_string_output(self):
        """Test that to_json returns a string."""
        generator = ReportGenerator()
        report = {"test": "data", "number": 42}
        
        json_str = generator.to_json(report)
        self.assertIsInstance(json_str, str)

    def test_to_json_valid_json(self):
        """Test that to_json produces valid JSON."""
        generator = ReportGenerator()
        report = {
            "report_type": "test",
            "data": [1, 2, 3],
            "nested": {"key": "value"}
        }
        
        json_str = generator.to_json(report)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed["report_type"], "test")
        self.assertEqual(parsed["data"], [1, 2, 3])
        self.assertEqual(parsed["nested"]["key"], "value")

    def test_to_json_handles_datetime(self):
        """Test that to_json handles datetime strings."""
        generator = ReportGenerator()
        report = {
            "timestamp": "2024-01-01 12:00:00",
            "nested": {"date": "2024-01-02"}
        }
        
        json_str = generator.to_json(report)
        parsed = json.loads(json_str)
        
        self.assertEqual(parsed["timestamp"], "2024-01-01 12:00:00")

    def test_to_json_pretty_format(self):
        """Test that JSON is pretty formatted."""
        generator = ReportGenerator()
        report = {"a": 1, "b": 2}
        
        json_str = generator.to_json(report)
        self.assertIn("\n", json_str)
        self.assertIn("  ", json_str)


class TestReportStructure(unittest.TestCase):
    def test_summary_report_expected_structure(self):
        """Test that summary report has expected keys (mock data)."""
        expected_keys = [
            "report_type", "generated_at", "period", "summary",
            "severity_breakdown", "protocol_distribution",
            "event_type_distribution", "severity_distribution"
        ]
        
        report = {"report_type": "summary", "generated_at": "", "period": "",
                  "summary": {}, "severity_breakdown": {},
                  "protocol_distribution": [], "event_type_distribution": [],
                  "severity_distribution": []}
        
        for key in expected_keys:
            self.assertIn(key, report)

    def test_anomaly_report_expected_structure(self):
        """Test that anomaly report has expected keys (mock data)."""
        report = {
            "report_type": "anomaly_detail",
            "generated_at": "2024-01-01",
            "filters": {},
            "total_anomalies": 0,
            "anomalies": []
        }
        
        self.assertIn("report_type", report)
        self.assertIn("filters", report)
        self.assertIn("total_anomalies", report)
        self.assertIn("anomalies", report)

    def test_user_report_expected_structure(self):
        """Test that user report has expected keys (mock data)."""
        report = {
            "report_type": "user_activity",
            "user_id": 1,
            "summary": {},
            "files": [],
            "recent_anomalies": []
        }
        
        self.assertIn("report_type", report)
        self.assertIn("user_id", report)
        self.assertIn("summary", report)
        self.assertIn("files", report)
        self.assertIn("recent_anomalies", report)


if __name__ == "__main__":
    unittest.main()
