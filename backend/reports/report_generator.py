"""
backend/reports/report_generator.py
Report generation for processed log data and anomaly detection results.
Supports multiple formats: JSON, CSV, and HTML report views.
"""
import csv
import io
import json
from datetime import datetime
from typing import List, Dict, Optional
from backend.database.db import query_db


class ReportGenerator:
    """Generates reports from processed log data and anomaly results."""

    def __init__(self, user_id: Optional[int] = None):
        self.user_id = user_id
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_summary_report(self) -> Dict:
        """Generate a summary report of all system data."""
        total_entries = query_db(
            "SELECT COUNT(*) as c FROM log_entries", one=True
        )["c"]

        total_anomalies = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results", one=True
        )["c"]

        open_anomalies = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE status = 'OPEN'", one=True
        )["c"]

        high_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'HIGH'", one=True
        )["c"]

        medium_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'MEDIUM'", one=True
        )["c"]

        low_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'LOW'", one=True
        )["c"]

        total_files = query_db(
            "SELECT COUNT(*) as c FROM raw_log_files", one=True
        )["c"]

        protocols = query_db(
            "SELECT protocol_type, COUNT(*) as count FROM log_entries GROUP BY protocol_type"
        )

        event_types = query_db(
            """SELECT event_type, COUNT(*) as count FROM log_entries
               WHERE event_type != 'NORMAL' GROUP BY event_type ORDER BY count DESC"""
        )

        severity_dist = query_db(
            "SELECT severity, COUNT(*) as count FROM anomaly_results GROUP BY severity"
        )

        return {
            "report_type": "summary",
            "generated_at": self.generated_at,
            "period": "all_time",
            "summary": {
                "total_log_entries": total_entries,
                "total_anomalies": total_anomalies,
                "open_anomalies": open_anomalies,
                "total_files_processed": total_files,
                "resolution_rate": round(((total_anomalies - open_anomalies) / total_anomalies * 100) if total_anomalies > 0 else 0, 2),
            },
            "severity_breakdown": {
                "high": high_severity,
                "medium": medium_severity,
                "low": low_severity,
            },
            "protocol_distribution": [dict(row) for row in protocols],
            "event_type_distribution": [dict(row) for row in event_types[:10]],
            "severity_distribution": [dict(row) for row in severity_dist],
        }

    def generate_anomaly_report(self, severity: Optional[str] = None, status: Optional[str] = None) -> Dict:
        """Generate a detailed report of anomalies with optional filters."""
        where_parts = []
        args = []

        if severity:
            where_parts.append("ar.severity = ?")
            args.append(severity.upper())
        if status:
            where_parts.append("ar.status = ?")
            args.append(status.upper())

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        anomalies = query_db(
            f"""SELECT ar.result_id, ar.anomaly_score, ar.severity, ar.status,
                      ar.detection_time, ar.explanation,
                      le.log_id, le.timestamp, le.source_ip, le.destination_ip,
                      le.event_type, le.protocol_type, le.service,
                      le.src_bytes, le.dst_bytes, le.duration
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               {where_sql}
               ORDER BY ar.detection_time DESC""",
            args
        )

        return {
            "report_type": "anomaly_detail",
            "generated_at": self.generated_at,
            "filters": {
                "severity": severity,
                "status": status,
            },
            "total_anomalies": len(anomalies),
            "anomalies": [dict(row) for row in anomalies],
        }

    def generate_user_report(self) -> Dict:
        """Generate a report specific to the current user's data."""
        if not self.user_id:
            return {"error": "User ID required for user-specific report"}

        files_uploaded = query_db(
            "SELECT COUNT(*) as c FROM raw_log_files WHERE uploaded_by = ?",
            (self.user_id,), one=True
        )["c"]

        entries_processed = query_db(
            """SELECT COUNT(*) as c FROM log_entries le
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = ?""",
            (self.user_id,), one=True
        )["c"]

        anomalies_found = query_db(
            """SELECT COUNT(*) as c FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = ?""",
            (self.user_id,), one=True
        )["c"]

        open_issues = query_db(
            """SELECT COUNT(*) as c FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = ? AND ar.status = 'OPEN'""",
            (self.user_id,), one=True
        )["c"]

        user_files = query_db(
            """SELECT f.file_id, f.file_name, f.upload_time, f.row_count, f.processed
               FROM raw_log_files f
               WHERE f.uploaded_by = ?
               ORDER BY f.upload_time DESC""",
            (self.user_id,)
        )

        user_anomalies = query_db(
            """SELECT ar.result_id, ar.severity, ar.status, ar.detection_time,
                      le.event_type, le.protocol_type, le.source_ip
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = ?
               ORDER BY ar.detection_time DESC
               LIMIT 50""",
            (self.user_id,)
        )

        return {
            "report_type": "user_activity",
            "generated_at": self.generated_at,
            "user_id": self.user_id,
            "summary": {
                "files_uploaded": files_uploaded,
                "entries_processed": entries_processed,
                "anomalies_found": anomalies_found,
                "open_issues": open_issues,
            },
            "files": [dict(row) for row in user_files],
            "recent_anomalies": [dict(row) for row in user_anomalies],
        }

    def to_json(self, report_data: Dict) -> str:
        """Convert report data to JSON string."""
        return json.dumps(report_data, indent=2, default=str)

    def to_csv(self, report_data: Dict) -> str:
        """Convert report anomalies to CSV format."""
        output = io.StringIO()
        
        if report_data.get("report_type") == "anomaly_detail":
            anomalies = report_data.get("anomalies", [])
            if anomalies:
                fieldnames = [
                    "result_id", "log_id", "anomaly_score", "severity", "status",
                    "detection_time", "timestamp", "source_ip", "destination_ip",
                    "event_type", "protocol_type", "service", "src_bytes",
                    "dst_bytes", "duration", "explanation"
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for anomaly in anomalies:
                    writer.writerow(anomaly)
        
        elif report_data.get("report_type") == "user_activity":
            anomalies = report_data.get("recent_anomalies", [])
            if anomalies:
                fieldnames = ["result_id", "severity", "status", "detection_time", 
                             "event_type", "protocol_type", "source_ip"]
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for anomaly in anomalies:
                    writer.writerow(anomaly)
        
        return output.getvalue()

    def get_report_formats(self) -> List[Dict]:
        """Return available report types and formats."""
        return [
            {
                "type": "summary",
                "name": "System Summary Report",
                "description": "Overview of all processed data and anomaly statistics",
                "formats": ["json", "csv"]
            },
            {
                "type": "anomaly_detail",
                "name": "Anomaly Details Report",
                "description": "Detailed list of all detected anomalies with filtering options",
                "formats": ["json", "csv", "html"]
            },
            {
                "type": "user_activity",
                "name": "User Activity Report",
                "description": "Personal report of your uploaded files and detected anomalies",
                "formats": ["json", "csv", "html"]
            },
        ]
