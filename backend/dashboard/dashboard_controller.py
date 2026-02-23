"""
dashboard/dashboard_controller.py
DashboardController class — Source: Section 4.5.6 of the project document.
'Manages communication between the application layer and the presentation layer.'
'Retrieves processed data and anomaly results from the database and prepares
them for visualization.'
'Ensures that the user interface remains decoupled from backend logic.'
"""
import logging
from backend.database.db import query_db
from backend.config import Config

logger = logging.getLogger(__name__)


class DashboardController:
    """
    Retrieves and aggregates data for the web-based presentation layer.
    Source: Section 4.5.6.
    """

    # ──────────────────────────────────────────────────────────────
    # Dashboard summary data (Section 4.4.2 — 'View Dashboard')
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_summary() -> dict:
        """
        Return aggregated statistics for the main dashboard view.
        Section 4.4.2: 'summarised overview of system status and recent activity.'
        """
        total_logs = query_db(
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

        return {
            "total_log_entries": total_logs,
            "total_anomalies": total_anomalies,
            "open_anomalies": open_anomalies,
            "high_severity": high_severity,
            "medium_severity": medium_severity,
            "low_severity": low_severity,
            "total_files": total_files,
        }

    @staticmethod
    def get_recent_anomalies(limit: int = 10) -> list:
        """
        Return the most recently detected anomalies for dashboard display.
        Section 4.2.1: 'anomaly detection results' displayed on dashboard.
        """
        rows = query_db(
            """SELECT ar.result_id, ar.anomaly_score, ar.severity, ar.status,
                      ar.detection_time, ar.explanation,
                      le.timestamp, le.source_ip, le.destination_ip,
                      le.event_type, le.protocol_type, le.service
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               ORDER BY ar.detection_time DESC
               LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in rows]

    @staticmethod
    def get_severity_distribution() -> dict:
        """
        Return anomaly counts grouped by severity for chart rendering.
        Section 4.2.1: 'visualizations' on the dashboard.
        """
        rows = query_db(
            """SELECT severity, COUNT(*) as count
               FROM anomaly_results GROUP BY severity"""
        )
        return {row["severity"]: row["count"] for row in rows}

    @staticmethod
    def get_event_type_distribution(limit: int = 10) -> list:
        """Return top N event/attack types for visualization."""
        rows = query_db(
            """SELECT event_type, COUNT(*) as count
               FROM log_entries
               WHERE event_type != 'NORMAL'
               GROUP BY event_type
               ORDER BY count DESC
               LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in rows]

    @staticmethod
    def get_protocol_distribution() -> list:
        """Return log entry counts per protocol type for visualization."""
        rows = query_db(
            """SELECT protocol_type, COUNT(*) as count
               FROM log_entries GROUP BY protocol_type"""
        )
        return [dict(r) for r in rows]

    @staticmethod
    def get_timeline_data(days: int = 7) -> list:
        """
        Return daily anomaly counts for the last N days for timeline chart.
        Section 4.2.1: dashboards provide 'clear visual' information.
        """
        rows = query_db(
            """SELECT DATE(detection_time) as day, COUNT(*) as count
               FROM anomaly_results
               WHERE detection_time >= DATE('now', ?)
               GROUP BY day ORDER BY day ASC""",
            (f"-{days} days",)
        )
        return [dict(r) for r in rows]

    # ──────────────────────────────────────────────────────────────
    # Anomaly list (Section 4.4.2 — 'View Anomalies')
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_anomaly_list(page: int = 1, per_page: int = None,
                         severity: str = None, status: str = None) -> dict:
        """
        Paginated anomaly list with optional filters.
        Section 4.4.2: 'inspect detected anomalies along with relevant metadata
        such as timestamps and severity indicators.'
        """
        per_page = per_page or Config.ANOMALIES_PER_PAGE
        offset = (page - 1) * per_page

        # Build WHERE clause from filters
        where_parts = []
        args = []
        if severity:
            where_parts.append("ar.severity = ?")
            args.append(severity.upper())
        if status:
            where_parts.append("ar.status = ?")
            args.append(status.upper())

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        total_row = query_db(
            f"SELECT COUNT(*) as c FROM anomaly_results ar {where_sql}", args, one=True
        )
        total = total_row["c"] if total_row else 0

        rows = query_db(
            f"""SELECT ar.result_id, ar.anomaly_score, ar.severity, ar.status,
                       ar.detection_time, ar.explanation,
                       le.log_id, le.timestamp, le.source_ip, le.destination_ip,
                       le.event_type, le.protocol_type, le.service, le.flag,
                       le.src_bytes, le.dst_bytes
                FROM anomaly_results ar
                JOIN log_entries le ON ar.log_id = le.log_id
                {where_sql}
                ORDER BY ar.detection_time DESC
                LIMIT ? OFFSET ?""",
            args + [per_page, offset]
        )

        return {
            "items": [dict(r) for r in rows],
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": max(1, (total + per_page - 1) // per_page),
        }

    @staticmethod
    def get_anomaly_detail(result_id: int) -> dict:
        """
        Return full detail for a single anomaly result.
        Section 4.4.2: 'View Anomalies' use case with metadata.
        """
        row = query_db(
            """SELECT ar.result_id, ar.anomaly_score, ar.severity, ar.status,
                      ar.detection_time, ar.explanation,
                      le.log_id, le.timestamp, le.source_ip, le.destination_ip,
                      le.event_type, le.message, le.protocol_type, le.service,
                      le.flag, le.src_bytes, le.dst_bytes, le.duration,
                      le.land, le.wrong_fragment, le.urgent, le.original_label
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               WHERE ar.result_id = ?""",
            (result_id,), one=True
        )
        return dict(row) if row else None

    @staticmethod
    def update_anomaly_status(result_id: int, new_status: str) -> bool:
        """
        Allow administrator to update anomaly status (REVIEWED / DISMISSED).
        Section 4.4.1: administrator manages monitoring results.
        """
        valid_statuses = {"OPEN", "REVIEWED", "DISMISSED"}
        if new_status.upper() not in valid_statuses:
            return False
        from backend.database.db import execute_db
        execute_db(
            "UPDATE anomaly_results SET status = ? WHERE result_id = ?",
            (new_status.upper(), result_id)
        )
        return True

    # ──────────────────────────────────────────────────────────────
    # File / ingestion history
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def get_file_history() -> list:
        """Return list of all ingested files with their processing status."""
        rows = query_db(
            """SELECT f.file_id, f.file_name, f.upload_time, f.row_count,
                      f.processed, u.username as uploaded_by
               FROM raw_log_files f
               LEFT JOIN users u ON f.uploaded_by = u.user_id
               ORDER BY f.upload_time DESC"""
        )
        return [dict(r) for r in rows]
