"""
ingestion/log_reader.py
Handles reading and ingesting raw log/dataset files.
Source: Section 4.2.2 — data ingestion is a responsibility of the Application Layer.
Section 3.4.7 — data obtained from stored datasets and locally generated log files.
"""
import os
import logging
from typing import Tuple

from backend.database.db import execute_db, query_db
from backend.models.log_entry import LogEntry
from backend.preprocessing.log_processor import LogProcessor
from backend.detection.anomaly_detector import AnomalyDetector
from backend.config import Config

logger = logging.getLogger(__name__)


class LogIngestionService:
    """
    Orchestrates the full pipeline: file reading → preprocessing → detection → storage.
    Implements the workflow described in Section 4.3.
    """

    def __init__(self, app_config=None):
        cfg = app_config or Config()
        self._contamination = cfg.ANOMALY_CONTAMINATION
        self._random_state = cfg.ANOMALY_RANDOM_STATE
        self._high_thresh = cfg.SEVERITY_HIGH_THRESHOLD
        self._medium_thresh = cfg.SEVERITY_MEDIUM_THRESHOLD

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def ingest(
        self,
        file_content: str,
        file_name: str,
        uploaded_by: int
    ) -> Tuple[int, int, int]:
        """
        Full ingestion pipeline for a single file.
        Section 4.3 workflow: ingest → preprocess → detect → store.

        Returns:
            Tuple of (file_id, n_entries_stored, n_anomalies_found)
        """
        # 1. Register file in database
        file_id = self._register_file(file_name, uploaded_by)
        logger.info("Ingestion: registered file '%s' as file_id=%d", file_name, file_id)

        # 2. Preprocess — LogProcessor (Section 4.5.3)
        processor = LogProcessor(file_id=file_id)
        entries = processor.process(file_content)
        if not entries:
            logger.warning("Ingestion: no valid entries parsed from '%s'.", file_name)
            return file_id, 0, 0

        # 3. Store LogEntry records
        entry_ids = self._store_entries(entries)
        for entry, eid in zip(entries, entry_ids):
            entry.log_id = eid

        # Update file row count
        execute_db(
            "UPDATE raw_log_files SET row_count = ?, processed = 1 WHERE file_id = ?",
            (len(entries), file_id)
        )

        # 4. Anomaly Detection — AnomalyDetector (Section 4.5.4)
        detector = AnomalyDetector(
            contamination=self._contamination,
            random_state=self._random_state,
        )
        anomaly_results = detector.detect(
            entries,
            high_threshold=self._high_thresh,
            medium_threshold=self._medium_thresh,
        )

        # 5. Store AnomalyResult records (Section 4.5.5)
        self._store_anomalies(anomaly_results)

        logger.info(
            "Ingestion complete: %d entries, %d anomalies for file_id=%d",
            len(entries), len(anomaly_results), file_id
        )
        return file_id, len(entries), len(anomaly_results)

    # ──────────────────────────────────────────────────────────────
    # Private helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _register_file(file_name: str, uploaded_by: int) -> int:
        return execute_db(
            "INSERT INTO raw_log_files (file_name, uploaded_by, processed) VALUES (?, ?, 0)",
            (file_name, uploaded_by)
        )

    @staticmethod
    def _store_entries(entries) -> list:
        """Batch-insert LogEntry records and return their assigned log_ids."""
        ids = []
        for entry in entries:
            eid = execute_db(
                """INSERT INTO log_entries
                   (file_id, timestamp, source_ip, destination_ip, event_type, message,
                    duration, protocol_type, service, flag, src_bytes, dst_bytes,
                    land, wrong_fragment, urgent, original_label)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                entry.to_db_tuple()
            )
            ids.append(eid)
        return ids

    @staticmethod
    def _store_anomalies(results) -> None:
        """Batch-insert AnomalyResult records."""
        for result in results:
            execute_db(
                """INSERT INTO anomaly_results
                   (log_id, anomaly_score, severity, detection_time, status, explanation)
                   VALUES (?,?,?,?,?,?)""",
                result.to_db_tuple()
            )

    @staticmethod
    def allowed_file(filename: str) -> bool:
        """Validate file extension against allowed types (Section 1.4 scope)."""
        ext = os.path.splitext(filename)[1].lower()
        return ext in Config.UPLOAD_EXTENSIONS
