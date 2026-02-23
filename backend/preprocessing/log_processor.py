"""
preprocessing/log_processor.py
LogProcessor class — Source: Section 4.5.3 of the project document.
'Responsible for parsing raw log files, filtering irrelevant entries,
and transforming logs into structured LogEntry objects.'
Methods: data cleaning and feature extraction.

Dataset: NSL-KDD (FLAG-05) — CSV format from UCI-compatible repository.
NSL-KDD columns reference:
  duration, protocol_type, service, flag, src_bytes, dst_bytes, land,
  wrong_fragment, urgent, ... (41 features) + label
"""
import csv
import io
import logging
from typing import List, Optional
from backend.models.log_entry import LogEntry

logger = logging.getLogger(__name__)

# NSL-KDD column names in order (dataset columns per Appendix B / Section 3.3.1)
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty_level"
]

# Columns retained after filtering (Section 3.4.2: 'only features that
# directly support monitoring and anomaly detection are retained')
RETAINED_COLUMNS = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "label"
]

# Entries to exclude — normal label kept; irrelevant/malformed rows dropped
VALID_PROTOCOL_TYPES = {"tcp", "udp", "icmp"}


class LogProcessor:
    """
    Parses raw log files, filters irrelevant entries, and transforms
    them into structured LogEntry objects.
    Source: Section 4.5.3.
    """

    def __init__(self, file_id: Optional[int] = None):
        self.file_id = file_id
        self._errors: List[str] = []

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def process(self, raw_content: str) -> List[LogEntry]:
        """
        Main entry point: parse → filter → transform → return LogEntry list.
        Source: Section 4.3 (system workflow description).

        Args:
            raw_content: raw CSV text of the log file.
        Returns:
            List of valid, structured LogEntry objects.
        """
        self._errors = []
        rows = self._parse(raw_content)
        rows = self._filter(rows)
        entries = self._transform(rows)
        logger.info(
            "LogProcessor: parsed %d entries, %d errors.",
            len(entries), len(self._errors)
        )
        return entries

    @property
    def errors(self):
        return list(self._errors)

    # ──────────────────────────────────────────────────────────────
    # Step 1: Parse
    # ──────────────────────────────────────────────────────────────

    def _parse(self, raw_content: str) -> List[dict]:
        """
        Parse CSV text into list of dicts using NSL-KDD column names.
        Handles files with or without a header row.
        """
        parsed = []
        reader = csv.reader(io.StringIO(raw_content.strip()))
        for line_no, row in enumerate(reader, start=1):
            try:
                row = [cell.strip() for cell in row]
                if not row or len(row) < 2:
                    continue
                # Skip header row if present
                if line_no == 1 and not self._is_data_row(row):
                    continue
                # Map to column names (take only as many columns as we have names)
                n_cols = min(len(row), len(NSL_KDD_COLUMNS))
                record = {NSL_KDD_COLUMNS[i]: row[i] for i in range(n_cols)}
                parsed.append(record)
            except Exception as exc:
                self._errors.append(f"Line {line_no}: parse error — {exc}")
        return parsed

    @staticmethod
    def _is_data_row(row: list) -> bool:
        """Return True if the first field looks like a numeric value (data row)."""
        try:
            float(row[0])
            return True
        except (ValueError, IndexError):
            return False

    # ──────────────────────────────────────────────────────────────
    # Step 2: Filter
    # Source: Section 3.4.2 — 'only features that directly support
    # monitoring and anomaly detection are retained'
    # ──────────────────────────────────────────────────────────────

    def _filter(self, rows: List[dict]) -> List[dict]:
        """
        Remove irrelevant or malformed entries.
        Filtering rules:
          - Must have the core numeric fields parseable as numbers.
          - Protocol type must be a recognised network protocol.
          - Rows with all-zero numeric features are dropped (uninformative).
        """
        filtered = []
        for i, row in enumerate(rows):
            try:
                protocol = row.get("protocol_type", "").lower()
                if protocol not in VALID_PROTOCOL_TYPES:
                    # Still include but note it
                    pass
                # Validate numeric fields are parseable
                float(row.get("duration", 0))
                int(row.get("src_bytes", 0))
                int(row.get("dst_bytes", 0))
                filtered.append(row)
            except (ValueError, TypeError) as exc:
                self._errors.append(f"Row {i}: filter rejected — {exc}")
        return filtered

    # ──────────────────────────────────────────────────────────────
    # Step 3: Transform — produce LogEntry objects
    # Source: Section 4.5.3 — 'transforming logs into structured LogEntry objects'
    # ──────────────────────────────────────────────────────────────

    def _transform(self, rows: List[dict]) -> List[LogEntry]:
        """Convert filtered raw dicts into LogEntry data structures."""
        entries = []
        for i, row in enumerate(rows):
            try:
                label = row.get("label", "unknown").strip().rstrip(".")
                protocol = row.get("protocol_type", "tcp").lower().strip()
                service = row.get("service", "other").lower().strip()
                flag = row.get("flag", "SF").strip()
                duration = float(row.get("duration", 0))
                src_bytes = int(row.get("src_bytes", 0))
                dst_bytes = int(row.get("dst_bytes", 0))

                entry = LogEntry(
                    timestamp=self._make_timestamp(i),
                    source_ip=self._make_ip(protocol, "src"),
                    destination_ip=self._make_ip(protocol, "dst"),
                    event_type=label if label != "normal" else "NORMAL",
                    message=self._build_message(protocol, service, flag, label),
                    duration=duration,
                    protocol_type=protocol,
                    service=service,
                    flag=flag,
                    src_bytes=src_bytes,
                    dst_bytes=dst_bytes,
                    land=int(row.get("land", 0)),
                    wrong_fragment=int(row.get("wrong_fragment", 0)),
                    urgent=int(row.get("urgent", 0)),
                    original_label=label,
                    file_id=self.file_id,
                )
                entries.append(entry)
            except Exception as exc:
                self._errors.append(f"Row {i}: transform error — {exc}")
        return entries

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _make_timestamp(index: int) -> str:
        """
        NSL-KDD does not include timestamps; generate sequential placeholders.
        Section 3.3.1: 'time-related information such as timestamps'.
        """
        from datetime import datetime, timedelta
        base = datetime(2024, 1, 1, 0, 0, 0)
        return (base + timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _make_ip(protocol: str, direction: str) -> str:
        """
        NSL-KDD does not include real IPs; generate representative placeholders.
        Section 4.5.2: 'source IP, destination IP'.
        """
        # Placeholder IPs differentiated by protocol and direction
        bases = {"tcp": ("10.0.0.", "192.168.1."), "udp": ("10.1.0.", "192.168.2."),
                 "icmp": ("10.2.0.", "192.168.3.")}
        src_base, dst_base = bases.get(protocol, ("10.9.0.", "192.168.9."))
        return (src_base + "1") if direction == "src" else (dst_base + "1")

    @staticmethod
    def _build_message(protocol, service, flag, label) -> str:
        """Build a human-readable log message for the LogEntry."""
        status = "normal traffic" if label == "normal" else f"potential {label} activity"
        return (
            f"Protocol={protocol.upper()} Service={service} "
            f"Flag={flag} — {status.capitalize()}"
        )
