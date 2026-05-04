"""
models/log_entry.py
LogEntry class — Source: Section 4.5.2 of the project document.
Attributes: timestamp, source_ip, destination_ip, event_type, message
'This class serves as the fundamental data structure for analysis and storage.'
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LogEntry:
    """
    Represents a single preprocessed log record.
    Source: Section 4.5.2 — fundamental data structure for analysis and storage.
    """
    # Core attributes from Section 4.5.2
    timestamp: str
    source_ip: str
    destination_ip: str
    event_type: str
    message: str

    # Extended network attributes (from Appendix B / Section 3.3.1 dataset attributes)
    # These form the feature vector for anomaly detection
    duration: float = 0.0
    protocol_type: str = "tcp"
    service: str = "other"
    flag: str = "SF"
    src_bytes: int = 0
    dst_bytes: int = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0
    original_label: str = "unknown"

    # Database identity (None before INSERT)
    log_id: Optional[int] = None
    file_id: Optional[int] = None

    def to_feature_dict(self):
        """
        Return the numerical/encoded attributes used by AnomalyDetector.
        Only numerical features are included; categorical encoding
        is handled by LogProcessor.
        """
        return {
            "duration": self.duration,
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "land": self.land,
            "wrong_fragment": self.wrong_fragment,
            "urgent": self.urgent,
        }

    def to_db_tuple(self):
        """Return values for INSERT INTO log_entries."""
        return (
            self.file_id,
            self.timestamp,
            self.source_ip,
            self.destination_ip,
            self.event_type,
            self.message,
            self.duration,
            self.protocol_type,
            self.service,
            self.flag,
            self.src_bytes,
            self.dst_bytes,
            self.land,
            self.wrong_fragment,
            self.urgent,
            self.original_label,
        )

    @classmethod
    def from_db_row(cls, row):
        """Reconstruct a LogEntry from a database row mapping."""
        return cls(
            log_id=row["log_id"],
            file_id=row["file_id"],
            timestamp=row["timestamp"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            event_type=row["event_type"],
            message=row["message"],
            duration=row["duration"] or 0.0,
            protocol_type=row["protocol_type"] or "tcp",
            service=row["service"] or "other",
            flag=row["flag"] or "SF",
            src_bytes=row["src_bytes"] or 0,
            dst_bytes=row["dst_bytes"] or 0,
            land=row["land"] or 0,
            wrong_fragment=row["wrong_fragment"] or 0,
            urgent=row["urgent"] or 0,
            original_label=row["original_label"] or "unknown",
        )

    def __repr__(self):
        return (
            f"<LogEntry id={self.log_id} ts={self.timestamp} "
            f"src={self.source_ip} dst={self.destination_ip} type={self.event_type}>"
        )
