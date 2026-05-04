"""
models/anomaly_result.py
AnomalyResult class — Source: Section 4.5.5 of the project document.
Attributes: result_id, log_id, anomaly_score, detection_time, status
'Supports result tracking and visualization.'
"""
from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class AnomalyResult:
    """
    Stores information related to a detected anomaly.
    Source: Section 4.5.5 — 'associated log entry, anomaly score,
    detection time, and status.'
    """
    log_id: int
    anomaly_score: float          # Isolation Forest score (more negative = more anomalous)
    severity: str                 # HIGH / MEDIUM / LOW  (FLAG-06)
    explanation: str              # Human-readable reason (Section 4.6 explainability)

    detection_time: str = None
    status: str = "OPEN"         # OPEN / REVIEWED / DISMISSED
    result_id: Optional[int] = None

    def __post_init__(self):
        if self.detection_time is None:
            from datetime import datetime, timezone
            self.detection_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    def to_db_tuple(self):
        """Return values for INSERT INTO anomaly_results."""
        return (
            self.log_id,
            self.anomaly_score,
            self.severity,
            self.detection_time,
            self.status,
            self.explanation,
        )

    @classmethod
    def from_db_row(cls, row):
        """Reconstruct an AnomalyResult from a database row mapping."""
        return cls(
            result_id=row["result_id"],
            log_id=row["log_id"],
            anomaly_score=row["anomaly_score"],
            severity=row["severity"],
            detection_time=row["detection_time"],
            status=row["status"],
            explanation=row["explanation"],
        )

    def __repr__(self):
        return (
            f"<AnomalyResult id={self.result_id} log_id={self.log_id} "
            f"score={self.anomaly_score:.4f} severity={self.severity}>"
        )
