"""
detection/anomaly_detector.py
AnomalyDetector class — Source: Section 4.5.4 of the project document.
'Encapsulates the logic used to identify abnormal behavior.'
'Applies the selected anomaly detection technique to processed log data
and assigns anomaly scores or labels.'
'This separation allows the detection method to be modified or replaced
without affecting other system components.'

Algorithm: Isolation Forest (scikit-learn) — FLAG-04 resolution.
Rationale: unsupervised, handles unknown anomalies, interpretable scores,
low computational overhead, no labelled training data required.
Aligns with Section 2.3 (resource-efficient) and Section 2.7 (explainability).
"""
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Tuple

from backend.models.log_entry import LogEntry
from backend.models.anomaly_result import AnomalyResult

logger = logging.getLogger(__name__)

# Numerical features used for detection (Section 3.3.1 / Appendix B)
NUMERIC_FEATURES = [
    "duration", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent"
]

# Categorical features that are label-encoded before detection
CATEGORICAL_FEATURES = ["protocol_type", "service", "flag"]


class AnomalyDetector:
    """
    Applies Isolation Forest to preprocessed log data to identify
    abnormal network behaviour.
    Source: Section 4.5.4.
    """

    def __init__(self, contamination: float = 0.1, random_state: int = 42):
        """
        Args:
            contamination: Expected proportion of anomalies (FLAG-04).
            random_state: Reproducibility seed.
        """
        self.contamination = contamination
        self.random_state = random_state
        self._model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )
        self._label_encoders: dict = {}
        self._fitted = False

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def detect(
        self,
        entries: List[LogEntry],
        high_threshold: float = -0.10,
        medium_threshold: float = 0.05,
    ) -> List[AnomalyResult]:
        """
        Main detection entry point.
        Fits the model on the provided entries and returns AnomalyResult
        objects only for entries flagged as anomalous.

        Args:
            entries: Preprocessed LogEntry objects from LogProcessor.
            high_threshold: Isolation Forest score below which = HIGH severity.
            medium_threshold: Score below which = MEDIUM severity (FLAG-06).
        Returns:
            List of AnomalyResult for anomalous entries only.
        """
        if not entries:
            logger.warning("AnomalyDetector: received empty entry list.")
            return []

        X = self._build_feature_matrix(entries)
        self._model.fit(X)
        self._fitted = True

        # decision_function returns the anomaly score:
        # lower (more negative) = more anomalous
        scores = self._model.decision_function(X)
        predictions = self._model.predict(X)   # -1 = anomaly, 1 = normal

        results = []
        for i, (entry, score, pred) in enumerate(zip(entries, scores, predictions)):
            if pred == -1:   # Anomaly detected
                severity = self._classify_severity(score, high_threshold, medium_threshold)
                explanation = self._explain(entry, score, severity)
                result = AnomalyResult(
                    log_id=entry.log_id,
                    anomaly_score=float(score),
                    severity=severity,
                    explanation=explanation,
                )
                results.append(result)

        logger.info(
            "AnomalyDetector: %d anomalies found in %d entries.",
            len(results), len(entries)
        )
        return results

    # ──────────────────────────────────────────────────────────────
    # Feature Engineering
    # Source: Section 4.2.2 — 'feature extraction' in application layer
    # ──────────────────────────────────────────────────────────────

    def _build_feature_matrix(self, entries: List[LogEntry]) -> np.ndarray:
        """
        Build the numeric feature matrix for Isolation Forest.
        Categorical features are label-encoded.
        Numerical features are extracted directly.
        """
        rows = []
        for entry in entries:
            row = []
            # Numerical features
            row.append(float(entry.duration))
            row.append(float(entry.src_bytes))
            row.append(float(entry.dst_bytes))
            row.append(float(entry.land))
            row.append(float(entry.wrong_fragment))
            row.append(float(entry.urgent))

            # Categorical features (label-encoded per feature)
            for feat in CATEGORICAL_FEATURES:
                val = getattr(entry, feat, "other")
                if feat not in self._label_encoders:
                    self._label_encoders[feat] = LabelEncoder()
                row.append(val)  # store raw; encode after collecting all

            rows.append(row)

        # Columns 0..5: numeric; columns 6..8: categorical strings
        matrix = np.array(rows, dtype=object)
        n_numeric = len(NUMERIC_FEATURES)

        for col_offset, feat in enumerate(CATEGORICAL_FEATURES):
            col_idx = n_numeric + col_offset
            col_vals = matrix[:, col_idx].astype(str)
            if feat not in self._label_encoders or \
               not hasattr(self._label_encoders[feat], "classes_"):
                self._label_encoders[feat] = LabelEncoder()
                matrix[:, col_idx] = self._label_encoders[feat].fit_transform(col_vals)
            else:
                # Handle unseen labels gracefully
                known = set(self._label_encoders[feat].classes_)
                col_vals = np.where(
                    np.isin(col_vals, list(known)), col_vals, "other"
                )
                matrix[:, col_idx] = self._label_encoders[feat].transform(col_vals)

        return matrix.astype(float)

    # ──────────────────────────────────────────────────────────────
    # Severity Classification (FLAG-06)
    # Section 4.4.2: 'severity indicators'
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _classify_severity(
        score: float,
        high_threshold: float,
        medium_threshold: float
    ) -> str:
        """
        Map Isolation Forest score to a human-readable severity level.
        Thresholds defined in config.py and declared in FLAG-06.
        """
        if score < high_threshold:
            return "HIGH"
        elif score < medium_threshold:
            return "MEDIUM"
        else:
            return "LOW"

    # ──────────────────────────────────────────────────────────────
    # Explainability
    # Source: Section 4.6 — 'present anomaly detection results in a
    # transparent and interpretable manner'
    # Source: Section 2.7 — 'systems often operate as black-box solutions'
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def _explain(entry: LogEntry, score: float, severity: str) -> str:
        """
        Generate a human-readable explanation of why this entry was flagged.
        Section 4.6 — explainability is explicitly prioritised in design.
        """
        reasons = []

        if entry.src_bytes > 100_000:
            reasons.append(
                f"unusually high source bytes ({entry.src_bytes:,})"
            )
        if entry.dst_bytes > 100_000:
            reasons.append(
                f"unusually high destination bytes ({entry.dst_bytes:,})"
            )
        if entry.wrong_fragment > 0:
            reasons.append(
                f"{entry.wrong_fragment} wrong IP fragment(s) detected"
            )
        if entry.urgent > 0:
            reasons.append(
                f"{entry.urgent} urgent TCP packet(s) observed"
            )
        if entry.land == 1:
            reasons.append(
                "source and destination host/port are identical (LAND attack indicator)"
            )
        if entry.duration == 0 and entry.src_bytes > 0 and entry.dst_bytes == 0:
            reasons.append(
                "zero-duration connection with one-way data transfer (probe indicator)"
            )
        if entry.original_label not in ("normal", "unknown"):
            reasons.append(
                f"original dataset label indicates '{entry.original_label}' activity"
            )

        if not reasons:
            reasons.append(
                "statistical deviation from baseline network behaviour pattern"
            )

        reason_text = "; ".join(reasons).capitalize() + "."
        return (
            f"[{severity}] Anomaly score: {score:.4f}. "
            f"Flagged because: {reason_text} "
            f"Protocol: {entry.protocol_type.upper()}, "
            f"Service: {entry.service}, Flag: {entry.flag}."
        )
