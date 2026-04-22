"""
backend/windowing/behavioral_features.py
Behavioral feature extraction from time-windowed aggregates.

Extends WindowAggregates with derived features suitable for ML-based anomaly detection.
Each feature is carefully engineered to capture specific anomalous behaviors:

VOLUME-BASED FEATURES:
  - event_rate: Traffic volume intensity (events/min). Spikes indicate DDoS, floods.
  - error_rate: Connection quality degradation. High error rates suggest network attacks.
  - bytes_per_event: Payload size anomalies. Unusually large payloads = data exfiltration.

DIVERSITY FEATURES:
  - source_uniqueness: Ratio of unique sources to total events. Many IPs = scanning/botnet.
  - dest_uniqueness: Ratio of unique destinations. Lateral movement, multi-target attacks.
  - protocol_entropy: Diversity of protocols. Unusual mix indicates anomalies.
  - service_entropy: Diversity of services accessed. Unusual pattern = reconnaissance.

BEHAVIORAL FEATURES:
  - event_type_concentration: How dominated by one event type. Homogeneous attack traffic.
  - duration_variability: Coefficient of variation in connection durations.
    Low variability (many similar-length connections) = brute force, port scan.

ATTACK-SPECIFIC INDICATORS:
  - land_attack_ratio: Source == destination. Indicator of specific attack type.
  - fragment_ratio: Fragmented packets. Evasion technique, unusual in normal traffic.

BASELINE ANOMALIES:
  - connection_density: Unique endpoints per event. High density = many endpoints contacted.
  - error_type_concentration: Concentration of specific error flags.

All features are normalized to [0, 1] range or unbounded positive values suitable for:
  - Isolation Forest (no range requirements, sensitive to scale differences)
  - Z-score based detection (requires numeric values)
  - Neural networks (better with normalized features)
"""

from dataclasses import dataclass
from typing import Dict, Optional, List
import numpy as np
import logging

logger = logging.getLogger(__name__)


def safe_divide(numerator: float, denominator: float, default: float = 0.0) -> float:
    """Safely compute numerator/denominator, handling division by zero."""
    return numerator / denominator if denominator > 0 else default


def entropy(counts: Dict[str, int]) -> float:
    """
    Compute Shannon entropy of a distribution.

    Entropy measures diversity:
      - 0 = all events are one type (max concentration)
      - log(n) = events uniformly distributed across n types (max entropy)

    Example:
      - 100% TCP: entropy = 0 (no diversity, suspicious)
      - 50% TCP, 50% UDP: entropy = 0.693 (balanced, normal)
    """
    if not counts or sum(counts.values()) == 0:
        return 0.0

    total = sum(counts.values())
    probabilities = [count / total for count in counts.values() if count > 0]

    # Shannon entropy: -sum(p_i * log(p_i))
    entropy_val = -sum(p * np.log(p) for p in probabilities if p > 0)
    return float(entropy_val)


def coefficient_of_variation(values: List[float]) -> float:
    """
    Compute coefficient of variation (CV = std / mean).

    CV measures relative variability:
      - CV ≈ 0: Values are very similar (low variability)
      - CV > 1: High variability relative to mean

    Example:
      - 100 sec, 101 sec, 99 sec: CV ≈ 0.01 (very consistent = brute force)
      - 1 sec, 100 sec, 1000 sec: CV > 1 (highly variable = normal)
    """
    if not values or len(values) < 2:
        return 0.0

    values = [v for v in values if v > 0]
    if not values:
        return 0.0

    mean = np.mean(values)
    if mean == 0:
        return 0.0

    std = np.std(values)
    return float(std / mean)


@dataclass
class BehavioralFeatures:
    """Derived behavioral features from a WindowAggregates for anomaly detection."""

    # ─────────────────────────────────────────────────────────────────────────
    # VOLUME-BASED FEATURES
    # ─────────────────────────────────────────────────────────────────────────

    event_rate: float = 0.0
    """
    Events per minute (normalized to 1-minute window).
    Detects: DDoS attacks, traffic spikes, sudden increases in volume.
    Range: [0, ∞)
    Baseline: Varies by network, typically 10-1000 events/min
    Anomaly: > 3x mean indicates potential flood attack
    """

    error_rate: float = 0.0
    """
    Proportion of events with error flags (errors_count / event_count).
    Detects: Connection failures, access denials, unusual connection states.
    Range: [0, 1]
    Baseline: Typically < 0.05 (< 5% error rate in normal networks)
    Anomaly: > 0.2 (20% errors) suggests network issues or attacks
    """

    bytes_per_event: float = 0.0
    """
    Average bytes transferred per event (total_bytes / event_count).
    Detects: Unusually large payloads, data exfiltration, file transfers.
    Range: [0, ∞)
    Baseline: Typically 100-10000 bytes/event depending on application
    Anomaly: 10-100x above baseline suggests data exfiltration
    """

    # ─────────────────────────────────────────────────────────────────────────
    # DIVERSITY FEATURES (Ratios)
    # ─────────────────────────────────────────────────────────────────────────

    source_uniqueness: float = 0.0
    """
    Ratio of unique source IPs to total events.
    Detects: Network scanning, distributed attacks, botnet traffic.
    Range: [0, 1]
    Baseline: Typically 0.01-0.1 (1-10% unique sources)
    Anomaly: > 0.3 (30% unique sources) suggests port/network scan
    High values = many different sources, each doing few things (scanning behavior)
    """

    dest_uniqueness: float = 0.0
    """
    Ratio of unique destination IPs to total events.
    Detects: Lateral movement, multi-target attacks, network reconnaissance.
    Range: [0, 1]
    Baseline: Typically 0.05-0.2 (5-20% unique destinations)
    Anomaly: > 0.4 suggests internal lateral movement or attack spreading
    High values = events spread across many targets (attack spreading)
    """

    connection_density: float = 0.0
    """
    Unique endpoints (sources + destinations) per event.
    Detects: Concentrated vs. distributed attack patterns.
    Range: [0, 2]
    Baseline: Typically 0.1-0.3
    Anomaly: Close to 2.0 means almost every event involves new endpoints (rare in normal traffic)
    """

    # ─────────────────────────────────────────────────────────────────────────
    # ENTROPY-BASED FEATURES (Diversity in distributions)
    # ─────────────────────────────────────────────────────────────────────────

    protocol_entropy: float = 0.0
    """
    Shannon entropy of protocol distribution (TCP, UDP, ICMP, etc.).
    Detects: Unusual protocol mix, protocol-specific attacks.
    Range: [0, log(num_protocols)] ≈ [0, 1.1] for 3 protocols
    Baseline: For normal networks with TCP/UDP mix: 0.5-0.8
    Anomaly: Close to 0 = 100% one protocol (e.g., all ICMP flooding)
    Anomaly: High entropy with unusual protocols (e.g., all GRE) is suspicious
    """

    service_entropy: float = 0.0
    """
    Shannon entropy of service distribution (HTTP, SSH, DNS, etc.).
    Detects: Unusual service access patterns, reconnaissance activity.
    Range: [0, log(num_services)]
    Baseline: For normal networks: 0.5-1.5
    Anomaly: Close to 0 = accessing only 1-2 services (targeted attack)
    Anomaly: Very high = accessing many unusual services (reconnaissance scan)
    """

    # ─────────────────────────────────────────────────────────────────────────
    # VARIABILITY & CONCENTRATION FEATURES
    # ─────────────────────────────────────────────────────────────────────────

    duration_variability: float = 0.0
    """
    Coefficient of variation in connection durations.
    Detects: Brute force (many short connections), unusual connection patterns.
    Range: [0, ∞)
    Baseline: Typically 0.3-1.5 for normal traffic
    Anomaly: << 0.1 (< 0.1) = very uniform durations = brute force/port scan
    Anomaly: >> 2.0 = extremely varied durations = unusual behavior
    """

    event_type_concentration: float = 0.0
    """
    Dominance of most common event type (max_count / total).
    Detects: Homogeneous attack traffic vs. normal mixed behavior.
    Range: [0, 1]
    Baseline: Typically 0.6-0.9 (one type dominates but not overwhelmingly)
    Anomaly: > 0.95 = 95%+ one event type (pure attack traffic)
    High concentration = attack traffic looks uniform
    """

    error_type_concentration: float = 0.0
    """
    Dominance of most common error flag (max_error_count / errors_count).
    Detects: Specific error-based attacks (e.g., all S0 flags = half-open connections).
    Range: [0, 1]
    Baseline: Typically 0.3-0.8 (mixed error types)
    Anomaly: > 0.9 = 90%+ same error type (targeted attack using specific technique)
    """

    # ─────────────────────────────────────────────────────────────────────────
    # ATTACK-SPECIFIC INDICATORS
    # ─────────────────────────────────────────────────────────────────────────

    land_attack_ratio: float = 0.0
    """
    Proportion of land attack events (source IP == destination IP).
    Detects: Land attacks (packets sent to self), specific attack signatures.
    Range: [0, 1]
    Baseline: Should be 0 in normal networks (extremely rare)
    Anomaly: Any value > 0 is suspicious; > 0.01 (1%) is highly anomalous
    """

    fragment_ratio: float = 0.0
    """
    Proportion of fragmented packets (wrong_fragment flag).
    Detects: Packet fragmentation evasion, unusual packet structure.
    Range: [0, 1]
    Baseline: Should be very low (< 0.001) in normal networks
    Anomaly: > 0.01 (1%) suggests intentional fragmentation or evasion
    """

    # ─────────────────────────────────────────────────────────────────────────
    # DERIVED METRICS (combination of features)
    # ─────────────────────────────────────────────────────────────────────────

    polymorph_score: float = 0.0
    """
    Combined diversity metric (average of normalized entropies and uniqueness).
    Detects: Overall "polymorphism" - how varied vs. homogeneous the traffic is.
    Range: [0, 1]
    High score = diverse traffic (could be normal or scanning)
    Low score = homogeneous traffic (could be normal baseline or focused attack)
    Useful for detecting when traffic changes from normal pattern
    """

    stress_score: float = 0.0
    """
    Combined volume/intensity metric (event_rate + error_rate + fragment_ratio).
    Detects: Overall network stress, potential overload or attack condition.
    Range: [0, ∞)
    Useful for detecting when network is under unusual load
    """

    def to_dict(self) -> Dict[str, float]:
        """Convert all features to dictionary for ML pipelines."""
        return {
            # Volume features
            "event_rate": self.event_rate,
            "error_rate": self.error_rate,
            "bytes_per_event": self.bytes_per_event,
            # Diversity features
            "source_uniqueness": self.source_uniqueness,
            "dest_uniqueness": self.dest_uniqueness,
            "connection_density": self.connection_density,
            # Entropy features
            "protocol_entropy": self.protocol_entropy,
            "service_entropy": self.service_entropy,
            # Variability features
            "duration_variability": self.duration_variability,
            "event_type_concentration": self.event_type_concentration,
            "error_type_concentration": self.error_type_concentration,
            # Attack-specific indicators
            "land_attack_ratio": self.land_attack_ratio,
            "fragment_ratio": self.fragment_ratio,
            # Derived metrics
            "polymorph_score": self.polymorph_score,
            "stress_score": self.stress_score,
        }

    def to_feature_vector(self) -> np.ndarray:
        """Convert features to numpy array for sklearn models."""
        features = self.to_dict()
        return np.array([features[k] for k in sorted(features.keys())])

    @staticmethod
    def feature_names() -> List[str]:
        """Get ordered list of feature names for interpretation."""
        return sorted([
            "event_rate", "error_rate", "bytes_per_event",
            "source_uniqueness", "dest_uniqueness", "connection_density",
            "protocol_entropy", "service_entropy",
            "duration_variability", "event_type_concentration", "error_type_concentration",
            "land_attack_ratio", "fragment_ratio",
            "polymorph_score", "stress_score",
        ])


class BehavioralFeatureExtractor:
    """
    Computes behavioral features from WindowAggregates.

    This extractor transforms raw aggregates (counts, sets, distributions) into
    derived features suitable for ML models. Features capture different aspects
    of network behavior and help ML models distinguish between normal and anomalous
    patterns.

    Example:
        aggregates = WindowAggregates(...)  # from TimeWindowAggregator
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1)
        features = extractor.extract(aggregates)

        # Use features for ML:
        feature_vector = features.to_feature_vector()
        model.predict([feature_vector])
    """

    def __init__(self, window_duration_minutes: float = 1.0):
        """
        Initialize extractor.

        Args:
            window_duration_minutes: Duration of the aggregation window.
                Used to normalize event_rate to events-per-minute.
        """
        self.window_duration_minutes = window_duration_minutes

    def extract(self, aggregates) -> BehavioralFeatures:
        """
        Extract behavioral features from a WindowAggregates object.

        Args:
            aggregates: WindowAggregates instance from TimeWindowAggregator

        Returns:
            BehavioralFeatures with all derived features computed
        """
        features = BehavioralFeatures()

        # Skip feature extraction for empty windows
        if aggregates.is_empty or aggregates.event_count == 0:
            return features

        # ─────────────────────────────────────────────────────────────────
        # VOLUME-BASED FEATURES
        # ─────────────────────────────────────────────────────────────────

        # Event rate: events per minute
        features.event_rate = float(aggregates.event_count / self.window_duration_minutes)

        # Error rate: proportion of events with errors
        features.error_rate = safe_divide(
            aggregates.errors_count,
            aggregates.event_count
        )

        # Bytes per event: average payload size
        total_bytes = aggregates.bytes_sent + aggregates.bytes_received
        features.bytes_per_event = safe_divide(total_bytes, aggregates.event_count)

        # ─────────────────────────────────────────────────────────────────
        # DIVERSITY FEATURES (Ratios)
        # ─────────────────────────────────────────────────────────────────

        # Source uniqueness: how many different source IPs are involved
        features.source_uniqueness = safe_divide(
            aggregates.unique_sources,
            aggregates.event_count
        )

        # Destination uniqueness: how many different target IPs
        features.dest_uniqueness = safe_divide(
            aggregates.unique_destinations,
            aggregates.event_count
        )

        # Connection density: unique endpoints per event
        total_unique_endpoints = (
            aggregates.unique_sources + aggregates.unique_destinations
        )
        features.connection_density = safe_divide(
            total_unique_endpoints,
            aggregates.event_count
        )

        # ─────────────────────────────────────────────────────────────────
        # ENTROPY-BASED FEATURES
        # ─────────────────────────────────────────────────────────────────

        # Protocol entropy: diversity of protocol types
        features.protocol_entropy = entropy(aggregates.protocols)

        # Service entropy: diversity of services accessed
        features.service_entropy = entropy(aggregates.services)

        # ─────────────────────────────────────────────────────────────────
        # VARIABILITY & CONCENTRATION FEATURES
        # ─────────────────────────────────────────────────────────────────

        # Duration variability: consistency of connection durations
        if aggregates.max_duration > 0:
            durations = [
                aggregates.min_duration,
                aggregates.avg_duration,
                aggregates.max_duration,
            ]
            features.duration_variability = coefficient_of_variation(durations)

        # Event type concentration: how dominated by one type
        if aggregates.event_types:
            max_count = max(aggregates.event_types.values())
            features.event_type_concentration = safe_divide(
                max_count,
                aggregates.event_count
            )

        # Error type concentration: for windows with errors
        if aggregates.errors_count > 0 and aggregates.protocols:
            # Approximate error concentration from protocol diversity
            # (since errors are not separately typed in current data structure)
            max_protocol_count = max(aggregates.protocols.values())
            features.error_type_concentration = safe_divide(
                max_protocol_count,
                aggregates.event_count
            )

        # ─────────────────────────────────────────────────────────────────
        # ATTACK-SPECIFIC INDICATORS
        # ─────────────────────────────────────────────────────────────────

        # Land attack ratio: events where source == destination
        features.land_attack_ratio = safe_divide(
            aggregates.land_attacks,
            aggregates.event_count
        )

        # Fragment ratio: fragmented packets
        features.fragment_ratio = safe_divide(
            aggregates.fragments,
            aggregates.event_count
        )

        # ─────────────────────────────────────────────────────────────────
        # DERIVED METRICS
        # ─────────────────────────────────────────────────────────────────

        # Polymorph score: overall diversity
        # Normalize entropies to [0, 1] range
        max_entropy = np.log(3)  # Approximate max entropy for 3 protocols
        norm_protocol_entropy = features.protocol_entropy / max_entropy if max_entropy > 0 else 0
        norm_service_entropy = features.service_entropy / (np.log(10) if np.log(10) > 0 else 1)

        features.polymorph_score = float(np.mean([
            features.source_uniqueness,
            features.dest_uniqueness,
            norm_protocol_entropy,
            norm_service_entropy,
        ]))

        # Stress score: overall intensity/load
        # Normalize to [0, 1] for combination
        # event_rate: divide by typical max (10000 events/min)
        # error_rate: already [0, 1]
        # fragment_ratio: already [0, 1]
        norm_event_rate = min(features.event_rate / 1000, 1.0)

        features.stress_score = float(np.mean([
            norm_event_rate,
            features.error_rate,
            features.fragment_ratio,
        ]))

        return features

    @staticmethod
    def feature_importance_guide() -> Dict[str, str]:
        """
        Return guidance on feature importance for different anomaly types.
        Helps interpret which features are most relevant for each attack.
        """
        return {
            "DDoS": "event_rate, source_uniqueness, connection_density, stress_score",
            "Port Scan": "dest_uniqueness, duration_variability, protocol_entropy, event_rate",
            "Brute Force": "duration_variability (LOW), error_rate, event_rate, service_entropy (LOW)",
            "Data Exfiltration": "bytes_per_event, connection_density, event_rate",
            "Reconnaissance": "service_entropy, source_uniqueness, connection_density",
            "Land Attack": "land_attack_ratio (HIGH)",
            "Fragmentation Evasion": "fragment_ratio (HIGH)",
            "Lateral Movement": "dest_uniqueness, source_uniqueness, event_type_concentration",
            "Normal Traffic": "polymorph_score (MEDIUM-HIGH), stress_score (LOW), event_rate (NORMAL)",
        }
