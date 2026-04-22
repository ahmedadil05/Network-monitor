"""
tests/unit/test_behavioral_features.py
Unit tests for behavioral feature extraction.

Tests verify that:
  1. Features are computed correctly from aggregates
  2. Edge cases (empty windows, zero values) are handled gracefully
  3. Features are numeric and suitable for ML models
  4. Feature ranges and meanings are correct
  5. Feature documentation is accurate
"""

import pytest
from datetime import datetime, timedelta
from backend.windowing.behavioral_features import (
    BehavioralFeatures,
    BehavioralFeatureExtractor,
    safe_divide,
    entropy,
    coefficient_of_variation,
)
from backend.windowing.time_window import (
    WindowAggregates,
    TimeWindowAggregator,
    WindowSize,
)
import numpy as np


class TestUtilityFunctions:
    """Test helper functions for feature extraction."""

    def test_safe_divide_normal(self):
        """Test normal division."""
        assert safe_divide(10, 2) == 5.0
        assert safe_divide(1, 3) == pytest.approx(0.333, rel=0.01)

    def test_safe_divide_by_zero(self):
        """Test division by zero returns default."""
        assert safe_divide(10, 0) == 0.0
        assert safe_divide(10, 0, default=100) == 100

    def test_entropy_uniform_distribution(self):
        """Test entropy with uniform distribution (maximum entropy)."""
        uniform = {"tcp": 50, "udp": 50}
        ent = entropy(uniform)
        assert ent == pytest.approx(np.log(2), rel=0.01)

    def test_entropy_single_type(self):
        """Test entropy with single type (zero entropy)."""
        single = {"tcp": 100}
        assert entropy(single) == pytest.approx(0.0, abs=1e-10)

    def test_entropy_three_types(self):
        """Test entropy with three types."""
        three = {"tcp": 34, "udp": 33, "icmp": 33}
        ent = entropy(three)
        # Expect approximately log(3) ≈ 1.099
        assert ent == pytest.approx(np.log(3), rel=0.02)

    def test_entropy_empty(self):
        """Test entropy with empty distribution."""
        assert entropy({}) == 0.0
        assert entropy({"a": 0}) == 0.0

    def test_coefficient_of_variation_uniform(self):
        """Test CV with uniform values (low variability)."""
        uniform = [100.0, 100.0, 100.0]
        cv = coefficient_of_variation(uniform)
        assert cv == pytest.approx(0.0, abs=1e-10)

    def test_coefficient_of_variation_varied(self):
        """Test CV with varied values."""
        varied = [10.0, 50.0, 100.0]
        cv = coefficient_of_variation(varied)
        # Should be > 0 for varying values
        assert cv > 0

    def test_coefficient_of_variation_empty(self):
        """Test CV with empty or edge cases."""
        assert coefficient_of_variation([]) == 0.0
        assert coefficient_of_variation([100.0]) == 0.0


class TestBehavioralFeaturesComputation:
    """Test behavioral feature extraction."""

    @pytest.fixture
    def normal_window(self):
        """Create a normal-looking window aggregate."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            event_count=100,
            bytes_sent=5000,
            bytes_received=10000,
            unique_sources=10,
            unique_destinations=20,
            unique_source_ips=set(f"10.0.0.{i}" for i in range(10)),
            unique_dest_ips=set(f"192.168.1.{i}" for i in range(20)),
            protocols={"tcp": 70, "udp": 30},
            services={"http": 50, "https": 30, "ssh": 20},
            event_types={"NORMAL": 95, "ANOMALY": 5},
            avg_duration=1.5,
            max_duration=3.0,
            min_duration=0.5,
            errors_count=2,
            land_attacks=0,
            fragments=0,
            is_empty=False,
        )
        return window

    @pytest.fixture
    def anomalous_window_ddos(self):
        """Create a DDoS-like window (high event rate, many sources)."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            event_count=5000,  # 5x normal
            bytes_sent=50000,
            bytes_received=100000,
            unique_sources=500,  # Many sources
            unique_destinations=5,  # Few targets (concentrated attack)
            unique_source_ips=set(f"10.0.{i}.{j}" for i in range(2) for j in range(250)),
            unique_dest_ips=set(f"192.168.1.{i}" for i in range(5)),
            protocols={"tcp": 5000},  # 100% TCP (no diversity)
            services={"http": 5000},
            event_types={"ATTACK": 5000},  # 100% attack type
            avg_duration=0.1,  # Very short
            max_duration=0.2,
            min_duration=0.1,
            errors_count=500,  # High error rate
            land_attacks=0,
            fragments=0,
            is_empty=False,
        )
        return window

    @pytest.fixture
    def anomalous_window_brute_force(self):
        """Create a brute force-like window (consistent short connections)."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            event_count=1000,
            bytes_sent=1000,
            bytes_received=1000,
            unique_sources=2,  # Few sources
            unique_destinations=1,  # Single target
            unique_source_ips={"10.0.0.1", "10.0.0.2"},
            unique_dest_ips={"192.168.1.100"},
            protocols={"tcp": 1000},  # 100% TCP
            services={"ssh": 1000},  # 100% SSH
            event_types={"NORMAL": 500, "ANOMALY": 500},
            avg_duration=0.5,  # All very similar
            max_duration=0.6,
            min_duration=0.4,
            errors_count=200,  # Many connection failures
            land_attacks=0,
            fragments=0,
            is_empty=False,
        )
        return window

    def test_empty_window(self):
        """Test feature extraction on empty window returns zeros."""
        empty_window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            is_empty=True,
            event_count=0,
        )
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(empty_window)

        # All features should be 0 for empty window
        assert features.event_rate == 0.0
        assert features.error_rate == 0.0
        assert features.bytes_per_event == 0.0

    def test_normal_window_features(self, normal_window):
        """Test feature extraction on normal window."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(normal_window)

        # Verify all features are computed
        assert features.event_rate == 100.0  # 100 events in 1 minute
        assert features.error_rate == pytest.approx(0.02)  # 2/100
        assert features.bytes_per_event == pytest.approx(150.0)  # 15000/100

        assert features.source_uniqueness == pytest.approx(0.1)  # 10/100
        assert features.dest_uniqueness == pytest.approx(0.2)  # 20/100
        assert features.connection_density == pytest.approx(0.3)  # 30/100

        # Should have protocol and service diversity (not 0 or 1)
        assert 0 < features.protocol_entropy < np.log(2)
        assert 0 < features.service_entropy

        # Normal features should be moderate
        assert features.polymorph_score > 0
        assert features.stress_score >= 0

    def test_ddos_window_features(self, anomalous_window_ddos):
        """Test feature extraction on DDoS-like window."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(anomalous_window_ddos)

        # DDoS characteristics
        assert features.event_rate == 5000.0  # Very high
        assert features.error_rate > 0.05  # High error rate
        assert features.source_uniqueness > 0.1  # Many sources
        assert features.protocol_entropy == pytest.approx(0.0, abs=0.01)  # 100% TCP
        assert features.event_type_concentration == pytest.approx(1.0)  # 100% attack

        # Duration should be very consistent (low variability)
        assert features.duration_variability < 0.5

    def test_brute_force_window_features(self, anomalous_window_brute_force):
        """Test feature extraction on brute force-like window."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(anomalous_window_brute_force)

        # Brute force characteristics
        assert features.source_uniqueness < 0.01  # Few sources
        assert features.dest_uniqueness < 0.01  # Single target
        assert features.protocol_entropy == pytest.approx(0.0, abs=0.01)  # 100% TCP
        assert features.service_entropy == pytest.approx(0.0, abs=0.01)  # 100% SSH
        assert features.error_rate > 0.1  # Many failures
        assert features.duration_variability < 0.5  # Consistent connections

    def test_feature_numeric_types(self, normal_window):
        """Verify all features are numeric (int or float)."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(normal_window)
        features_dict = features.to_dict()

        for name, value in features_dict.items():
            assert isinstance(value, (int, float)), f"{name} is not numeric"
            assert not np.isnan(value), f"{name} is NaN"
            assert np.isfinite(value), f"{name} is infinite"

    def test_feature_ranges(self, normal_window):
        """Verify features are in expected ranges."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(normal_window)

        # Ratio-based features should be in [0, 1]
        assert 0 <= features.error_rate <= 1
        assert 0 <= features.source_uniqueness <= 1
        assert 0 <= features.dest_uniqueness <= 1
        assert 0 <= features.land_attack_ratio <= 1
        assert 0 <= features.fragment_ratio <= 1
        assert 0 <= features.event_type_concentration <= 1
        assert 0 <= features.error_type_concentration <= 1

        # Entropy should be non-negative
        assert features.protocol_entropy >= 0
        assert features.service_entropy >= 0

        # Polymorph and stress scores should be in [0, 1] range
        assert 0 <= features.polymorph_score <= 1
        assert 0 <= features.stress_score <= 1

    def test_feature_to_dict(self, normal_window):
        """Test conversion to dictionary for ML pipelines."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(normal_window)
        features_dict = features.to_dict()

        # Should have all expected features
        expected_keys = {
            "event_rate", "error_rate", "bytes_per_event",
            "source_uniqueness", "dest_uniqueness", "connection_density",
            "protocol_entropy", "service_entropy",
            "duration_variability", "event_type_concentration", "error_type_concentration",
            "land_attack_ratio", "fragment_ratio",
            "polymorph_score", "stress_score",
        }
        assert set(features_dict.keys()) == expected_keys

    def test_feature_to_vector(self, normal_window):
        """Test conversion to numpy array for sklearn."""
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(normal_window)
        vector = features.to_feature_vector()

        assert isinstance(vector, np.ndarray)
        assert vector.shape == (15,)  # 15 features
        assert all(np.isfinite(vector))

    def test_feature_names_list(self):
        """Test that feature names list is correct."""
        names = BehavioralFeatures.feature_names()
        assert len(names) == 15
        assert all(isinstance(name, str) for name in names)
        assert len(set(names)) == len(names)  # All unique

    def test_importance_guide(self):
        """Test feature importance guidance for different attacks."""
        guide = BehavioralFeatureExtractor.feature_importance_guide()

        assert isinstance(guide, dict)
        assert "DDoS" in guide
        assert "Port Scan" in guide
        assert "Brute Force" in guide
        assert "Lateral Movement" in guide
        assert "Normal Traffic" in guide

        # Each entry should be a string describing relevant features
        for attack_type, features in guide.items():
            assert isinstance(features, str)
            assert len(features) > 0


class TestIntegrationWithTimeWindow:
    """Test integration with TimeWindowAggregator."""

    def test_extract_features_from_windowed_df(self):
        """Test extracting features from a complete windowed DataFrame."""
        import pandas as pd

        # Create sample log data
        logs = pd.DataFrame({
            "timestamp": pd.date_range("2024-01-01 00:00:00", periods=1000, freq="10ms"),
            "source_ip": ["10.0.0." + str(i % 10) for i in range(1000)],
            "destination_ip": ["192.168.1." + str(i % 50) for i in range(1000)],
            "protocol_type": ["tcp"] * 700 + ["udp"] * 300,
            "service": ["http"] * 500 + ["https"] * 300 + ["ssh"] * 200,
            "duration": [1.0 + (i % 5) * 0.2 for i in range(1000)],
            "src_bytes": [1000 + i for i in range(1000)],
            "dst_bytes": [2000 + i for i in range(1000)],
            "flag": ["S0"] * 50 + ["SF"] * 950,
            "event_type": ["NORMAL"] * 950 + ["ANOMALY"] * 50,
            "land": [0] * 1000,
            "wrong_fragment": [0] * 1000,
        })

        # Aggregate into windows
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        windowed_df = aggregator.aggregate(logs)

        # Extract features for each window
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)

        features_list = []
        for idx, row in windowed_df.iterrows():
            # Create window aggregate from row data
            window = WindowAggregates(
                window_start=row["window_start"],
                window_end=row["window_end"],
                event_count=int(row["event_count"]),
                bytes_sent=int(row["bytes_sent"]),
                bytes_received=int(row["bytes_received"]),
                unique_sources=int(row["unique_sources"]),
                unique_destinations=int(row["unique_destinations"]),
                avg_duration=row["avg_duration"],
                max_duration=row["max_duration"],
                min_duration=row["min_duration"],
                errors_count=int(row["errors_count"]),
                is_empty=row["is_empty"],
            )
            features = extractor.extract(window)
            features_list.append(features.to_dict())

        # Verify we got features for each window
        assert len(features_list) > 0

        # Convert to DataFrame for analysis
        features_df = pd.DataFrame(features_list)
        assert features_df.shape[1] == 15  # 15 features
        assert len(features_df) > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_window_with_zero_bytes(self):
        """Test window with no byte transfer."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            event_count=100,
            bytes_sent=0,
            bytes_received=0,
            unique_sources=10,
            unique_destinations=20,
            unique_source_ips=set(f"10.0.0.{i}" for i in range(10)),
            unique_dest_ips=set(f"192.168.1.{i}" for i in range(20)),
            is_empty=False,
        )
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(window)

        assert features.bytes_per_event == 0.0
        assert features.event_rate == 100.0

    def test_window_with_single_event(self):
        """Test window with only one event."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 1),
            event_count=1,
            bytes_sent=100,
            bytes_received=200,
            unique_sources=1,
            unique_destinations=1,
            unique_source_ips={"10.0.0.1"},
            unique_dest_ips={"192.168.1.1"},
            is_empty=False,
        )
        extractor = BehavioralFeatureExtractor(window_duration_minutes=1.0)
        features = extractor.extract(window)

        assert features.source_uniqueness == 1.0  # 1/1
        assert features.dest_uniqueness == 1.0  # 1/1
        assert features.bytes_per_event == 300.0  # (100+200)/1

    def test_window_with_small_duration(self):
        """Test extraction with smaller window duration."""
        window = WindowAggregates(
            window_start=datetime(2024, 1, 1, 0, 0),
            window_end=datetime(2024, 1, 1, 0, 0, 10),  # 10 seconds
            event_count=50,
            unique_sources=5,
            unique_destinations=10,
            is_empty=False,
        )
        extractor = BehavioralFeatureExtractor(window_duration_minutes=10.0 / 60.0)  # 10 seconds
        features = extractor.extract(window)

        # Event rate should be scaled to per-minute
        assert features.event_rate == pytest.approx(300.0)  # 50 * 60 / 10
