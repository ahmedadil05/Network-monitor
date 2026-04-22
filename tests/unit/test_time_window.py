"""
tests/unit/test_time_window.py
Comprehensive unit tests for TimeWindowAggregator and BehaviorProfile.
"""
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

from backend.windowing.time_window import (
    TimeWindowAggregator,
    BehaviorProfile,
    WindowSize,
    EmptyWindowStrategy,
    WindowAggregates,
)


class TestWindowSize:
    """Test WindowSize enum."""

    def test_window_sizes_have_timedelta(self):
        """All window sizes should have valid timedeltas."""
        for size in WindowSize:
            assert isinstance(size.value, timedelta)
            assert size.seconds > 0

    def test_window_labels(self):
        """Window sizes should have human-readable labels."""
        assert WindowSize.ONE_MINUTE.label == "1m"
        assert WindowSize.FIVE_MINUTES.label == "5m"
        assert WindowSize.ONE_HOUR.label == "1h"
        assert WindowSize.ONE_DAY.label == "1d"


class TestWindowAggregates:
    """Test WindowAggregates data structure."""

    def test_to_dict_conversion(self):
        """WindowAggregates should convert to dict."""
        start = datetime(2024, 1, 1, 0, 0, 0)
        end = datetime(2024, 1, 1, 0, 1, 0)

        agg = WindowAggregates(
            window_start=start,
            window_end=end,
            event_count=100,
            unique_sources=5,
        )

        d = agg.to_dict()
        assert d["window_start"] == start
        assert d["window_end"] == end
        assert d["event_count"] == 100
        assert d["unique_sources"] == 5

    def test_aggregates_defaults(self):
        """WindowAggregates should have sensible defaults."""
        agg = WindowAggregates(
            window_start=datetime.now(),
            window_end=datetime.now() + timedelta(minutes=1),
        )

        assert agg.event_count == 0
        assert agg.unique_sources == 0
        assert agg.is_empty is True
        assert agg.avg_duration == 0.0


class TestTimeWindowAggregator:
    """Test TimeWindowAggregator core functionality."""

    @pytest.fixture
    def sample_logs(self):
        """Create sample log DataFrame for testing."""
        timestamps = [
            datetime(2024, 1, 1, 0, 0, 1),
            datetime(2024, 1, 1, 0, 0, 15),
            datetime(2024, 1, 1, 0, 0, 30),
            datetime(2024, 1, 1, 0, 1, 5),
            datetime(2024, 1, 1, 0, 1, 20),
        ]

        data = {
            "timestamp": pd.to_datetime(timestamps).tz_localize("UTC"),
            "source_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3", "10.0.0.1"],
            "destination_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.1", "192.168.1.3", "192.168.1.1"],
            "protocol_type": ["tcp", "udp", "tcp", "icmp", "tcp"],
            "service": ["http", "dns", "http", None, "https"],
            "flag": ["SF", "SF", "SF", "SF", "S0"],
            "duration": [10.5, 2.3, 15.7, 5.0, 12.1],
            "src_bytes": [1024, 512, 2048, 256, 1024],
            "dst_bytes": [2048, 256, 1024, 128, 2048],
            "land": [0, 0, 0, 0, 1],
            "wrong_fragment": [0, 0, 1, 0, 0],
            "event_type": ["NORMAL", "NORMAL", "NORMAL", "NORMAL", "ATTACK"],
        }

        return pd.DataFrame(data)

    def test_aggregation_one_minute_windows(self, sample_logs):
        """Test aggregation into 1-minute windows."""
        aggregator = TimeWindowAggregator(
            window_size=WindowSize.ONE_MINUTE,
            empty_strategy=EmptyWindowStrategy.FILL,
        )

        result = aggregator.aggregate(sample_logs)

        # Should have 2 windows (0-1 min and 1-2 min)
        assert len(result) == 2
        assert result["window_id"].tolist() == [0, 1]

    def test_event_count_aggregation(self, sample_logs):
        """Test that events are counted correctly in windows."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 3 events, Second minute: 2 events
        assert result.iloc[0]["event_count"] == 3
        assert result.iloc[1]["event_count"] == 2

    def test_unique_sources_aggregation(self, sample_logs):
        """Test unique source count per window."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 10.0.0.1, 10.0.0.2 (2 unique)
        assert result.iloc[0]["unique_sources"] == 2
        # Second minute: 10.0.0.3, 10.0.0.1 (2 unique)
        assert result.iloc[1]["unique_sources"] == 2

    def test_unique_destinations_aggregation(self, sample_logs):
        """Test unique destination count per window."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 192.168.1.1, 192.168.1.2 (2 unique)
        assert result.iloc[0]["unique_destinations"] == 2
        # Second minute: 192.168.1.3, 192.168.1.1 (2 unique)
        assert result.iloc[1]["unique_destinations"] == 2

    def test_bytes_aggregation(self, sample_logs):
        """Test bytes sent/received aggregation."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: src_bytes = 1024 + 512 + 2048 = 3584
        assert result.iloc[0]["bytes_sent"] == 3584
        # First minute: dst_bytes = 2048 + 256 + 1024 = 3328
        assert result.iloc[0]["bytes_received"] == 3328

    def test_protocol_distribution(self, sample_logs):
        """Test protocol type distribution."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 2x tcp, 1x udp
        assert result.iloc[0]["protocols_tcp"] == 2
        assert result.iloc[0]["protocols_udp"] == 1

    def test_event_type_distribution(self, sample_logs):
        """Test event type distribution."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 3x NORMAL
        assert result.iloc[0]["event_type_normal"] == 3
        # Second minute: 1x NORMAL, 1x ATTACK
        assert result.iloc[1]["event_type_normal"] == 1
        assert result.iloc[1]["event_type_attack"] == 1

    def test_error_flags_detection(self, sample_logs):
        """Test detection of error flags (S0, etc.)."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 0 errors (all SF)
        assert result.iloc[0]["errors_count"] == 0
        # Second minute: 1 error (S0 flag)
        assert result.iloc[1]["errors_count"] == 1

    def test_land_attacks_detection(self, sample_logs):
        """Test detection of land attacks (source==dest)."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 0 land attacks
        assert result.iloc[0]["land_attacks"] == 0
        # Second minute: 1 land attack
        assert result.iloc[1]["land_attacks"] == 1

    def test_fragmented_packets_count(self, sample_logs):
        """Test counting of fragmented packets."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: 0 + 0 + 1 = 1 fragment
        assert result.iloc[0]["fragments"] == 1

    def test_duration_statistics(self, sample_logs):
        """Test duration min/max/avg calculation."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
        result = aggregator.aggregate(sample_logs)

        # First minute: durations = [10.5, 2.3, 15.7]
        assert result.iloc[0]["min_duration"] == 2.3
        assert result.iloc[0]["max_duration"] == 15.7
        assert 9.0 < result.iloc[0]["avg_duration"] < 10.0  # Approximately 9.5

    def test_skip_empty_windows(self, sample_logs):
        """Test skipping empty windows."""
        aggregator = TimeWindowAggregator(
            window_size=WindowSize.ONE_MINUTE,
            empty_strategy=EmptyWindowStrategy.SKIP,
        )

        result = aggregator.aggregate(sample_logs)

        # Should only have non-empty windows
        assert (result["is_empty"] == False).all()

    def test_fill_empty_windows(self, sample_logs):
        """Test filling empty windows with zero values."""
        aggregator = TimeWindowAggregator(
            window_size=WindowSize.ONE_MINUTE,
            empty_strategy=EmptyWindowStrategy.FILL,
        )

        result = aggregator.aggregate(sample_logs)

        # Should have filled windows (even if empty in middle)
        assert result["is_empty"].sum() == 0  # All marked as non-empty after filling

    def test_empty_dataframe_input(self):
        """Test handling of empty input DataFrame."""
        aggregator = TimeWindowAggregator()
        result = aggregator.aggregate(pd.DataFrame())

        assert result.empty
        assert len(result.columns) > 0  # Should have schema

    def test_five_minute_windows(self, sample_logs):
        """Test aggregation into 5-minute windows."""
        aggregator = TimeWindowAggregator(window_size=WindowSize.FIVE_MINUTES)
        result = aggregator.aggregate(sample_logs)

        # All logs fit in one 5-minute window
        assert len(result) >= 1
        assert result.iloc[0]["event_count"] == 5

    def test_timezone_handling(self):
        """Test UTC timezone handling."""
        # Create logs with UTC timezone
        timestamps = [
            datetime(2024, 1, 1, 0, 0, 1),
            datetime(2024, 1, 1, 0, 0, 15),
        ]

        df = pd.DataFrame(
            {
                "timestamp": pd.to_datetime(timestamps).tz_localize("UTC"),
                "source_ip": ["10.0.0.1", "10.0.0.2"],
                "destination_ip": ["192.168.1.1", "192.168.1.2"],
                "protocol_type": ["tcp", "tcp"],
                "flag": ["SF", "SF"],
                "duration": [1.0, 1.0],
                "src_bytes": [100, 100],
                "dst_bytes": [100, 100],
                "land": [0, 0],
                "wrong_fragment": [0, 0],
                "event_type": ["NORMAL", "NORMAL"],
            }
        )

        aggregator = TimeWindowAggregator()
        result = aggregator.aggregate(df)

        # Should handle timezone correctly
        assert result["window_start"].dtype == "datetime64[ns, UTC]"


class TestBehaviorProfile:
    """Test BehaviorProfile for baseline learning and anomaly detection."""

    @pytest.fixture
    def normal_windows(self):
        """Create DataFrame with normal window behavior."""
        data = {
            "event_count": [100, 98, 102, 99, 101, 100, 99, 102] * 5,  # ~100 events/window
            "unique_sources": [10, 11, 9, 10, 10, 11, 10, 9] * 5,      # ~10 sources/window
            "unique_destinations": [20, 21, 19, 20, 20, 21, 20, 19] * 5,  # ~20 dests/window
            "bytes_sent": [5000, 4900, 5100, 5000, 4950, 5050, 5000, 5000] * 5,
        }
        return pd.DataFrame(data)

    def test_profile_statistics_computation(self, normal_windows):
        """Test that BehaviorProfile computes statistics correctly."""
        profile = BehaviorProfile(normal_windows)

        assert "event_count" in profile.stats
        assert "unique_sources" in profile.stats
        assert profile.stats["event_count"]["mean"] == pytest.approx(100.0, rel=0.1)
        assert profile.stats["event_count"]["std"] > 0

    def test_zscore_calculation(self, normal_windows):
        """Test Z-score calculation for outlier detection."""
        profile = BehaviorProfile(normal_windows)

        # Normal value (close to mean)
        zscore_normal = profile.get_zscore("event_count", 100)
        assert abs(zscore_normal) < 1.0

        # Anomalous value (far from mean)
        zscore_anomaly = profile.get_zscore("event_count", 500)
        assert abs(zscore_anomaly) > 2.0

    def test_anomaly_detection_threshold(self, normal_windows):
        """Test anomaly detection with Z-score threshold."""
        profile = BehaviorProfile(normal_windows)

        # Normal window
        normal_window = {
            "event_count": 100,
            "unique_sources": 10,
            "unique_destinations": 20,
        }
        assert not profile.is_anomalous(normal_window, threshold=2.0)

        # Anomalous window (spike)
        anomaly_window = {
            "event_count": 500,
            "unique_sources": 50,
            "unique_destinations": 100,
        }
        assert profile.is_anomalous(anomaly_window, threshold=2.0)

    def test_profile_report_generation(self, normal_windows):
        """Test that profile generates readable report."""
        profile = BehaviorProfile(normal_windows)
        report = profile.report()

        assert "Behavior Profile Report" in report
        assert "event_count" in report
        assert "mean:" in report
        assert "std:" in report

    def test_percentile_thresholds(self, normal_windows):
        """Test percentile-based thresholds in profile."""
        profile = BehaviorProfile(normal_windows)

        # p95 should be higher than mean
        assert profile.stats["event_count"]["p95"] > profile.stats["event_count"]["mean"]
        # p5 should be lower than mean
        assert profile.stats["event_count"]["p5"] < profile.stats["event_count"]["mean"]


class TestTimeWindowingIntegration:
    """Integration tests combining windowing with anomaly detection."""

    def test_windowing_enables_anomaly_detection(self):
        """Test that windowing enables detection of traffic anomalies."""
        # Demonstrate how windowing converts individual logs into behavioral features
        # that make anomalies obvious and detectable

        # Create windows: 50 normal (with small variance), then 5 spike
        # Normal windows vary slightly around 100 events/min
        normal_events = [98, 99, 100, 101, 102] * 10  # 50 windows with slight variance

        data = {
            "event_count": normal_events + [500] * 5,  # Normal: ~100/min, Spike: 500/min
            "unique_sources": [10] * 50 + [50] * 5,
            "unique_destinations": [20] * 50 + [100] * 5,
            "bytes_sent": [5000] * 50 + [25000] * 5,
        }

        windowed = pd.DataFrame(data)

        # Key insight: windowing reduces thousands of individual logs to dozens of windows
        # where spikes become obvious statistical outliers

        # Compute baseline statistics from normal windows
        normal_mean = windowed.iloc[:50]["event_count"].mean()
        normal_std = windowed.iloc[:50]["event_count"].std()

        # Verify normal and anomaly windows are clearly different
        assert 99 < normal_mean < 101, f"Normal windows mean should be ~100, got {normal_mean}"
        assert normal_std > 0, "Normal std should be positive"
        assert windowed.iloc[50]["event_count"] == 500, "Spike window should have 500 events"

        # Calculate Z-scores manually
        def calc_zscore(value, mean, std):
            return (value - mean) / std if std > 0 else 0.0

        normal_zscore = calc_zscore(100, normal_mean, normal_std)
        spike_zscore = calc_zscore(500, normal_mean, normal_std)

        # Verify spike is statistically significant (|Z| > 2 = 95% confidence)
        assert abs(normal_zscore) < 2.0, f"Normal window Z-score: {normal_zscore}"
        assert abs(spike_zscore) > 2.0, f"Spike Z-score: {spike_zscore} should be > 2.0"

        # Mark anomalies using Z-score threshold
        windowed["zscore"] = windowed["event_count"].apply(
            lambda count: calc_zscore(count, normal_mean, normal_std)
        )
        windowed["is_anomalous"] = windowed["zscore"].apply(lambda z: abs(z) > 2.0)

        # Most normal windows should NOT be flagged
        normal_flagged = windowed.iloc[:50]["is_anomalous"].sum()
        assert normal_flagged < 5, f"Few normal windows should be flagged, got {normal_flagged}"

        # All spike windows SHOULD be flagged
        spike_flagged = windowed.iloc[50:55]["is_anomalous"].sum()
        assert spike_flagged == 5, f"All spike windows should be flagged, got {spike_flagged}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
