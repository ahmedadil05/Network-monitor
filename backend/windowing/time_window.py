"""
backend/windowing/time_window.py
Time window aggregation for behavior-based anomaly detection.

Transforms raw log data into fixed time intervals, computing aggregate statistics
that characterize system behavior in each window. These windowed aggregates form
the basis for anomaly detection by enabling comparison of:
  - Normal vs. anomalous traffic volumes
  - Unusual communication patterns (new IPs, unusual protocols)
  - Sudden behavioral changes (spikes, drops)

Design principles:
  - Window-first: all analysis happens at window granularity, not per-log
  - Stateless: each window computed independently
  - Observable: detailed metrics and statistics per window
  - Configurable: support multiple window sizes and aggregation strategies
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any
from enum import Enum
from datetime import datetime, timedelta

import pandas as pd
import numpy as np


class EmptyWindowStrategy(Enum):
    """Strategy for handling empty time windows."""
    FILL = "fill"        # Insert rows with zero/null values for empty windows
    SKIP = "skip"        # Omit empty windows from result
    FORWARD_FILL = "forward_fill"  # Forward-fill last known values


class WindowSize(Enum):
    """Supported aggregation window sizes."""
    ONE_MINUTE = timedelta(minutes=1)
    FIVE_MINUTES = timedelta(minutes=5)
    TEN_MINUTES = timedelta(minutes=10)
    FIFTEEN_MINUTES = timedelta(minutes=15)
    THIRTY_MINUTES = timedelta(minutes=30)
    ONE_HOUR = timedelta(hours=1)
    ONE_DAY = timedelta(days=1)

    @property
    def seconds(self) -> int:
        return int(self.value.total_seconds())

    @property
    def label(self) -> str:
        """Human-readable label."""
        if self == WindowSize.ONE_MINUTE:
            return "1m"
        elif self == WindowSize.FIVE_MINUTES:
            return "5m"
        elif self == WindowSize.TEN_MINUTES:
            return "10m"
        elif self == WindowSize.FIFTEEN_MINUTES:
            return "15m"
        elif self == WindowSize.THIRTY_MINUTES:
            return "30m"
        elif self == WindowSize.ONE_HOUR:
            return "1h"
        elif self == WindowSize.ONE_DAY:
            return "1d"
        return "custom"


@dataclass
class WindowAggregates:
    """Aggregated statistics for a single time window."""
    # Temporal
    window_start: datetime
    window_end: datetime
    window_id: int = field(default=0)

    # Traffic volume
    event_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

    # Unique endpoints
    unique_sources: int = 0
    unique_destinations: int = 0
    unique_source_ips: Set[str] = field(default_factory=set)
    unique_dest_ips: Set[str] = field(default_factory=set)

    # Protocol distribution
    protocols: Dict[str, int] = field(default_factory=dict)  # {tcp: 100, udp: 50, ...}
    services: Dict[str, int] = field(default_factory=dict)   # {http: 80, ssh: 10, ...}

    # Event type distribution
    event_types: Dict[str, int] = field(default_factory=dict)  # {NORMAL: 95, ATTACK: 5, ...}

    # Connection quality
    avg_duration: float = 0.0
    max_duration: float = 0.0
    min_duration: float = 0.0

    # Flags and errors
    errors_count: int = 0  # Count of error flags
    land_attacks: int = 0  # Count where source==dest
    fragments: int = 0     # Count of fragmented packets

    # Metadata
    is_empty: bool = True
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for DataFrame."""
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "window_id": self.window_id,
            "event_count": self.event_count,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "unique_sources": self.unique_sources,
            "unique_destinations": self.unique_destinations,
            "avg_duration": self.avg_duration,
            "max_duration": self.max_duration,
            "min_duration": self.min_duration,
            "errors_count": self.errors_count,
            "land_attacks": self.land_attacks,
            "fragments": self.fragments,
            "is_empty": self.is_empty,
            "protocols_tcp": self.protocols.get("tcp", 0),
            "protocols_udp": self.protocols.get("udp", 0),
            "protocols_icmp": self.protocols.get("icmp", 0),
            "event_type_normal": self.event_types.get("NORMAL", 0),
            "event_type_attack": self.event_types.get("ATTACK", 0),
            "event_type_anomaly": self.event_types.get("ANOMALY", 0),
        }


class TimeWindowAggregator:
    """
    Aggregates raw log data into fixed time windows.

    Transforms a DataFrame of individual log entries into a DataFrame where each row
    represents system behavior during a time window. This enables:

    1. **Baseline Learning:** Normal windows establish baseline behavior (traffic volume,
       endpoint counts, protocol mix). Anomaly detectors learn these patterns.

    2. **Anomaly Detection:** Deviations from baseline (sudden spikes, new endpoints,
       unusual protocols) become detectable as outliers in the windowed data.

    3. **Temporal Context:** Windows preserve time ordering, enabling time-series analysis
       and detection of sustained anomalies (not just one-off events).

    4. **Dimensionality Reduction:** Aggregating thousands of logs into hundreds of windows
       makes anomaly detection computationally feasible and focuses on behavior, not details.

    Example:
        Raw logs (thousands):
          timestamp: 2024-01-01 00:00:01, src: 10.0.0.1, dst: 192.168.1.1, events: syn_flood
          timestamp: 2024-01-01 00:00:05, src: 10.0.0.2, dst: 192.168.1.2, events: normal
          ...

        Windowed data (1-minute intervals, 24 rows for 24 hours):
          window_start: 2024-01-01 00:00:00, event_count: 523, unique_sources: 12, unique_dests: 45
          window_start: 2024-01-01 00:01:00, event_count: 487, unique_sources: 10, unique_dests: 42
          ...

        Anomaly detection input: each row shows "what was the system like in this minute?"
    """

    def __init__(
        self,
        window_size: WindowSize = WindowSize.ONE_MINUTE,
        empty_strategy: EmptyWindowStrategy = EmptyWindowStrategy.FILL,
        timezone: str = "UTC",
    ):
        """
        Initialize the aggregator.

        Args:
            window_size: Time window duration (1m, 5m, 1h, etc.)
            empty_strategy: How to handle windows with no data
            timezone: Timezone for window boundaries (default UTC)
        """
        self.window_size = window_size
        self.empty_strategy = empty_strategy
        self.timezone = timezone
        self._windows: Dict[int, WindowAggregates] = {}

    def aggregate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Aggregate log data into time windows.

        Args:
            df: DataFrame with parsed logs (must have 'timestamp' column)

        Returns:
            DataFrame where each row is a time window with aggregates
        """
        if df.empty:
            return self._empty_result_dataframe()

        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Convert to UTC if needed
        if df["timestamp"].dt.tz is None:
            df["timestamp"] = df["timestamp"].dt.tz_localize("UTC")
        else:
            df["timestamp"] = df["timestamp"].dt.tz_convert("UTC")

        # Create windows
        self._windows = {}
        time_range = (df["timestamp"].min(), df["timestamp"].max())
        self._create_windows(time_range)

        # Aggregate data into windows
        for idx, row in df.iterrows():
            self._add_to_window(row)

        # Finalize windows
        for window_id in self._windows:
            self._windows[window_id].unique_sources = len(self._windows[window_id].unique_source_ips)
            self._windows[window_id].unique_destinations = len(self._windows[window_id].unique_dest_ips)

        # Handle empty windows
        if self.empty_strategy == EmptyWindowStrategy.SKIP:
            result_windows = [w for w in self._windows.values() if not w.is_empty]
        elif self.empty_strategy == EmptyWindowStrategy.FILL:
            result_windows = list(self._windows.values())
        elif self.empty_strategy == EmptyWindowStrategy.FORWARD_FILL:
            result_windows = self._forward_fill_windows()
        else:
            result_windows = list(self._windows.values())

        # Convert to DataFrame
        window_dicts = [w.to_dict() for w in sorted(result_windows, key=lambda w: w.window_start)]
        result_df = pd.DataFrame(window_dicts)

        return result_df

    def _create_windows(self, time_range: tuple) -> None:
        """Create window boundaries for the time range."""
        start_time = time_range[0].floor(f"{self.window_size.seconds}s")
        end_time = time_range[1].ceil(f"{self.window_size.seconds}s")

        window_id = 0
        current_time = start_time

        while current_time < end_time:
            window_end = current_time + self.window_size.value
            self._windows[window_id] = WindowAggregates(
                window_start=current_time,
                window_end=window_end,
                window_id=window_id,
            )
            window_id += 1
            current_time = window_end

    def _add_to_window(self, row: pd.Series) -> None:
        """Add a log entry to the appropriate window."""
        timestamp = row["timestamp"]
        window_id = self._find_window_id(timestamp)

        if window_id not in self._windows:
            return

        window = self._windows[window_id]
        window.is_empty = False

        # Event count
        window.event_count += 1

        # Traffic bytes
        if "src_bytes" in row:
            window.bytes_sent += int(row["src_bytes"]) if pd.notna(row["src_bytes"]) else 0
        if "dst_bytes" in row:
            window.bytes_received += int(row["dst_bytes"]) if pd.notna(row["dst_bytes"]) else 0

        # Unique endpoints
        if "source_ip" in row and pd.notna(row["source_ip"]):
            window.unique_source_ips.add(str(row["source_ip"]))
        if "destination_ip" in row and pd.notna(row["destination_ip"]):
            window.unique_dest_ips.add(str(row["destination_ip"]))

        # Protocols
        if "protocol_type" in row and pd.notna(row["protocol_type"]):
            protocol = str(row["protocol_type"]).lower()
            window.protocols[protocol] = window.protocols.get(protocol, 0) + 1

        # Services
        if "service" in row and pd.notna(row["service"]):
            service = str(row["service"]).lower()
            window.services[service] = window.services.get(service, 0) + 1

        # Event types
        if "event_type" in row and pd.notna(row["event_type"]):
            event_type = str(row["event_type"]).upper()
            window.event_types[event_type] = window.event_types.get(event_type, 0) + 1

        # Duration stats
        if "duration" in row and pd.notna(row["duration"]):
            duration = float(row["duration"])
            window.avg_duration = (window.avg_duration * (window.event_count - 1) + duration) / window.event_count
            window.max_duration = max(window.max_duration, duration)
            if window.min_duration == 0.0 or duration < window.min_duration:
                window.min_duration = duration

        # Error flags
        if "flag" in row and pd.notna(row["flag"]):
            flag = str(row["flag"]).upper()
            # S0, S1, S2, S3, RSTO, RSTR, RSTOS0 are error/unusual flags
            error_flags = {"S0", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "OTH"}
            if flag in error_flags:
                window.errors_count += 1

        # Land attacks (source == destination)
        if "land" in row and pd.notna(row["land"]):
            if int(row["land"]) == 1:
                window.land_attacks += 1

        # Fragmented packets
        if "wrong_fragment" in row and pd.notna(row["wrong_fragment"]):
            window.fragments += int(row["wrong_fragment"]) if pd.notna(row["wrong_fragment"]) else 0

    def _find_window_id(self, timestamp: datetime) -> int:
        """Find the window ID for a given timestamp."""
        for window_id, window in self._windows.items():
            if window.window_start <= timestamp < window.window_end:
                return window_id
        return -1

    def _forward_fill_windows(self) -> List[WindowAggregates]:
        """Forward fill empty windows with previous values."""
        sorted_windows = sorted(self._windows.values(), key=lambda w: w.window_start)
        result = []

        last_values = {
            "event_count": 0,
            "unique_sources": 0,
            "unique_destinations": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
        }

        for window in sorted_windows:
            if not window.is_empty:
                result.append(window)
                last_values = {
                    "event_count": window.event_count,
                    "unique_sources": window.unique_sources,
                    "unique_destinations": window.unique_destinations,
                    "bytes_sent": window.bytes_sent,
                    "bytes_received": window.bytes_received,
                }
            else:
                # Create filled window
                filled = WindowAggregates(
                    window_start=window.window_start,
                    window_end=window.window_end,
                    window_id=window.window_id,
                    event_count=last_values["event_count"],
                    unique_sources=last_values["unique_sources"],
                    unique_destinations=last_values["unique_destinations"],
                    bytes_sent=last_values["bytes_sent"],
                    bytes_received=last_values["bytes_received"],
                    is_empty=False,
                )
                result.append(filled)

        return result

    def _empty_result_dataframe(self) -> pd.DataFrame:
        """Return an empty DataFrame with correct schema."""
        return pd.DataFrame(
            columns=[
                "window_start", "window_end", "window_id", "event_count", "bytes_sent",
                "bytes_received", "unique_sources", "unique_destinations", "avg_duration",
                "max_duration", "min_duration", "errors_count", "land_attacks", "fragments",
                "is_empty", "protocols_tcp", "protocols_udp", "protocols_icmp",
                "event_type_normal", "event_type_attack", "event_type_anomaly",
            ]
        )


class BehaviorProfile:
    """
    Statistical profile of system behavior across multiple windows.

    Used to establish baseline and detect deviations:
      - mean_event_count, std_event_count: typical traffic volume
      - mean_unique_sources, std_unique_sources: typical endpoint count
      - percentile_95_events: threshold for "spike"
      - percentile_5_events: threshold for "drop"
    """

    def __init__(self, windowed_df: pd.DataFrame):
        """
        Initialize behavior profile from windowed data.

        Args:
            windowed_df: DataFrame with time-windowed aggregates
        """
        self.df = windowed_df
        self.stats = {}
        self._compute_stats()

    def _compute_stats(self) -> None:
        """Compute baseline statistics from windows."""
        numeric_cols = self.df.select_dtypes(include=[np.number]).columns

        for col in numeric_cols:
            if col == "window_id" or col == "is_empty":
                continue

            values = self.df[col].dropna()
            if len(values) == 0:
                continue

            self.stats[col] = {
                "mean": values.mean(),
                "std": values.std(),
                "median": values.median(),
                "min": values.min(),
                "max": values.max(),
                "p5": values.quantile(0.05),
                "p25": values.quantile(0.25),
                "p75": values.quantile(0.75),
                "p95": values.quantile(0.95),
            }

    def get_zscore(self, column: str, value: float) -> float:
        """
        Compute Z-score for a value relative to baseline.

        Z-score > 2 or < -2 indicates statistically significant deviation.
        """
        if column not in self.stats or self.stats[column]["std"] == 0:
            return 0.0

        mean = self.stats[column]["mean"]
        std = self.stats[column]["std"]
        return (value - mean) / std if std > 0 else 0.0

    def is_anomalous(self, window_dict: Dict[str, Any], threshold: float = 2.0) -> bool:
        """
        Detect if a window is anomalous based on Z-scores.

        Args:
            window_dict: Single window's aggregates (dict)
            threshold: Z-score threshold for anomaly (default 2.0 = 95% confidence)

        Returns:
            True if any metric deviates > threshold standard deviations
        """
        for col, value in window_dict.items():
            if col in self.stats and isinstance(value, (int, float)):
                zscore = self.get_zscore(col, value)
                if abs(zscore) > threshold:
                    return True
        return False

    def report(self) -> str:
        """Generate human-readable behavior profile report."""
        lines = ["Behavior Profile Report", "=" * 60]

        for col, stats in sorted(self.stats.items()):
            lines.append(f"\n{col}:")
            lines.append(f"  mean:   {stats['mean']:.2f}")
            lines.append(f"  median: {stats['median']:.2f}")
            lines.append(f"  std:    {stats['std']:.2f}")
            lines.append(f"  range:  [{stats['min']:.2f}, {stats['max']:.2f}]")
            lines.append(f"  p95:    {stats['p95']:.2f} (spike threshold)")
            lines.append(f"  p5:     {stats['p5']:.2f} (drop threshold)")

        return "\n".join(lines)
