# Time Window Aggregation Module Documentation

**Last Updated:** 2026-04-22  
**Status:** Production Ready (v1.0)  
**Test Coverage:** 26/26 tests passing ✅

## Overview

The time window aggregation module transforms parsed log data into fixed time intervals, computing aggregate statistics that characterize system behavior. This windowed representation enables **behavior-based anomaly detection** by converting millions of individual log entries into hundreds of behavioral snapshots.

**Key Insight:** Anomalies are deviations from *normal system behavior*, not deviations from individual log records. Time windows capture behavior.

---

## Why Time Windowing Enables Anomaly Detection

### Problem: Individual Logs Aren't Meaningful

```
Log entry:  10.0.0.1 → 192.168.1.1, TCP, 10 bytes, 5 seconds
Question:   Is this anomalous?
Answer:    🤷 Impossible to say without context
```

One connection tells you nothing. You need *context*.

### Solution: Windows Reveal Behavior

```
1-minute window:
  - Total events: 500 (vs. normal ~100)
  - New source IPs: 50 (vs. normal ~10)
  - New destination IPs: 100 (vs. normal ~20)

Question:  Is this anomalous?
Answer:   ✅ Clearly yes! 5x traffic spike + 5x new IPs = attack signature
```

**Windows transform the question from "is this log entry weird?" to "is this system behavior weird?"**

---

## How It Works

### 1. Parse Logs
```
Raw CSV: thousands of individual connection records
timestamp, source_ip, destination_ip, protocol, bytes, ...
```

### 2. Group by Time Window
```
Partition logs into fixed intervals (1-min, 5-min, 1-hour, etc.)
```

### 3. Aggregate Statistics
```
For each window, compute:
  - Traffic volume (event count, bytes sent/received)
  - Endpoint diversity (unique sources, unique destinations)
  - Protocol distribution (TCP, UDP, ICMP percentages)
  - Event type distribution (NORMAL, ATTACK, ANOMALY)
  - Connection quality (average/max/min duration)
  - Error indicators (land attacks, fragments, flags)
```

### 4. Return Behavior DataFrame
```
One row per time window, each row = "what was the system doing in this window?"
window_start  | event_count | unique_sources | unique_destinations | ...
2024-01-01... | 523         | 12             | 45                  | ...
2024-01-01... | 487         | 10             | 42                  | ...
```

### 5. Detect Anomalies
```
Learn baseline:
  mean_event_count ≈ 500, std ≈ 50
  mean_unique_sources ≈ 10, std ≈ 1

New window arrives:
  event_count = 2500 → Z-score = (2500-500)/50 = 40 → ANOMALY! 🚨
```

---

## Architecture

### WindowSize (Enum)

Supported aggregation granularities:

```python
WindowSize.ONE_MINUTE       # 1m windows (ideal for fast anomaly detection)
WindowSize.FIVE_MINUTES     # 5m windows (balanced granularity)
WindowSize.FIFTEEN_MINUTES  # 15m windows
WindowSize.ONE_HOUR         # 1h windows (useful for day/week patterns)
WindowSize.ONE_DAY          # 1d windows (long-term trends)
```

### EmptyWindowStrategy (Enum)

Strategies for handling time windows with no data:

- **SKIP** — Omit empty windows from results
  - Use when: Only care about active periods
  - Effect: Sparse time series with gaps

- **FILL** — Insert zero-valued rows for empty windows
  - Use when: Need complete time axis for plotting/analysis
  - Effect: Complete time series, easier to detect "silent" periods

- **FORWARD_FILL** — Repeat previous non-zero values
  - Use when: Assuming behavior continues unchanged during silence
  - Effect: Smooth interpolation between active periods

### WindowAggregates (DataClass)

Aggregated statistics for a single time window.

**Temporal Fields:**
```python
window_start: datetime      # Window begin (inclusive)
window_end: datetime        # Window end (exclusive)
window_id: int              # Sequential ID [0, 1, 2, ...]
```

**Traffic Volume:**
```python
event_count: int            # Total log entries in window
bytes_sent: int             # Total bytes source → destination
bytes_received: int         # Total bytes destination → source
```

**Endpoint Diversity:**
```python
unique_sources: int         # Count of unique source IPs
unique_destinations: int    # Count of unique destination IPs
```

**Protocol Distribution:**
```python
protocols: Dict[str, int]           # {tcp: 450, udp: 50, icmp: 0}
  protocols_tcp: int                # Quick access column
  protocols_udp: int
  protocols_icmp: int
```

**Event Type Distribution:**
```python
event_types: Dict[str, int]         # {NORMAL: 475, ATTACK: 25, ...}
  event_type_normal: int            # Quick access columns
  event_type_attack: int
  event_type_anomaly: int
```

**Connection Quality:**
```python
avg_duration: float         # Mean connection duration
max_duration: float         # Longest connection
min_duration: float         # Shortest connection
```

**Error Indicators:**
```python
errors_count: int           # Unusual flags (S0, S1, S2, S3, RSTO, etc.)
land_attacks: int           # Connections where source == destination
fragments: int              # Fragmented packets
```

### TimeWindowAggregator

Main class for aggregating logs into windows.

```python
aggregator = TimeWindowAggregator(
    window_size=WindowSize.ONE_MINUTE,
    empty_strategy=EmptyWindowStrategy.FILL,
    timezone="UTC"
)

result_df = aggregator.aggregate(parsed_logs_df)
```

**Input:**
- DataFrame with parsed logs (must have `timestamp` column)

**Output:**
- DataFrame where each row is a time window with aggregates
- Sorted by timestamp
- All numeric columns have correct types
- UTC timestamps

### BehaviorProfile

Learns baseline behavior from training windows and detects anomalies.

```python
# Learn baseline from normal logs
normal_windows = windowed_df[windowed_df['is_normal'] == True]
profile = BehaviorProfile(normal_windows)

# Detect anomalies in new data
for window in new_windows:
    is_anomalous = profile.is_anomalous(window.to_dict(), threshold=2.0)
```

**Key Methods:**

```python
profile.get_zscore(column: str, value: float) -> float
    # Compute standardized score (how many std devs from mean)
    # Z-score > 2.0 = top 2.5% (statistically significant)
    # Z-score > 3.0 = top 0.15% (highly significant)

profile.is_anomalous(window_dict: Dict, threshold: float) -> bool
    # True if ANY metric deviates > threshold std devs

profile.stats: Dict[str, Dict]
    # Raw statistics per metric
    # Keys: mean, std, median, min, max, p5, p25, p75, p95

profile.report() -> str
    # Human-readable baseline summary
```

---

## Usage Examples

### Example 1: Basic Windowing

```python
from backend.ingestion.log_data_loader import LogDataLoader
from backend.windowing.time_window import TimeWindowAggregator, WindowSize

# Load logs
loader = LogDataLoader()
result = loader.load_csv(csv_content)
logs_df = result.dataframe

# Aggregate into 1-minute windows
aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
windows_df = aggregator.aggregate(logs_df)

print(windows_df)
#   window_start  window_end  window_id  event_count  unique_sources  ...
# 0 2024-01-01... 2024-01-01... 0         523         12              ...
# 1 2024-01-01... 2024-01-01... 1         487         10              ...
```

### Example 2: Learn Baseline & Detect Anomalies

```python
from backend.windowing.time_window import BehaviorProfile

# Split data: first 24 hours = training, next 24 hours = test
train_windows = windows_df.iloc[:1440]      # 1440 1-min windows = 1 day
test_windows = windows_df.iloc[1440:2880]

# Learn baseline from normal day
profile = BehaviorProfile(train_windows)

# Print baseline
print(profile.report())

# Detect anomalies
test_windows['zscore_events'] = test_windows['event_count'].apply(
    lambda count: profile.get_zscore('event_count', count)
)
test_windows['is_anomalous'] = test_windows['zscore_events'].apply(
    lambda z: abs(z) > 2.0
)

anomaly_count = test_windows['is_anomalous'].sum()
print(f"Detected {anomaly_count} anomalous windows")
```

### Example 3: Multi-Scale Analysis

```python
# Analyze at different granularities

# Fast detection: 1-minute windows
agg_1m = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
fast_windows = agg_1m.aggregate(logs_df)

# Trend analysis: 1-hour windows
agg_1h = TimeWindowAggregator(window_size=WindowSize.ONE_HOUR)
slow_windows = agg_1h.aggregate(logs_df)

# Real-time: detect spikes in 1m windows
# Historical: understand patterns in 1h windows
```

### Example 4: Handle Missing Data

```python
# Strategy 1: Skip empty windows (sparse series)
agg_skip = TimeWindowAggregator(
    empty_strategy=EmptyWindowStrategy.SKIP
)
compact_windows = agg_skip.aggregate(logs_df)

# Strategy 2: Fill empty windows (complete series)
agg_fill = TimeWindowAggregator(
    empty_strategy=EmptyWindowStrategy.FILL
)
complete_windows = agg_fill.aggregate(logs_df)

# Strategy 3: Forward fill (smooth interpolation)
agg_ffill = TimeWindowAggregator(
    empty_strategy=EmptyWindowStrategy.FORWARD_FILL
)
smooth_windows = agg_ffill.aggregate(logs_df)
```

---

## Aggregated Metrics (Explained)

### Traffic Volume Metrics

**event_count**
- Total number of log entries in the window
- **Normal:** Relatively constant (±5-10%)
- **Anomalous:** Sudden spikes (attack flood) or drops (network outage)
- **Example:** Normal=100/min, Attack=1000/min (10x spike)

**bytes_sent / bytes_received**
- Network traffic volume (upstream/downstream)
- **Normal:** Proportional to event_count
- **Anomalous:** Disproportionate (e.g., few events but huge bytes = large payloads)
- **Example:** Exfiltration attack: 10 events, 1GB bytes_sent

### Endpoint Diversity Metrics

**unique_sources / unique_destinations**
- How many distinct IPs participated in the window
- **Normal:** Relatively stable (same users/servers repeat)
- **Anomalous:** Sudden increase (scanning) or decrease (isolation)
- **Example:** Normal=10 sources, Port scan=5000 sources

### Protocol Metrics

**protocols_tcp / protocols_udp / protocols_icmp**
- Distribution of protocol types
- **Normal:** Typically TCP-dominant (e.g., 80% TCP, 20% UDP)
- **Anomalous:** Unusual protocol mix (e.g., 90% ICMP = network reconnaissance)

### Error/Flag Metrics

**errors_count**
- Connection flags indicating errors/unusual states (S0, S1, RSTO, etc.)
- **Normal:** Low count, expected failures
- **Anomalous:** High count (connection resets, failures)

**land_attacks**
- Connections where source IP == destination IP
- **Normal:** 0 (invalid, dropped by OS)
- **Anomalous:** > 0 (legacy DoS attack, network misconfiguration)

**fragments**
- Fragmented packets (possible evasion technique)
- **Normal:** 0 or very low
- **Anomalous:** > 0 (potential IDS evasion)

---

## Behavior Profiles and Z-Scores

### What is a Z-Score?

Standardized score showing deviation from mean:

```
Z = (value - mean) / std_dev

Z = 0   → value equals mean (typical)
Z = 1   → value is 1 std above mean (about 84th percentile)
Z = 2   → value is 2 std above mean (about 97.5th percentile, slightly unusual)
Z = 3   → value is 3 std above mean (about 99.9th percentile, very unusual)
Z = -2  → value is 2 std below mean (about 2.5th percentile, slightly unusual)
```

### Thresholds for Anomaly Detection

```python
# Conservative: only flag extreme outliers
threshold = 3.0       # > 99.9% confidence, very few false positives

# Balanced: flag unusual but not extreme
threshold = 2.0       # > 97.5% confidence, good balance

# Sensitive: flag any unusual behavior
threshold = 1.5       # > ~93% confidence, more false positives
```

### Example Baseline Report

```
Behavior Profile Report
============================================================

event_count:
  mean:   500.00
  median: 498.00
  std:    25.00
  range:  [450.00, 550.00]
  p95:    545.00 (spike threshold)
  p5:     455.00 (drop threshold)

unique_sources:
  mean:   10.00
  median: 10.00
  std:    1.50
  range:  [8.00, 12.00]
  p95:    12.50
  p5:     7.50

bytes_sent:
  mean:   5000.00
  median: 4950.00
  std:    500.00
  range:  [4000.00, 6000.00]
  p95:    5950.00
  p5:     4050.00
```

---

## Performance Characteristics

| Aspect | Complexity | Notes |
|--------|-----------|-------|
| Parsing logs | O(n) | Single pass through events |
| Computing aggregates | O(n) | Single pass, constant-time updates |
| Sorting by timestamp | O(m log m) | m = number of windows |
| **Total** | **O(n + m log m)** | Dominated by aggregation for large n |

**Memory Usage:** O(n) for holding all windows in memory

**Suitable for:** Files up to ~1GB (millions of logs, thousands of windows)

**Scalability:** For larger datasets, consider:
- Streaming windowing (process in chunks)
- Distributed processing (Spark, MapReduce)
- Time-series database (InfluxDB, Prometheus)

---

## Integration with Anomaly Detection

### Pipeline

```
Raw Logs
    ↓ [LogDataLoader]
Parsed DataFrame
    ↓ [TimeWindowAggregator]
Windowed Behavior DataFrame
    ↓ [BehaviorProfile]
Baseline Statistics
    ↓ [Detection Logic]
Anomaly Scores / Flags
    ↓ [Alerts / Storage]
```

### Approach 1: Statistical Z-Score Detection

```python
profile = BehaviorProfile(baseline_windows)

for window in incoming_windows:
    is_spike = profile.get_zscore('event_count', window['event_count']) > 2.0
    is_new_sources = profile.get_zscore('unique_sources', window['unique_sources']) > 2.0
    
    if is_spike or is_new_sources:
        alert("Anomaly detected!")
```

### Approach 2: Machine Learning (Isolation Forest, etc.)

```python
from backend.detection.anomaly_detector import AnomalyDetector

# Train on baseline windows
detector = AnomalyDetector(contamination=0.05)
detector.fit(baseline_windows[feature_columns])

# Detect in new windows
scores = detector.detect(incoming_windows[feature_columns])
anomalies = scores < threshold
```

### Approach 3: Rule-Based Detection

```python
def is_anomalous(window):
    # Custom business rules
    if window['event_count'] > 1000:
        return True
    if window['unique_sources'] > 100:
        return True
    if window['protocols_icmp'] > 0:  # ICMP unusual in our network
        return True
    return False
```

---

## Window Size Selection Guide

| Scenario | Recommended | Rationale |
|----------|-------------|-----------|
| Real-time alerts | 1m | Fast detection, low latency |
| Network monitoring dashboard | 5m | Good balance |
| Historical analysis | 1h | Smooth trends, less noise |
| Daily reports | 1d | Long-term patterns |
| DDoS detection | 30s-1m | Need fast response |
| Network anomalies | 5-10m | Reduces false positives |
| User behavior analysis | 1h-1d | Captures daily patterns |

---

## Common Pitfalls & Solutions

### Pitfall 1: Insufficient Baseline

**Problem:** Baseline includes anomalies
```python
# BAD: Learn from all data (includes attack days)
profile = BehaviorProfile(all_windows)
```

**Solution:** Use known-good data only
```python
# GOOD: Learn from weekdays when no attacks occurred
profile = BehaviorProfile(normal_weekday_windows)
```

### Pitfall 2: Wrong Window Size

**Problem:** Too small → high variance, many false positives
```python
# BAD: 10-second windows for slow networks
aggregator = TimeWindowAggregator(window_size=tiny_size)
```

**Solution:** Choose appropriate granularity
```python
# GOOD: 1-5 minute windows for typical networks
aggregator = TimeWindowAggregator(window_size=WindowSize.ONE_MINUTE)
```

### Pitfall 3: Ignoring Temporal Patterns

**Problem:** Monday traffic ≠ Saturday traffic
```python
# BAD: Same threshold all week
profile = BehaviorProfile(mixed_weekday_data)
```

**Solution:** Separate baselines by day-of-week
```python
# GOOD: Learn Monday-Friday separately
monday_profile = BehaviorProfile(monday_windows)
weekend_profile = BehaviorProfile(weekend_windows)
```

### Pitfall 4: Empty Window Handling

**Problem:** Gaps cause time-series breaks
```python
# BAD: Unknown behavior during outage
result = aggregator.aggregate(data)  # Skips silence period
```

**Solution:** Choose appropriate strategy
```python
# GOOD: Fill to show absence of activity
aggregator = TimeWindowAggregator(empty_strategy=EmptyWindowStrategy.FILL)
```

---

## Testing

Run comprehensive tests:

```bash
pytest tests/unit/test_time_window.py -v
```

**Coverage:**
- 26 tests covering windowing, aggregation, and anomaly detection
- Edge cases: empty data, timezone handling, multiple window sizes
- Integration: end-to-end windowing + anomaly detection

---

## References

- **Statistical Process Control:** Shewhart control charts, Z-scores
- **Time-Series Anomaly Detection:** ARIMA, Isolation Forest, LSTM
- **Windowing:** Apache Flink, Kafka Streams documentation
- **Network Anomalies:** Intrusion detection systems (IDS) literature

---

## Future Enhancements

1. **Streaming Windowing:** Process logs as they arrive (Kafka integration)
2. **Adaptive Windows:** Variable-size windows based on data density
3. **Multi-Scale Anomalies:** Detect anomalies at different time scales simultaneously
4. **Forecast-Based Detection:** Compare against predicted values
5. **Seasonal Decomposition:** Separate trend, seasonality, residuals
6. **Machine Learning Integration:** Learn optimal feature weighting
