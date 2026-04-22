# Log Ingestion Module Documentation

**Last Updated:** 2026-04-22  
**Status:** Production Ready (v1.0)  
**Test Coverage:** 28/28 tests passing ✅

## Overview

The log ingestion module provides **schema-first**, **type-safe** data loading with strict validation. It parses raw CSV/log data, validates against a rigid data contract, normalizes fields, and returns a clean Pandas DataFrame with validated timestamps.

**Key Characteristics:**
- ✅ No ML/aggregation - raw data only
- ✅ Strict schema validation with type coercion
- ✅ Detailed error reporting (parse, validation, row-level)
- ✅ Timestamp handling (ISO 8601, UTC, sequential inference)
- ✅ IP validation (IPv4/IPv6)
- ✅ Configurable inference modes
- ✅ Observable error tracking

---

## Architecture

### DataContract (`data_contract.py`)

Defines the complete schema for network log records. No business logic — purely validation rules.

**15 Required Fields:**

| Field | Type | Constraints | Example |
|-------|------|-----------|---------|
| `timestamp` | DATETIME | Required, ISO 8601 | 2024-01-01T12:00:00 |
| `source_ip` | IP_ADDRESS | Required | 10.0.0.1 |
| `destination_ip` | IP_ADDRESS | Required | 192.168.1.1 |
| `protocol_type` | STRING | Required, {tcp, udp, icmp} | tcp |
| `service` | STRING | Nullable | http |
| `flag` | STRING | Required | SF |
| `duration` | FLOAT | Required, [0, 2147483647] | 42.5 |
| `src_bytes` | INT | Required, ≥0 | 1024 |
| `dst_bytes` | INT | Required, ≥0 | 2048 |
| `land` | INT | Required, {0, 1} | 0 |
| `wrong_fragment` | INT | Required, ≥0 | 0 |
| `urgent` | INT | Required, ≥0 | 0 |
| `event_type` | STRING | Required | NORMAL |
| `message` | STRING | Nullable | "Normal traffic" |
| `original_label` | STRING | Nullable | normal |

#### Key Classes:

**FieldType (Enum):** STRING, INT, FLOAT, DATETIME, IP_ADDRESS, BOOLEAN

**FieldConstraint:**
```python
constraint = FieldConstraint(
    name="protocol_type",
    field_type=FieldType.STRING,
    required=True,
    allowed_values={"tcp", "udp", "icmp"},
    description="Network protocol"
)

is_valid, errors = constraint.validate("tcp")  # (True, None)
is_valid, errors = constraint.validate("http")  # (False, ["not in allowed values"])
```

**DataContract:**
```python
contract = DataContract()

# Validate
is_valid, errors = contract.validate_record({
    "timestamp": "2024-01-01T12:00:00",
    "source_ip": "10.0.0.1",
    # ... other fields
})

# Normalize (type coercion)
normalized = contract.normalize_record({
    "protocol_type": "TCP",      # → "tcp" (lowercased)
    "duration": "42.5",          # → 42.5 (float)
    "src_bytes": "1024",         # → 1024 (int)
})
```

---

### LogDataLoader (`log_data_loader.py`)

Orchestrates the full parsing → validation → normalization → DataFrame pipeline.

#### LoaderConfig

```python
config = LoaderConfig(
    strict_mode=True,              # Fail on ANY error
    skip_invalid_rows=False,       # Include invalid rows in result
    infer_missing_timestamp=True,  # Generate sequential timestamps
    infer_missing_ips=True,        # Generate placeholder IPs
    max_errors=1000                # Stop after this many errors
)
```

#### LoaderResult

```python
result = loader.load_csv(csv_content)

# Access results
df = result.dataframe                 # Pandas DataFrame
success = result.success              # bool: no errors
has_errors = result.has_errors        # bool: any errors
error_count = result.error_count      # int: total errors
row_count = result.row_count          # int: loaded rows

# Error details
result.parse_errors      # CSV parsing errors
result.validation_errors # Contract validation errors
result.row_errors        # Row-level validation errors (with raw data)

# Statistics
result.stats = {
    "rows": 1234,
    "columns": 15,
    "timestamp_range": {"min": "...", "max": "..."},
    "event_types": {"NORMAL": 1000, "ATTACK": 234},
    "protocols": {"tcp": 900, "udp": 334}
}

# Human-readable report
print(result.report())
```

#### Workflow

1. **Parse:** CSV → list of rows
2. **Infer:** Fill missing timestamps, IPs
3. **Validate:** Check against data contract
4. **Normalize:** Type coercion and lowercase certain fields
5. **DataFrame:** Sort by timestamp, convert types, finalize

---

## Usage Examples

### Example 1: Load and Validate CSV

```python
from backend.ingestion.log_data_loader import LogDataLoader

csv_content = """2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal
2024-01-02T12:00:00,10.0.0.2,192.168.1.2,udp,dns,SF,1.5,512,256,0,0,0,NORMAL,Normal traffic,normal"""

loader = LogDataLoader()
result = loader.load_csv(csv_content)

if result.success:
    print(f"Loaded {result.row_count} rows")
    print(result.dataframe)
    # DataFrame columns and types:
    # timestamp      datetime64[ns, UTC]
    # source_ip      string
    # destination_ip string
    # protocol_type  string
    # ...
else:
    print("Errors occurred:")
    print(result.report())
```

### Example 2: Skip Invalid Rows

```python
from backend.ingestion.log_data_loader import LogDataLoader, LoaderConfig

config = LoaderConfig(skip_invalid_rows=True)
loader = LogDataLoader(config=config)
result = loader.load_csv(csv_content)

# Valid rows are in result.dataframe
# Invalid rows are in result.row_errors
print(f"Valid: {result.row_count}, Invalid: {len(result.row_errors)}")
```

### Example 3: Infer Missing Timestamps

```python
config = LoaderConfig(infer_missing_timestamp=True)
loader = LogDataLoader(config=config)

# CSV with incomplete rows (no timestamps)
csv_content = """10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

result = loader.load_csv(csv_content)
# Timestamps will be auto-generated starting from 2024-01-01T00:00:00
```

### Example 4: Custom Data Contract

```python
from backend.ingestion.data_contract import DataContract, FieldConstraint, FieldType

# Create custom contract
custom_contract = DataContract(
    constraints=[
        FieldConstraint(name="timestamp", field_type=FieldType.DATETIME, required=True),
        # ... custom fields
    ]
)

loader = LogDataLoader(contract=custom_contract)
result = loader.load_csv(csv_content)
```

### Example 5: Statistics and Analysis

```python
result = loader.load_csv(csv_content)

# Get statistics
print(result.stats)
# {
#     "rows": 1234,
#     "columns": 15,
#     "timestamp_range": {
#         "min": "2024-01-01T00:00:00+00:00",
#         "max": "2024-12-31T23:59:59+00:00"
#     },
#     "event_types": {"NORMAL": 1000, "ATTACK": 234},
#     "protocols": {"tcp": 900, "udp": 334}
# }

# Access DataFrame
df = result.dataframe
df.groupby("protocol_type")["event_type"].value_counts()
```

---

## CSV Format

**Required:** 15 comma-separated fields in exact order:

```
timestamp,source_ip,destination_ip,protocol_type,service,flag,duration,src_bytes,dst_bytes,land,wrong_fragment,urgent,event_type,message,original_label
2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal
```

**Header Row:** Automatically detected and skipped if first row contains field names like "timestamp", "source_ip", etc.

**Empty Fields:** Left empty or use null values; will be populated with defaults or inferred values based on `LoaderConfig`.

---

## Error Handling

### Parse Errors

```python
result.parse_errors = [
    "Line 1: Unexpected CSV format",
    "Line 5: Mismatched column count"
]
```

### Validation Errors

```python
result.validation_errors = [
    "Missing required field: 'timestamp'",
    "Field 'protocol_type': value 'http' not in allowed values {'tcp', 'udp', 'icmp'}"
]
```

### Row Errors

```python
result.row_errors = [
    {
        "row_no": 5,
        "raw": ["invalid_ts", "10.0.0.1", "192.168.1.1", ...],
        "errors": [
            "Field 'timestamp': Cannot parse datetime: invalid_ts",
            "Field 'duration': value -1 is below minimum 0"
        ]
    }
]
```

---

## Type Coercion

| Type | Input | Output | Notes |
|------|-------|--------|-------|
| STRING | "TCP" | "tcp" | Lowercased for protocol_type, service, flag |
| INT | "42" | 42 | Parsed from string or float (truncated) |
| INT | "42.7" | 42 | Float truncated to int |
| FLOAT | "42.5" | 42.5 | Parsed from string or int |
| DATETIME | "2024-01-01T12:00:00" | datetime(...) | ISO format parsed |
| DATETIME | "2024-01-01 12:00:00" | datetime(...) | Standard format parsed |
| IP_ADDRESS | "10.0.0.1" | "10.0.0.1" | Validated as IPv4 |
| IP_ADDRESS | "::1" | "::1" | Accepted as IPv6 |
| BOOLEAN | "true", "1", "yes" | True | Multiple representations |
| BOOLEAN | "false", "0", "no" | False | Multiple representations |

---

## Validation Rules

### Required vs. Optional

- **Required:** timestamp, source_ip, destination_ip, protocol_type, flag, duration, src_bytes, dst_bytes, land, wrong_fragment, urgent, event_type
- **Optional (Nullable):** service, message, original_label

### Constraints

- **protocol_type:** Must be one of {tcp, udp, icmp}
- **duration:** 0 ≤ value ≤ 2,147,483,647 seconds
- **src_bytes, dst_bytes, land, wrong_fragment, urgent:** ≥ 0
- **land:** Must be 0 or 1
- **IP addresses:** Valid IPv4 or IPv6 format

### Custom Validators

```python
def validate_symmetric_ips(value):
    """Custom validator: source and destination should be different."""
    src, dst = value  # Receives both IPs
    return src != dst

constraint = FieldConstraint(
    name="symmetric_check",
    custom_validator=validate_symmetric_ips
)
```

---

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Parse | O(n) | Single pass through CSV |
| Validate | O(n) | Single pass, constraint checks are constant-time |
| Normalize | O(n) | Single pass, type coercions |
| DataFrame creation | O(n log n) | Sorting by timestamp |
| **Total** | **O(n log n)** | Dominated by sorting |

**Memory:** O(n) — all rows in memory; suitable for files up to ~100MB

---

## Integration with Existing Code

### Replace LogProcessor

The new `LogDataLoader` can replace the existing `LogProcessor`:

```python
# Old code
processor = LogProcessor(file_id=file_id)
entries = processor.process(file_content)

# New code
loader = LogDataLoader()
result = loader.load_csv(file_content)
df = result.dataframe

# Convert DataFrame to LogEntry objects if needed
from backend.models.log_entry import LogEntry
entries = [LogEntry(**row) for row in df.to_dict(orient="records")]
```

### Use in LogIngestionService

```python
from backend.ingestion.log_data_loader import LogDataLoader

class LogIngestionService:
    def ingest(self, file_content: str, file_name: str, uploaded_by: int):
        loader = LogDataLoader()
        result = loader.load_csv(file_content)
        
        if not result.success:
            logger.error(f"Load failed: {result.report()}")
            raise ValueError(f"Invalid data: {result.error_count} errors")
        
        df = result.dataframe
        # ... store in database
        return result.row_count, len(result.row_errors)
```

---

## Testing

Run the comprehensive test suite:

```bash
pytest tests/unit/test_log_data_loader.py -v
```

**Coverage:**
- ✅ FieldConstraint validation (11 tests)
- ✅ DataContract schema (5 tests)
- ✅ LoaderResult utilities (3 tests)
- ✅ LogDataLoader CSV parsing (9 tests)

All 28 tests passing.

---

## Future Enhancements

1. **Async Loading:** Process large files in background with progress callbacks
2. **Streaming:** Process DataFrames in chunks instead of all-in-memory
3. **Caching:** Memoize validation rules for repeated loads
4. **Custom Rules:** User-defined validation functions per field
5. **Format Detection:** Auto-detect CSV vs. TSV vs. JSON
6. **Compression:** Handle gzip/bzip2 natively
7. **Database Loading:** Direct INSERT without intermediate DataFrame

---

## Troubleshooting

### "Expected at least 1 row, got 0"

**Cause:** All rows detected as header rows.  
**Fix:** Ensure first data row doesn't have field names; check `_is_header_row()` logic.

### "Failed to convert 'timestamp' to datetime"

**Cause:** Timestamp format not recognized.  
**Fix:** Use ISO 8601 format (2024-01-01T12:00:00) or enable `infer_missing_timestamp`.

### "Field 'protocol_type': value 'http' not in allowed values"

**Cause:** 'http' is a service, not a protocol.  
**Fix:** Use 'tcp', 'udp', or 'icmp' for protocol_type.

### "Field 'source_ip': Invalid IPv4 address"

**Cause:** Malformed IP address.  
**Fix:** Use valid IPv4 (e.g., 10.0.0.1) or IPv6 (e.g., ::1).

---

## References

- **NSL-KDD Dataset:** http://kdd.ics.uci.edu/databases/kddcup99/
- **Pandas Documentation:** https://pandas.pydata.org/docs/
- **ISO 8601:** https://en.wikipedia.org/wiki/ISO_8601
- **IPv4/IPv6:** https://en.wikipedia.org/wiki/IP_address
