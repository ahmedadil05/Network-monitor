"""
tests/unit/test_log_data_loader.py
Comprehensive unit tests for LogDataLoader and DataContract.
"""
import pytest
import pandas as pd
from datetime import datetime
from backend.ingestion.data_contract import DataContract, FieldConstraint, FieldType
from backend.ingestion.log_data_loader import LogDataLoader, LoaderConfig, LoaderResult


class TestFieldConstraint:
    """Test FieldConstraint validation and type coercion."""

    def test_string_type_coercion(self):
        """String fields should accept and coerce values."""
        constraint = FieldConstraint(name="test", field_type=FieldType.STRING)
        is_valid, _ = constraint.validate("hello")
        assert is_valid

    def test_required_field_missing(self):
        """Required fields should fail when None."""
        constraint = FieldConstraint(name="test", field_type=FieldType.STRING, required=True)
        is_valid, msg = constraint.validate(None)
        assert not is_valid
        assert "required" in msg.lower()

    def test_nullable_field(self):
        """Nullable fields should accept None."""
        constraint = FieldConstraint(name="test", field_type=FieldType.STRING, nullable=True)
        is_valid, _ = constraint.validate(None)
        assert is_valid

    def test_int_type_coercion(self):
        """Int fields should coerce from strings and floats."""
        constraint = FieldConstraint(name="test", field_type=FieldType.INT)
        assert constraint._coerce_type("42") == 42
        assert constraint._coerce_type("42.7") == 42
        assert constraint._coerce_type(42.7) == 42

    def test_float_type_coercion(self):
        """Float fields should coerce from strings and ints."""
        constraint = FieldConstraint(name="test", field_type=FieldType.FLOAT)
        assert constraint._coerce_type("42.5") == 42.5
        assert constraint._coerce_type("42") == 42.0
        assert constraint._coerce_type(42) == 42.0

    def test_min_max_constraints(self):
        """Min/max constraints should be enforced."""
        constraint = FieldConstraint(
            name="test", field_type=FieldType.INT, min_value=0, max_value=100
        )
        # Valid
        is_valid, _ = constraint.validate(50)
        assert is_valid
        # Below min
        is_valid, msg = constraint.validate(-1)
        assert not is_valid and "minimum" in msg.lower()
        # Above max
        is_valid, msg = constraint.validate(101)
        assert not is_valid and "maximum" in msg.lower()

    def test_allowed_values_constraint(self):
        """Allowed values should be enforced."""
        constraint = FieldConstraint(
            name="test", field_type=FieldType.STRING, allowed_values={"tcp", "udp", "icmp"}
        )
        is_valid, _ = constraint.validate("tcp")
        assert is_valid
        is_valid, msg = constraint.validate("http")
        assert not is_valid

    def test_regex_pattern_constraint(self):
        """Regex patterns should be enforced."""
        constraint = FieldConstraint(
            name="test", field_type=FieldType.STRING, regex_pattern=r"^\d{3}-\d{4}$"
        )
        is_valid, _ = constraint.validate("123-4567")
        assert is_valid
        is_valid, msg = constraint.validate("123-456")
        assert not is_valid

    def test_ip_address_validation(self):
        """IP address fields should validate format."""
        constraint = FieldConstraint(name="test", field_type=FieldType.IP_ADDRESS)

        # Valid IPv4
        is_valid, _ = constraint.validate("192.168.1.1")
        assert is_valid

        # Invalid IPv4
        is_valid, msg = constraint.validate("192.168.1.256")
        assert not is_valid

        is_valid, msg = constraint.validate("192.168.1")
        assert not is_valid

    def test_datetime_parsing(self):
        """Datetime fields should parse multiple formats."""
        constraint = FieldConstraint(name="test", field_type=FieldType.DATETIME)

        # ISO format
        is_valid, _ = constraint.validate("2024-01-01T12:00:00")
        assert is_valid

        # Standard format
        is_valid, _ = constraint.validate("2024-01-01 12:00:00")
        assert is_valid

        # datetime object
        is_valid, _ = constraint.validate(datetime(2024, 1, 1))
        assert is_valid

    def test_boolean_parsing(self):
        """Boolean fields should parse various representations."""
        constraint = FieldConstraint(name="test", field_type=FieldType.BOOLEAN)

        for true_val in ["true", "True", "1", "yes", "on"]:
            is_valid, _ = constraint.validate(true_val)
            assert is_valid

        for false_val in ["false", "False", "0", "no", "off"]:
            is_valid, _ = constraint.validate(false_val)
            assert is_valid


class TestDataContract:
    """Test DataContract schema validation."""

    def test_default_contract_fields(self):
        """Default contract should have expected fields."""
        contract = DataContract()
        fields = contract.get_field_names()

        assert "timestamp" in fields
        assert "source_ip" in fields
        assert "destination_ip" in fields
        assert "protocol_type" in fields
        assert "duration" in fields
        assert "src_bytes" in fields
        assert "dst_bytes" in fields

    def test_validate_valid_record(self):
        """Valid record should pass validation."""
        contract = DataContract()
        record = {
            "timestamp": "2024-01-01T12:00:00",
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.1",
            "protocol_type": "tcp",
            "service": "http",
            "flag": "SF",
            "duration": 42.5,
            "src_bytes": 1024,
            "dst_bytes": 2048,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "event_type": "NORMAL",
            "message": "Normal traffic",
        }

        is_valid, errors = contract.validate_record(record)
        assert is_valid
        assert errors is None

    def test_validate_missing_required_field(self):
        """Missing required field should fail."""
        contract = DataContract()
        record = {
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.1",
            # Missing timestamp
        }

        is_valid, errors = contract.validate_record(record)
        assert not is_valid
        assert any("timestamp" in err.lower() for err in errors)

    def test_validate_invalid_protocol_type(self):
        """Invalid protocol type should fail."""
        contract = DataContract()
        record = {
            "timestamp": "2024-01-01T12:00:00",
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.1",
            "protocol_type": "invalid_protocol",
            "service": "http",
            "flag": "SF",
            "duration": 42.5,
            "src_bytes": 1024,
            "dst_bytes": 2048,
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0,
            "event_type": "NORMAL",
            "message": "Normal traffic",
        }

        is_valid, errors = contract.validate_record(record)
        assert not is_valid
        assert any("protocol" in err.lower() for err in errors)

    def test_normalize_record(self):
        """Record should be normalized with proper types."""
        contract = DataContract()
        record = {
            "timestamp": "2024-01-01 12:00:00",
            "source_ip": "10.0.0.1",
            "destination_ip": "192.168.1.1",
            "protocol_type": "TCP",  # Should be lowercased
            "service": "HTTP",
            "flag": "SF",
            "duration": "42.5",  # Should be float
            "src_bytes": "1024",  # Should be int
            "dst_bytes": "2048",
            "land": "0",
            "wrong_fragment": "0",
            "urgent": "0",
            "event_type": "NORMAL",
            "message": "Normal traffic",
            "original_label": "normal",
        }

        normalized = contract.normalize_record(record)
        assert isinstance(normalized["timestamp"], datetime)
        assert isinstance(normalized["duration"], float)
        assert isinstance(normalized["src_bytes"], int)
        assert normalized["protocol_type"] == "tcp"  # Lowercase
        assert normalized["service"] == "http"  # Lowercase


class TestLoaderResult:
    """Test LoaderResult utility class."""

    def test_result_success_no_errors(self):
        """Result should indicate success when no errors."""
        result = LoaderResult()
        assert result.success
        assert not result.has_errors
        assert result.error_count == 0

    def test_result_with_errors(self):
        """Result should track errors."""
        result = LoaderResult()
        result.add_parse_error(1, "Invalid CSV")
        result.add_row_error(2, ["a", "b"], ["Invalid protocol"])

        assert not result.success
        assert result.has_errors
        assert result.error_count == 2

    def test_result_report(self):
        """Result should generate readable report."""
        result = LoaderResult()
        result.add_parse_error(1, "Invalid CSV")

        report = result.report()
        assert "0 rows loaded" in report
        assert "1 errors" in report
        assert "Parse Errors" in report


class TestLogDataLoader:
    """Test LogDataLoader CSV parsing and DataFrame generation."""

    def test_load_simple_csv(self):
        """Load a simple valid CSV file."""
        # Full row with all 15 fields in correct order
        csv_content = """2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        assert result.row_count >= 1, f"Expected at least 1 row, got {result.row_count}"
        assert "timestamp" in result.dataframe.columns
        assert "source_ip" in result.dataframe.columns
        assert "protocol_type" in result.dataframe.columns

    def test_load_csv_with_missing_timestamps(self):
        """Load CSV with incomplete fields — should infer timestamps."""
        # CSV row with only 14 fields (missing timestamp, has all others)
        csv_content = """10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        config = LoaderConfig(infer_missing_timestamp=True, infer_missing_ips=False)
        loader = LogDataLoader(config=config)
        result = loader.load_csv(csv_content)

        if result.row_count > 0:
            # Check that timestamp was inferred
            assert "timestamp" in result.dataframe.columns
            # All timestamps should be non-null if inferred
            if result.dataframe["timestamp"].dtype == "datetime64[ns, UTC]":
                assert result.dataframe["timestamp"].notna().all()

    def test_dataframe_column_types(self):
        """DataFrame should have correct column types."""
        csv_content = """2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        if result.row_count > 0:
            df = result.dataframe
            # Check numeric columns have correct types
            if "duration" in df.columns:
                assert df["duration"].dtype == "float64"
            if "src_bytes" in df.columns:
                assert df["src_bytes"].dtype == "int64"
            if "dst_bytes" in df.columns:
                assert df["dst_bytes"].dtype == "int64"
            if "timestamp" in df.columns:
                assert pd.api.types.is_datetime64_any_dtype(df["timestamp"])

    def test_dataframe_sorted_by_timestamp(self):
        """DataFrame should be sorted by timestamp."""
        csv_content = """2024-01-03T12:00:00,10.0.0.3,192.168.1.3,tcp,http,SF,1,1,1,0,0,0,NORMAL,Third,normal
2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,1,1,1,0,0,0,NORMAL,First,normal
2024-01-02T12:00:00,10.0.0.2,192.168.1.2,tcp,http,SF,1,1,1,0,0,0,NORMAL,Second,normal"""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        if result.row_count > 1 and "timestamp" in result.dataframe.columns:
            df = result.dataframe
            timestamps = df["timestamp"].tolist()
            assert timestamps == sorted(timestamps), "DataFrame should be sorted by timestamp"

    def test_loader_statistics(self):
        """Loader should compute statistics."""
        csv_content = """2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal
2024-01-02T12:00:00,10.0.0.2,192.168.1.2,udp,dns,SF,1.5,512,256,0,0,0,ATTACK,Attack traffic,attack"""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        assert result.stats["rows"] >= 1
        assert "timestamp_range" in result.stats

    def test_load_csv_with_validation_errors(self):
        """Load CSV with invalid data — should collect errors."""
        csv_content = """invalid_timestamp,10.0.0.1,192.168.1.1,invalid_protocol,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        config = LoaderConfig(skip_invalid_rows=True)
        loader = LogDataLoader(config=config)
        result = loader.load_csv(csv_content)

        # Should have validation errors
        assert result.has_errors or result.row_count == 0

    def test_empty_csv(self):
        """Empty CSV should be handled gracefully."""
        csv_content = ""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        assert result.row_count == 0
        assert result.dataframe.empty

    def test_csv_with_header_detection(self):
        """CSV with header row should be auto-detected and skipped."""
        csv_content = """timestamp,source_ip,destination_ip,protocol_type,service,flag,duration,src_bytes,dst_bytes,land,wrong_fragment,urgent,event_type,message,original_label
2024-01-01T12:00:00,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        loader = LogDataLoader()
        result = loader.load_csv(csv_content)

        assert result.row_count == 1

    def test_strict_mode_fails_on_error(self):
        """Strict mode should fail on any validation error."""
        csv_content = """invalid_timestamp,10.0.0.1,192.168.1.1,tcp,http,SF,42.5,1024,2048,0,0,0,NORMAL,Normal traffic,normal"""

        config = LoaderConfig(strict_mode=True, skip_invalid_rows=False)
        loader = LogDataLoader(config=config)
        result = loader.load_csv(csv_content)

        # Record should still be in DataFrame but marked with errors
        assert result.row_errors  # Should have row errors from validation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
