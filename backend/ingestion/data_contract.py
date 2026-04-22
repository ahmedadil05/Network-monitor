"""
backend/ingestion/data_contract.py
Strict data contract definition for log records.

Defines schema, validation rules, type constraints, and normalization for all log data.
No business logic — purely schema definition and validation.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Set, Callable, Any, Optional, Type
from enum import Enum
import re
from datetime import datetime


class FieldType(Enum):
    """Supported field types in the data contract."""
    STRING = "string"
    INT = "int"
    FLOAT = "float"
    DATETIME = "datetime"
    IP_ADDRESS = "ip_address"
    BOOLEAN = "boolean"


@dataclass
class FieldConstraint:
    """Validation constraint for a single field."""
    name: str
    field_type: FieldType
    required: bool = True
    nullable: bool = False
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    allowed_values: Optional[Set[str]] = None
    regex_pattern: Optional[str] = None
    custom_validator: Optional[Callable[[Any], bool]] = None
    description: str = ""

    def validate(self, value: Any) -> tuple[bool, Optional[str]]:
        """
        Validate a value against this constraint.
        Returns: (is_valid, error_message)
        """
        # Check for None/null values
        if value is None or (isinstance(value, str) and value.strip() == ""):
            if self.required and not self.nullable:
                return False, f"Field '{self.name}' is required and cannot be null"
            if self.nullable:
                return True, None
            return False, f"Field '{self.name}' cannot be null"

        # Type validation
        try:
            validated_value = self._coerce_type(value)
        except (ValueError, TypeError) as e:
            return False, f"Field '{self.name}': invalid type — expected {self.field_type.value}, got {type(value).__name__}"

        # Range validation for numeric types
        if self.field_type in (FieldType.INT, FieldType.FLOAT):
            if self.min_value is not None and validated_value < self.min_value:
                return False, f"Field '{self.name}': value {validated_value} is below minimum {self.min_value}"
            if self.max_value is not None and validated_value > self.max_value:
                return False, f"Field '{self.name}': value {validated_value} exceeds maximum {self.max_value}"

        # Allowed values validation
        if self.allowed_values is not None:
            normalized = str(validated_value).lower() if isinstance(validated_value, str) else str(validated_value)
            if normalized not in {str(v).lower() for v in self.allowed_values}:
                return False, f"Field '{self.name}': value '{value}' not in allowed values {self.allowed_values}"

        # Regex pattern validation
        if self.regex_pattern is not None:
            if not re.match(self.regex_pattern, str(validated_value)):
                return False, f"Field '{self.name}': value '{value}' does not match pattern {self.regex_pattern}"

        # Custom validator
        if self.custom_validator is not None:
            try:
                if not self.custom_validator(validated_value):
                    return False, f"Field '{self.name}': custom validation failed for value '{value}'"
            except Exception as e:
                return False, f"Field '{self.name}': custom validator error — {str(e)}"

        return True, None

    def _coerce_type(self, value: Any) -> Any:
        """Coerce value to the expected field type."""
        if isinstance(value, str):
            value = value.strip()

        if self.field_type == FieldType.STRING:
            result = str(value)
            # Normalize certain fields to lowercase
            if self.name in ("protocol_type", "service", "flag"):
                result = result.lower()
            return result
        elif self.field_type == FieldType.INT:
            return int(float(value))  # Allow "1.5" -> 1
        elif self.field_type == FieldType.FLOAT:
            return float(value)
        elif self.field_type == FieldType.DATETIME:
            if isinstance(value, datetime):
                return value
            # Try ISO format
            try:
                return datetime.fromisoformat(value)
            except (ValueError, TypeError):
                # Try common formats
                for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S"]:
                    try:
                        return datetime.strptime(value, fmt)
                    except ValueError:
                        continue
                raise ValueError(f"Cannot parse datetime: {value}")
        elif self.field_type == FieldType.IP_ADDRESS:
            # Just validate format, don't convert
            self._validate_ip(value)
            return str(value)
        elif self.field_type == FieldType.BOOLEAN:
            if isinstance(value, bool):
                return value
            if str(value).lower() in ("true", "1", "yes", "on"):
                return True
            if str(value).lower() in ("false", "0", "no", "off"):
                return False
            raise ValueError(f"Cannot parse boolean: {value}")
        else:
            raise ValueError(f"Unknown field type: {self.field_type}")

    @staticmethod
    def _validate_ip(value: str) -> None:
        """Validate IP address format (IPv4 or IPv6)."""
        # Simple validation for IPv4
        if ":" in str(value):
            # IPv6
            pass  # Accept any IPv6-like format
        else:
            # IPv4
            parts = str(value).split(".")
            if len(parts) != 4:
                raise ValueError(f"Invalid IPv4 address: {value}")
            for part in parts:
                try:
                    num = int(part)
                    if not (0 <= num <= 255):
                        raise ValueError(f"Octet {num} out of range [0-255]")
                except ValueError:
                    raise ValueError(f"Invalid IPv4 octet: {part}")


class DataContract:
    """
    Strict data contract defining the schema for log records.
    Provides validation, normalization, and type coercion.
    """

    # Core network log schema (aligned with NSL-KDD + custom fields)
    DEFAULT_CONSTRAINTS = [
        # Temporal
        FieldConstraint(
            name="timestamp",
            field_type=FieldType.DATETIME,
            required=True,
            description="UTC timestamp in ISO 8601 format or parseable format"
        ),
        # Network
        FieldConstraint(
            name="source_ip",
            field_type=FieldType.IP_ADDRESS,
            required=True,
            description="Source IPv4 or IPv6 address"
        ),
        FieldConstraint(
            name="destination_ip",
            field_type=FieldType.IP_ADDRESS,
            required=True,
            description="Destination IPv4 or IPv6 address"
        ),
        # Protocol
        FieldConstraint(
            name="protocol_type",
            field_type=FieldType.STRING,
            required=True,
            allowed_values={"tcp", "udp", "icmp"},
            description="Network protocol: tcp, udp, or icmp"
        ),
        FieldConstraint(
            name="service",
            field_type=FieldType.STRING,
            required=True,
            nullable=True,
            description="Network service (http, ssh, ftp, etc.)"
        ),
        FieldConstraint(
            name="flag",
            field_type=FieldType.STRING,
            required=True,
            description="Connection flag (SF, S0, S1, S2, S3, RSTO, RSTR, RSTOS0, OTH)"
        ),
        # Traffic
        FieldConstraint(
            name="duration",
            field_type=FieldType.FLOAT,
            required=True,
            min_value=0,
            max_value=2147483647,  # Max reasonable duration in seconds (~68 years)
            description="Connection duration in seconds"
        ),
        FieldConstraint(
            name="src_bytes",
            field_type=FieldType.INT,
            required=True,
            min_value=0,
            description="Number of bytes from source to destination"
        ),
        FieldConstraint(
            name="dst_bytes",
            field_type=FieldType.INT,
            required=True,
            min_value=0,
            description="Number of bytes from destination to source"
        ),
        # Flags
        FieldConstraint(
            name="land",
            field_type=FieldType.INT,
            required=True,
            min_value=0,
            max_value=1,
            description="1 if source and destination IPs are identical, else 0"
        ),
        FieldConstraint(
            name="wrong_fragment",
            field_type=FieldType.INT,
            required=True,
            min_value=0,
            description="Count of wrong fragments"
        ),
        FieldConstraint(
            name="urgent",
            field_type=FieldType.INT,
            required=True,
            min_value=0,
            description="Count of urgent packets"
        ),
        # Event metadata
        FieldConstraint(
            name="event_type",
            field_type=FieldType.STRING,
            required=True,
            description="Event classification (NORMAL, ATTACK, ANOMALY, etc.)"
        ),
        FieldConstraint(
            name="message",
            field_type=FieldType.STRING,
            required=True,
            nullable=True,
            description="Human-readable log message"
        ),
        FieldConstraint(
            name="original_label",
            field_type=FieldType.STRING,
            required=False,
            nullable=True,
            description="Original label from source data (for reference)"
        ),
    ]

    def __init__(self, constraints: Optional[List[FieldConstraint]] = None):
        """
        Initialize with custom constraints or default schema.
        """
        self.constraints = {c.name: c for c in (constraints or self.DEFAULT_CONSTRAINTS)}
        self._validation_errors: List[str] = []

    def validate_record(self, record: Dict[str, Any]) -> tuple[bool, Optional[List[str]]]:
        """
        Validate a single record against the contract.
        Returns: (is_valid, error_messages)
        """
        self._validation_errors = []

        # Check for required fields
        for field_name, constraint in self.constraints.items():
            if field_name not in record and constraint.required:
                self._validation_errors.append(f"Missing required field: '{field_name}'")

        # Validate each present field
        for field_name, value in record.items():
            if field_name in self.constraints:
                is_valid, error_msg = self.constraints[field_name].validate(value)
                if not is_valid:
                    self._validation_errors.append(error_msg)

        return len(self._validation_errors) == 0, self._validation_errors if self._validation_errors else None

    def normalize_record(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize a record by coercing types and applying field constraints.
        Assumes record has already passed validation.
        Returns normalized record.
        """
        normalized = {}
        for field_name, constraint in self.constraints.items():
            if field_name in record:
                try:
                    normalized[field_name] = constraint._coerce_type(record[field_name])
                except Exception as e:
                    # This should not happen if validation passed, but handle gracefully
                    normalized[field_name] = record[field_name]
        return normalized

    def get_field_names(self) -> List[str]:
        """Get ordered list of all field names in the contract."""
        return list(self.constraints.keys())

    def get_field_types(self) -> Dict[str, FieldType]:
        """Get mapping of field names to types."""
        return {name: c.field_type for name, c in self.constraints.items()}

    def __repr__(self):
        return f"<DataContract with {len(self.constraints)} fields>"
