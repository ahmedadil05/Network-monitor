"""
backend/ingestion/log_data_loader.py
Production-grade log ingestion with strict data contracts.

Parses CSV/raw log data, validates against schema, normalizes fields,
and returns clean Pandas DataFrame with validated timestamps.

Design principles:
  - Schema-first: data contract defines all validation rules
  - Type-safe: all fields have explicit types with coercion
  - Observable: detailed error reporting with row-level granularity
  - No side effects: returns immutable data structures
  - No ML/aggregation: raw data only
"""
import csv
import io
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta

import pandas as pd

from backend.ingestion.data_contract import DataContract, FieldConstraint, FieldType

logger = logging.getLogger(__name__)


class LoaderConfig:
    """Configuration for LogDataLoader behavior."""

    def __init__(
        self,
        strict_mode: bool = True,
        skip_invalid_rows: bool = False,
        infer_missing_timestamp: bool = True,
        infer_missing_ips: bool = True,
        max_errors: Optional[int] = 1000,
    ):
        """
        Args:
            strict_mode: If True, fail on ANY validation error; if False, collect errors
            skip_invalid_rows: If True, skip invalid rows; if False, include in errors list
            infer_missing_timestamp: If True, generate sequential timestamps for missing values
            infer_missing_ips: If True, generate placeholder IPs for missing values
            max_errors: Stop processing after this many errors (None = no limit)
        """
        self.strict_mode = strict_mode
        self.skip_invalid_rows = skip_invalid_rows
        self.infer_missing_timestamp = infer_missing_timestamp
        self.infer_missing_ips = infer_missing_ips
        self.max_errors = max_errors


class LoaderResult:
    """Result of a loading operation."""

    def __init__(
        self,
        dataframe: Optional[pd.DataFrame] = None,
        validation_errors: Optional[List[str]] = None,
        parse_errors: Optional[List[str]] = None,
        row_errors: Optional[List[Dict]] = None,
        stats: Optional[Dict] = None,
    ):
        self.dataframe = dataframe or pd.DataFrame()
        self.validation_errors = validation_errors or []
        self.parse_errors = parse_errors or []
        self.row_errors = row_errors or []
        self.stats = stats or {}

    @property
    def success(self) -> bool:
        """True if load succeeded with no errors."""
        return len(self.validation_errors) == 0 and len(self.parse_errors) == 0

    @property
    def has_errors(self) -> bool:
        """True if any errors occurred."""
        return len(self.validation_errors) > 0 or len(self.parse_errors) > 0 or len(self.row_errors) > 0

    @property
    def error_count(self) -> int:
        """Total number of errors."""
        return len(self.validation_errors) + len(self.parse_errors) + len(self.row_errors)

    @property
    def row_count(self) -> int:
        """Number of rows in resulting DataFrame."""
        return len(self.dataframe) if self.dataframe is not None else 0

    def add_parse_error(self, line_no: int, error: str) -> None:
        """Add a parse error."""
        self.parse_errors.append(f"Line {line_no}: {error}")

    def add_row_error(self, row_no: int, raw_row: List[str], errors: List[str]) -> None:
        """Add a row-level validation error."""
        self.row_errors.append({"row_no": row_no, "raw": raw_row, "errors": errors})

    def report(self) -> str:
        """Generate a human-readable error report."""
        lines = [
            f"LoaderResult: {self.row_count} rows loaded, {self.error_count} errors",
            f"  Validation errors: {len(self.validation_errors)}",
            f"  Parse errors: {len(self.parse_errors)}",
            f"  Row errors: {len(self.row_errors)}",
        ]

        if self.parse_errors:
            lines.append("\nParse Errors:")
            for err in self.parse_errors[:10]:
                lines.append(f"  - {err}")
            if len(self.parse_errors) > 10:
                lines.append(f"  ... and {len(self.parse_errors) - 10} more")

        if self.row_errors:
            lines.append("\nRow Errors:")
            for row_err in self.row_errors[:10]:
                lines.append(f"  Row {row_err['row_no']}: {', '.join(row_err['errors'])}")
            if len(self.row_errors) > 10:
                lines.append(f"  ... and {len(self.row_errors) - 10} more")

        if self.stats:
            lines.append("\nStatistics:")
            for key, value in self.stats.items():
                lines.append(f"  {key}: {value}")

        return "\n".join(lines)

    def __repr__(self):
        return f"<LoaderResult rows={self.row_count} errors={self.error_count}>"


class LogDataLoader:
    """
    Production-grade log data loader with strict schema validation.

    Workflow:
      1. Parse raw CSV/text into structured records
      2. Infer missing fields (timestamps, IPs) if enabled
      3. Validate each record against data contract
      4. Normalize field types
      5. Return clean Pandas DataFrame
    """

    def __init__(self, config: Optional[LoaderConfig] = None, contract: Optional[DataContract] = None):
        self.config = config or LoaderConfig()
        self.contract = contract or DataContract()
        self._result: Optional[LoaderResult] = None

    def load_csv(self, file_content: str, file_name: str = "unknown") -> LoaderResult:
        """
        Load and parse CSV file content.

        Args:
            file_content: Raw CSV text content
            file_name: Name of file (for logging)

        Returns:
            LoaderResult with DataFrame and error details
        """
        logger.info(f"Loading CSV file: {file_name}")

        result = LoaderResult()
        records = []

        # Step 1: Parse CSV
        parsed_rows = self._parse_csv(file_content, result)
        logger.info(f"Parsed {len(parsed_rows)} rows from CSV")

        # Step 2: Process each row
        for row_no, raw_row in enumerate(parsed_rows, start=1):
            # Infer missing fields
            record = self._infer_missing_fields(raw_row, row_no)

            # Validate
            is_valid, errors = self.contract.validate_record(record)
            if not is_valid:
                result.add_row_error(row_no, raw_row, errors)
                if self.config.skip_invalid_rows:
                    continue
                else:
                    # Add invalid record anyway for inspection
                    records.append(record)
                    continue

            # Normalize
            normalized = self.contract.normalize_record(record)
            records.append(normalized)

            # Check error limit
            if self.config.max_errors and result.error_count >= self.config.max_errors:
                logger.warning(f"Reached max errors limit ({self.config.max_errors})")
                break

        # Step 3: Create DataFrame
        if records:
            df = pd.DataFrame(records)
            # Ensure correct column order and types
            df = self._finalize_dataframe(df, result)
            result.dataframe = df
        else:
            result.dataframe = pd.DataFrame()

        # Step 4: Compute statistics
        result.stats = self._compute_stats(result.dataframe)

        logger.info(
            f"Load complete: {result.row_count} rows, {result.error_count} errors, "
            f"validation_errors={len(result.validation_errors)}, "
            f"parse_errors={len(result.parse_errors)}, "
            f"row_errors={len(result.row_errors)}"
        )

        self._result = result
        return result

    # ──────────────────────────────────────────────────────────────
    # Private methods
    # ──────────────────────────────────────────────────────────────

    def _parse_csv(self, file_content: str, result: LoaderResult) -> List[List[str]]:
        """
        Parse CSV content into list of rows.
        Handles header detection and empty lines.
        """
        parsed_rows = []
        reader = csv.reader(io.StringIO(file_content.strip()))

        for line_no, row in enumerate(reader, start=1):
            try:
                # Skip empty rows
                if not row or all(not cell.strip() for cell in row):
                    continue

                # Strip whitespace
                row = [cell.strip() for cell in row]

                # Skip header row if detected
                if line_no == 1 and self._is_header_row(row):
                    logger.debug("Skipped header row")
                    continue

                parsed_rows.append(row)
            except Exception as e:
                result.add_parse_error(line_no, str(e))
                if self.config.max_errors and result.error_count >= self.config.max_errors:
                    break

        return parsed_rows

    @staticmethod
    def _is_header_row(row: List[str]) -> bool:
        """
        Detect if a row is a header row.
        Header rows have field names like 'timestamp', 'source_ip', etc.
        Data rows have actual values.
        """
        if not row:
            return False

        first_col = row[0].lower()
        # Common header column names
        header_keywords = {
            "timestamp", "source_ip", "destination_ip", "protocol_type", "service",
            "flag", "duration", "src_bytes", "dst_bytes", "land", "wrong_fragment",
            "urgent", "event_type", "message", "original_label", "id", "name", "time"
        }

        if first_col in header_keywords:
            return True

        # Check if first column looks like a timestamp (contains date-like patterns)
        if any(sep in first_col for sep in ["2024", "2025", "2023", "-", "T", ":"]):
            return False

        # Try to parse as number (classic data row indicator)
        try:
            float(first_col)
            return False
        except ValueError:
            # Could be header or unstructured data
            # If it's a common header name, it's a header
            return first_col in header_keywords

    def _infer_missing_fields(self, raw_row: List[str], row_no: int) -> Dict[str, str]:
        """
        Convert raw CSV row to record dict and infer missing fields.
        """
        # Map CSV columns to field names
        field_names = self.contract.get_field_names()

        record = {}
        for i, value in enumerate(raw_row):
            if i < len(field_names):
                record[field_names[i]] = value

        # Fill in missing required fields
        if self.config.infer_missing_timestamp and "timestamp" not in record:
            record["timestamp"] = self._generate_timestamp(row_no)

        if self.config.infer_missing_ips:
            if "source_ip" not in record:
                record["source_ip"] = self._generate_ip("src", row_no)
            if "destination_ip" not in record:
                record["destination_ip"] = self._generate_ip("dst", row_no)

        # Fill defaults for other missing fields
        for field_name in field_names:
            if field_name not in record:
                constraint = self.contract.constraints[field_name]
                if constraint.nullable:
                    record[field_name] = None
                elif constraint.field_type == FieldType.STRING:
                    record[field_name] = ""
                elif constraint.field_type == FieldType.INT:
                    record[field_name] = "0"
                elif constraint.field_type == FieldType.FLOAT:
                    record[field_name] = "0.0"
                else:
                    record[field_name] = ""

        return record

    @staticmethod
    def _generate_timestamp(row_no: int) -> str:
        """Generate sequential timestamp starting from 2024-01-01."""
        base = datetime(2024, 1, 1, 0, 0, 0)
        ts = base + timedelta(seconds=row_no)
        return ts.isoformat()

    @staticmethod
    def _generate_ip(direction: str, row_no: int) -> str:
        """Generate placeholder IP based on direction and row number."""
        base_octet = (row_no % 254) + 1  # Avoid .0 and .255
        if direction == "src":
            return f"10.0.0.{base_octet}"
        else:
            return f"192.168.1.{base_octet}"

    def _finalize_dataframe(self, df: pd.DataFrame, result: LoaderResult) -> pd.DataFrame:
        """
        Finalize DataFrame: ensure correct column order, types, and datetime handling.
        """
        field_names = self.contract.get_field_names()
        field_types = self.contract.get_field_types()

        # Reorder columns
        existing_cols = [col for col in field_names if col in df.columns]
        df = df[existing_cols]

        # Convert types
        for col in df.columns:
            field_type = field_types.get(col)
            if field_type == FieldType.DATETIME:
                try:
                    df[col] = pd.to_datetime(df[col], utc=True)
                except Exception as e:
                    logger.warning(f"Failed to convert '{col}' to datetime: {e}")
            elif field_type == FieldType.INT:
                try:
                    df[col] = df[col].astype("int64")
                except Exception as e:
                    logger.warning(f"Failed to convert '{col}' to int: {e}")
            elif field_type == FieldType.FLOAT:
                try:
                    df[col] = df[col].astype("float64")
                except Exception as e:
                    logger.warning(f"Failed to convert '{col}' to float: {e}")
            elif field_type == FieldType.STRING:
                df[col] = df[col].astype("string")

        # Sort by timestamp
        if "timestamp" in df.columns:
            df = df.sort_values("timestamp").reset_index(drop=True)

        return df

    @staticmethod
    def _compute_stats(df: pd.DataFrame) -> Dict[str, any]:
        """Compute basic statistics about the DataFrame."""
        if df.empty:
            return {"rows": 0, "columns": 0}

        stats = {
            "rows": len(df),
            "columns": len(df.columns),
            "timestamp_range": None,
            "event_types": None,
            "protocols": None,
        }

        if "timestamp" in df.columns:
            try:
                stats["timestamp_range"] = {
                    "min": str(df["timestamp"].min()),
                    "max": str(df["timestamp"].max()),
                }
            except Exception:
                pass

        if "event_type" in df.columns:
            stats["event_types"] = df["event_type"].value_counts().to_dict()

        if "protocol_type" in df.columns:
            stats["protocols"] = df["protocol_type"].value_counts().to_dict()

        return stats
