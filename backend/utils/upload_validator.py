"""
backend/utils/upload_validator.py
File upload validation with detailed error reporting.
Validates file size, type, encoding, and content structure.
"""
import os
import csv
import io
import logging
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional, Tuple

from backend.config import Config

logger = logging.getLogger(__name__)


class UploadErrorType(Enum):
    NO_FILE = "no_file"
    EMPTY_FILENAME = "empty_filename"
    INVALID_EXTENSION = "invalid_extension"
    FILE_TOO_LARGE = "file_too_large"
    EMPTY_FILE = "empty_file"
    ENCODING_ERROR = "encoding_error"
    INVALID_CSV_STRUCTURE = "invalid_csv_structure"
    NO_VALID_ROWS = "no_valid_rows"
    UNEXPECTED_ERROR = "unexpected_error"


@dataclass
class UploadError:
    error_type: UploadErrorType
    message: str
    details: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "type": self.error_type.value,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ValidationResult:
    is_valid: bool
    content: Optional[str] = None
    errors: Optional[List[UploadError]] = None
    encoding_used: Optional[str] = None
    row_count: Optional[int] = None
    file_size: Optional[int] = None

    @property
    def error_messages(self) -> List[str]:
        if not self.errors:
            return []
        return [err.message for err in self.errors]

    @property
    def primary_error(self) -> Optional[str]:
        if not self.errors:
            return None
        return self.errors[0].message


class UploadValidator:
    DEFAULT_MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    DEFAULT_MIN_FILE_SIZE = 1  # 1 byte minimum
    CHUNK_SIZE = 1024 * 1024  # 1 MB chunks for reading

    def __init__(self, app_config=None):
        cfg = app_config or Config()
        self._allowed_extensions = cfg.UPLOAD_EXTENSIONS
        self._max_file_size = getattr(cfg, 'MAX_UPLOAD_SIZE', self.DEFAULT_MAX_FILE_SIZE)
        self._min_file_size = self.DEFAULT_MIN_FILE_SIZE
        self._allowed_encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'iso-8859-1']

    def validate_upload(
        self,
        file_obj,
        check_csv_structure: bool = True
    ) -> ValidationResult:
        """
        Complete validation pipeline for file uploads.
        
        Args:
            file_obj: FileStorage object from Flask request
            check_csv_structure: Whether to validate CSV structure
            
        Returns:
            ValidationResult with validation status and details
        """
        errors: List[UploadError] = []

        # 1. Check if file exists
        if not file_obj:
            return ValidationResult(
                is_valid=False,
                errors=[UploadError(
                    error_type=UploadErrorType.NO_FILE,
                    message="No file was provided in the request."
                )]
            )

        # 2. Check filename
        filename = file_obj.filename
        if not filename or filename.strip() == "":
            return ValidationResult(
                is_valid=False,
                errors=[UploadError(
                    error_type=UploadErrorType.EMPTY_FILENAME,
                    message="No file was selected."
                )]
            )

        # 3. Validate file extension
        ext_error = self._validate_extension(filename)
        if ext_error:
            errors.append(ext_error)

        # 4. Check file size (read into memory safely)
        file_obj.seek(0, os.SEEK_END)
        file_size = file_obj.tell()
        file_obj.seek(0)
        
        size_error = self._validate_size(file_size)
        if size_error:
            errors.append(size_error)

        # 5. Handle empty file
        if file_size == 0:
            return ValidationResult(
                is_valid=False,
                errors=[UploadError(
                    error_type=UploadErrorType.EMPTY_FILE,
                    message="The uploaded file is empty."
                )]
            )

        # 6. Read and decode content with encoding detection
        content, encoding, enc_error = self._read_and_decode(file_obj)
        if enc_error:
            errors.append(enc_error)

        # If critical errors exist, return early
        critical_errors = [e for e in errors if e.error_type in [
            UploadErrorType.INVALID_EXTENSION,
            UploadErrorType.FILE_TOO_LARGE,
        ]]
        if critical_errors:
            return ValidationResult(
                is_valid=False,
                errors=errors,
                file_size=file_size
            )

        # 7. Validate content is not empty after stripping
        stripped_content = content.strip() if content else ""
        if not stripped_content:
            return ValidationResult(
                is_valid=False,
                errors=[UploadError(
                    error_type=UploadErrorType.EMPTY_FILE,
                    message="The uploaded file contains no content."
                )]
            )

        # 8. Validate CSV structure if requested
        if check_csv_structure and not errors:
            csv_error = self._validate_csv_structure(stripped_content)
            if csv_error:
                errors.append(csv_error)

        # 9. Return result
        if errors:
            return ValidationResult(
                is_valid=False,
                errors=errors,
                encoding_used=encoding,
                file_size=file_size
            )

        return ValidationResult(
            is_valid=True,
            content=content,
            encoding_used=encoding,
            row_count=len(stripped_content.splitlines()),
            file_size=file_size
        )

    def _validate_extension(self, filename: str) -> Optional[UploadError]:
        """Validate file has an allowed extension."""
        ext = os.path.splitext(filename)[1].lower()
        if not ext:
            return UploadError(
                error_type=UploadErrorType.INVALID_EXTENSION,
                message=f"File has no extension. Allowed: {', '.join(sorted(self._allowed_extensions))}",
                details=f"Expected one of: {self._allowed_extensions}"
            )
        if ext not in self._allowed_extensions:
            return UploadError(
                error_type=UploadErrorType.INVALID_EXTENSION,
                message=f"File type '{ext}' is not supported.",
                details=f"Allowed extensions: {', '.join(sorted(self._allowed_extensions))}"
            )
        return None

    def _validate_size(self, file_size: int) -> Optional[UploadError]:
        """Validate file size is within limits."""
        if file_size < self._min_file_size:
            return UploadError(
                error_type=UploadErrorType.EMPTY_FILE,
                message="The uploaded file is empty or too small to process."
            )
        if file_size > self._max_file_size:
            max_mb = self._max_file_size / (1024 * 1024)
            actual_mb = file_size / (1024 * 1024)
            return UploadError(
                error_type=UploadErrorType.FILE_TOO_LARGE,
                message=f"File size ({actual_mb:.1f} MB) exceeds the maximum allowed size ({max_mb:.0f} MB).",
                details=f"Maximum file size: {max_mb:.0f} MB"
            )
        return None

    def _read_and_decode(
        self,
        file_obj
    ) -> Tuple[str, Optional[str], Optional[UploadError]]:
        """
        Read file content and decode with encoding detection.
        Returns content, detected encoding, and any error.
        """
        try:
            raw_data = file_obj.read()
        except Exception as exc:
            return "", None, UploadError(
                error_type=UploadErrorType.UNEXPECTED_ERROR,
                message="Failed to read file content.",
                details=str(exc)
            )

        if not raw_data:
            return "", None, UploadError(
                error_type=UploadErrorType.EMPTY_FILE,
                message="The uploaded file contains no data."
            )

        # Try UTF-8 first (most common)
        if raw_data.startswith(b'\xef\xbb\xbf'):
            # UTF-8 BOM
            try:
                return raw_data.decode('utf-8-sig'), 'utf-8-sig', None
            except UnicodeDecodeError:
                pass

        # Try each encoding
        for encoding in self._allowed_encodings:
            try:
                return raw_data.decode(encoding), encoding, None
            except (UnicodeDecodeError, UnicodeError):
                continue

        # Fallback: decode with replacement characters
        decoded = raw_data.decode('utf-8', errors='replace')
        return decoded, 'utf-8 (lossy)', UploadError(
            error_type=UploadErrorType.ENCODING_ERROR,
            message="File encoding could not be fully recognized. Some characters may display incorrectly.",
            details="The file was decoded with some character substitutions. Consider re-saving in UTF-8 format."
        )

    def _validate_csv_structure(self, content: str) -> Optional[UploadError]:
        """Validate that content has valid CSV structure."""
        if not content:
            return UploadError(
                error_type=UploadErrorType.EMPTY_FILE,
                message="The file contains no parseable content."
            )

        try:
            reader = csv.reader(io.StringIO(content))
            rows = list(reader)

            if not rows:
                return UploadError(
                    error_type=UploadErrorType.INVALID_CSV_STRUCTURE,
                    message="The file appears to be empty or has no valid rows."
                )

            # Check if we have at least one row
            if len(rows) < 1:
                return UploadError(
                    error_type=UploadErrorType.NO_VALID_ROWS,
                    message="The file contains no data rows."
                )

            # Check column consistency (all rows should have similar column counts)
            first_row_len = len(rows[0]) if rows else 0
            if first_row_len < 2:
                return UploadError(
                    error_type=UploadErrorType.INVALID_CSV_STRUCTURE,
                    message="The file appears to have too few columns. Expected at least 2 columns.",
                    details=f"First row has {first_row_len} columns."
                )

            # Check for consistent column count (allow minor variations)
            inconsistent_rows = 0
            for i, row in enumerate(rows[1:min(11, len(rows))], start=2):
                if abs(len(row) - first_row_len) > 5:
                    inconsistent_rows += 1

            if inconsistent_rows > 3:
                return UploadError(
                    error_type=UploadErrorType.INVALID_CSV_STRUCTURE,
                    message="The CSV structure is inconsistent. Rows have varying column counts.",
                    details=f"Found {inconsistent_rows} rows with significantly different column counts. "
                            f"Expected approximately {first_row_len} columns."
                )

            return None

        except csv.Error as exc:
            return UploadError(
                error_type=UploadErrorType.INVALID_CSV_STRUCTURE,
                message="The file is not a valid CSV format.",
                details=str(exc)
            )
        except Exception as exc:
            return UploadError(
                error_type=UploadErrorType.UNEXPECTED_ERROR,
                message="An unexpected error occurred while validating the file structure.",
                details=str(exc)
            )
