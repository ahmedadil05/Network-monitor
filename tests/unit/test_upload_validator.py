"""
tests/unit/test_upload_validator.py
Unit tests for UploadValidator — file validation with detailed error reporting.
"""
import unittest
import sys
import os
from io import BytesIO
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from backend.utils.upload_validator import (
    UploadValidator,
    UploadErrorType,
    ValidationResult,
)


class MockFileStorage:
    def __init__(self, filename, content, size=None):
        self.filename = filename
        self._content = content if isinstance(content, bytes) else content.encode('utf-8')
        self._size = size or len(self._content)
        self._pos = 0

    def read(self, size=-1):
        if size == -1:
            result = self._content[self._pos:]
            self._pos = len(self._content)
        else:
            result = self._content[self._pos:self._pos + size]
            self._pos += len(result)
        return result

    def seek(self, pos, whence=0):
        if whence == os.SEEK_END:
            self._pos = self._size + pos
        elif whence == os.SEEK_SET:
            self._pos = pos
        else:
            self._pos += pos
        return self._pos

    def tell(self):
        return self._pos


class TestExtensionValidation(unittest.TestCase):
    def setUp(self):
        self.validator = UploadValidator()

    def test_valid_csv_extension(self):
        file = MockFileStorage("test.csv", "0,tcp,http,SF,100,200,0,0,0,normal")
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)

    def test_valid_txt_extension(self):
        file = MockFileStorage("test.txt", "0,tcp,http,SF,100,200,0,0,0,normal")
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)

    def test_valid_log_extension(self):
        file = MockFileStorage("test.log", "0,tcp,http,SF,100,200,0,0,0,normal")
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)

    def test_invalid_extension_rejected(self):
        file = MockFileStorage("test.pdf", "data")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.INVALID_EXTENSION)

    def test_no_extension_rejected(self):
        file = MockFileStorage("testfile", "data")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.INVALID_EXTENSION)

    def test_case_insensitive_extension(self):
        file = MockFileStorage("test.CSV", "0,tcp,http,SF,100,200,0,0,0,normal")
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)


class TestSizeValidation(unittest.TestCase):
    def setUp(self):
        self.validator = UploadValidator()

    def test_empty_file_rejected(self):
        file = MockFileStorage("test.csv", "")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.EMPTY_FILE)

    def test_valid_size_accepted(self):
        content = "0,tcp,http,SF,100,200,0,0,0,normal" * 10
        file = MockFileStorage("test.csv", content)
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.file_size, len(content))

    def test_oversized_file_rejected(self):
        from backend.config import Config
        class SmallConfig:
            UPLOAD_EXTENSIONS = Config.UPLOAD_EXTENSIONS
            MAX_UPLOAD_SIZE = 100
        validator = UploadValidator(SmallConfig())
        content = "0,tcp,http,SF,100,200,0,0,0,normal" * 20
        file = MockFileStorage("test.csv", content)
        result = validator.validate_upload(file)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.FILE_TOO_LARGE)


class TestEncodingValidation(unittest.TestCase):
    def setUp(self):
        self.validator = UploadValidator()

    def test_utf8_content(self):
        content = "Hello, World! こんにちは"
        file = MockFileStorage("test.csv", content)
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.encoding_used, 'utf-8')

    def test_utf8_bom_handled(self):
        content = "\ufeffnormal,tcp,http,SF,100,200,0,0,0,normal"
        file = MockFileStorage("test.csv", content)
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.encoding_used, 'utf-8-sig')

    def test_latin1_content(self):
        content = "café, naïve"  # Contains non-ASCII characters
        file = MockFileStorage("test.csv", content)
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)


class TestCSVStructureValidation(unittest.TestCase):
    def setUp(self):
        self.validator = UploadValidator()

    def test_valid_csv_structure(self):
        content = "0,tcp,http,SF,100,200,0,0,0,normal\n1,udp,dns,SF,50,100,0,0,0,neptune"
        file = MockFileStorage("test.csv", content)
        result = self.validator.validate_upload(file)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.row_count, 2)

    def test_empty_csv_rejected(self):
        file = MockFileStorage("test.csv", "")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)

    def test_whitespace_only_rejected(self):
        file = MockFileStorage("test.csv", "   \n\n   ")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)


class TestNoFileHandling(unittest.TestCase):
    def setUp(self):
        self.validator = UploadValidator()

    def test_none_file_rejected(self):
        result = self.validator.validate_upload(None)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.NO_FILE)

    def test_empty_filename_rejected(self):
        file = MockFileStorage("", "data")
        result = self.validator.validate_upload(file)
        self.assertFalse(result.is_valid)
        self.assertEqual(result.errors[0].error_type, UploadErrorType.EMPTY_FILENAME)


class TestValidationResult(unittest.TestCase):
    def test_valid_result_properties(self):
        result = ValidationResult(
            is_valid=True,
            content="test content",
            encoding_used="utf-8",
            row_count=5,
            file_size=100
        )
        self.assertEqual(result.error_messages, [])
        self.assertIsNone(result.primary_error)

    def test_invalid_result_properties(self):
        from backend.utils.upload_validator import UploadError
        errors = [
            UploadError(UploadErrorType.INVALID_EXTENSION, "Invalid extension"),
            UploadError(UploadErrorType.FILE_TOO_LARGE, "File too large")
        ]
        result = ValidationResult(is_valid=False, errors=errors)
        self.assertEqual(len(result.error_messages), 2)
        self.assertEqual(result.primary_error, "Invalid extension")


if __name__ == "__main__":
    unittest.main()
