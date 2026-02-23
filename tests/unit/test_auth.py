"""
tests/unit/test_auth.py
Unit tests for User authentication — Section 4.5.1, Table 3.5.
"""
import unittest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from werkzeug.security import generate_password_hash
from backend.models.user import User

class TestUserModel(unittest.TestCase):
    def _user(self, password="pass"):
        return User(1, "admin", generate_password_hash(password), "administrator")

    def test_validate_correct(self):
        self.assertTrue(self._user("secret").validate_password("secret"))
    def test_validate_wrong(self):
        self.assertFalse(self._user("secret").validate_password("wrong"))
    def test_validate_empty(self):
        self.assertFalse(self._user("secret").validate_password(""))
    def test_get_id_string(self):
        self.assertIsInstance(self._user().get_id(), str)
        self.assertEqual(self._user().get_id(), "1")
    def test_role(self):
        self.assertEqual(self._user().role, "administrator")
    def test_hash_not_plain(self):
        u = self._user("mypassword")
        self.assertNotEqual(u.password_hash, "mypassword")

if __name__ == "__main__":
    unittest.main()
