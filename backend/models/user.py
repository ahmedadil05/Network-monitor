"""
models/user.py
User class — Source: Section 4.5.1.
Attributes: user_id, username, password_hash, role
Methods: login validation, session management support.
No flask_login required — uses Flask built-in session (see session_manager.py).
"""
from werkzeug.security import generate_password_hash, check_password_hash
from backend.database.db import query_db, execute_db


class User:
    """
    Represents an authenticated system user (administrator).
    Source: Section 4.5.1.
    """

    def __init__(self, user_id, username, password_hash, role):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role

    def get_id(self):
        return str(self.user_id)

    # ──────────────────────────────────────────────────────────────
    # Class methods (data access)
    # ──────────────────────────────────────────────────────────────

    @classmethod
    def get_by_id(cls, user_id):
        row = query_db("SELECT * FROM users WHERE user_id = ?", (user_id,), one=True)
        if row is None:
            return None
        return cls(row["user_id"], row["username"], row["password_hash"], row["role"])

    @classmethod
    def get_by_username(cls, username):
        row = query_db("SELECT * FROM users WHERE username = ?", (username,), one=True)
        if row is None:
            return None
        return cls(row["user_id"], row["username"], row["password_hash"], row["role"])

    @classmethod
    def create(cls, username, password, role="administrator"):
        """Create a new user. Section 4.5.1: password hash — never store plain text."""
        existing = query_db("SELECT user_id FROM users WHERE username = ?", (username,), one=True)
        if existing:
            raise ValueError(f"Username '{username}' already exists.")
        hashed = generate_password_hash(password)
        uid = execute_db(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hashed, role)
        )
        return cls(uid, username, hashed, role)

    # ──────────────────────────────────────────────────────────────
    # Instance methods
    # ──────────────────────────────────────────────────────────────

    def validate_password(self, password):
        """
        Verify plain-text password against stored hash.
        Source: Section 4.5.1 — 'methods for login validation'.
        """
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User id={self.user_id} username={self.username} role={self.role}>"
