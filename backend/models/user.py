"""
models/user.py
User class — Source: Section 4.5.1.
Attributes: user_id, username, password_hash, role
Methods: login validation, session management support.
Roles: administrator, analyst, viewer
"""
from werkzeug.security import generate_password_hash, check_password_hash
from backend.database.db import query_db, execute_db


class User:
    """
    Represents an authenticated system user.
    Source: Section 4.5.1.
    Roles: administrator (full access), analyst (upload/analysis), viewer (read-only)
    """

    def __init__(self, user_id, username, password_hash, role):
        self.user_id = user_id
        self.username = username
        self.password_hash = password_hash
        self.role = role

    def get_id(self):
        return str(self.user_id)

    def is_admin(self):
        """Check if user has administrator role."""
        return self.role == "administrator"

    def is_analyst(self):
        """Check if user has analyst or higher role."""
        return self.role in ["administrator", "analyst"]

    def is_viewer(self):
        """Check if user has at least viewer role."""
        return self.role in ["administrator", "analyst", "viewer"]

    # ──────────────────────────────────────────────────────────────
    # Class methods (data access)
    # ──────────────────────────────────────────────────────────────

    @classmethod
    def get_by_id(cls, user_id):
        row = query_db("SELECT * FROM users WHERE user_id = %s", (user_id,), one=True)
        if row is None:
            return None
        return cls(row["user_id"], row["username"], row["password_hash"], row["role"])

    @classmethod
    def get_by_username(cls, username):
        row = query_db("SELECT * FROM users WHERE username = %s", (username,), one=True)
        if row is None:
            return None
        return cls(row["user_id"], row["username"], row["password_hash"], row["role"])

    @classmethod
    def create(cls, username, password, role="viewer"):
        """Create a new user. Section 4.5.1: password hash — never store plain text."""
        if role not in ["administrator", "analyst", "viewer"]:
            raise ValueError(f"Invalid role '{role}'. Must be 'administrator', 'analyst', or 'viewer'.")
        
        existing = query_db("SELECT user_id FROM users WHERE username = %s", (username,), one=True)
        if existing:
            raise ValueError(f"Username '{username}' already exists.")
        
        hashed = generate_password_hash(password)
        uid = execute_db(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s) RETURNING user_id",
            (username, hashed, role),
            return_id=True
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

    @classmethod
    def get_all(cls):
        """Return all users."""
        rows = query_db("SELECT * FROM users ORDER BY user_id")
        return [cls(row["user_id"], row["username"], row["password_hash"], row["role"]) for row in rows]

    @classmethod
    def update(cls, user_id, username=None, role=None, password=None):
        """Update user details."""
        if role and role not in ["administrator", "analyst", "viewer"]:
            raise ValueError(f"Invalid role '{role}'. Must be 'administrator', 'analyst', or 'viewer'.")
        
        if username:
            existing = query_db(
                "SELECT user_id FROM users WHERE username = %s AND user_id != %s", 
                (username, user_id), 
                one=True
            )
            if existing:
                raise ValueError(f"Username '{username}' already exists.")
        
        if password:
            hashed = generate_password_hash(password)
            execute_db("UPDATE users SET password_hash = %s WHERE user_id = %s", (hashed, user_id))
        
        if username:
            execute_db("UPDATE users SET username = %s WHERE user_id = %s", (username, user_id))
        
        if role:
            execute_db("UPDATE users SET role = %s WHERE user_id = %s", (role, user_id))
        
        return cls.get_by_id(user_id)

    @classmethod
    def delete(cls, user_id):
        """Delete a user by ID."""
        execute_db("DELETE FROM users WHERE user_id = %s", (user_id,))

    def __repr__(self):
        return f"<User id={self.user_id} username={self.username} role={self.role}>"
