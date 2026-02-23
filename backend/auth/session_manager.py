"""
auth/session_manager.py
Session management using Flask's built-in session mechanism.
Source: Section 4.5.1 — 'methods for login validation and session management.'
No external libraries required — uses Flask's standard session (signed cookie).
"""
from functools import wraps
from flask import session, redirect, url_for, flash


def login_user(user):
    """Store user identity in the Flask session (signed cookie)."""
    session.clear()
    session["user_id"] = user.user_id
    session["username"] = user.username
    session["role"] = user.role


def logout_user():
    """Clear all session data."""
    session.clear()


def get_current_user():
    """
    Return the current logged-in User object, or None if not authenticated.
    Loads from database on every request (stateless session).
    """
    user_id = session.get("user_id")
    if user_id is None:
        return None
    from backend.models.user import User
    return User.get_by_id(user_id)


def login_required(f):
    """
    Decorator: redirects unauthenticated users to login page.
    Section 4.2.1 — 'user authentication is handled at this layer to ensure
    that only authorized administrators can access monitoring data.'
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.", "info")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def is_authenticated():
    """Return True if a user is currently logged in."""
    return "user_id" in session
