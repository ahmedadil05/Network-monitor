"""
auth/session_manager.py
Session management using Flask's built-in session mechanism.
Source: Section 4.5.1 — 'methods for login validation and session management.'
No external libraries required — uses Flask's standard session (signed cookie).
Supports three roles: administrator, analyst, viewer.
"""
from functools import wraps
from flask import session, redirect, url_for, flash, abort


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


def admin_required(f):
    """
    Decorator: requires administrator role.
    Only users with 'administrator' role can access admin-only features.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.", "info")
            return redirect(url_for("auth.login"))
        if session.get("role") != "administrator":
            flash("Access denied. Administrator privileges required.", "error")
            abort(403)
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    """
    Decorator: requires analyst or administrator role.
    Allows users to upload datasets and run analyses.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to access this page.", "info")
            return redirect(url_for("auth.login"))
        if session.get("role") not in ["administrator", "analyst"]:
            flash("Access denied. Analyst or higher privileges required.", "error")
            abort(403)
        return f(*args, **kwargs)
    return decorated


def viewer_required(f):
    """
    Decorator: requires any authenticated user (viewer or higher).
    All authenticated users have at least viewer role.
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


def is_admin():
    """Return True if current user is an administrator."""
    return session.get("role") == "administrator"


def is_analyst():
    """Return True if current user is an analyst or administrator."""
    return session.get("role") in ["administrator", "analyst"]


def is_viewer():
    """Return True if current user is authenticated (all users are at least viewers)."""
    return "user_id" in session
