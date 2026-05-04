"""
backend/auth/rbac.py
Role-Based Access Control decorators and middleware.
Enforces access control based on user roles: administrator, analyst, viewer.
"""
from functools import wraps
from flask import redirect, url_for, session, abort
from backend.models.user import User


def login_required(f):
    """Decorator: require user to be logged in."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator: require user to be an administrator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        
        user = User.get_by_id(session["user_id"])
        if not user or not user.is_admin():
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


def analyst_required(f):
    """Decorator: require user to be an analyst or administrator."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        
        user = User.get_by_id(session["user_id"])
        if not user or not user.is_analyst():
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function


def viewer_required(f):
    """Decorator: require user to be logged in (all authenticated users are viewers at minimum)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("auth.login"))
        
        user = User.get_by_id(session["user_id"])
        if not user or not user.is_viewer():
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function
