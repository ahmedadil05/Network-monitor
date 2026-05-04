"""
auth/routes.py
Authentication routes — login, logout, and registration.
Source: Section 4.4.1 (Use Case: User Authentication)
Section 4.5.1 — login validation and session management.
Supports three roles: administrator, analyst, viewer.
"""
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash
)
from backend.models.user import User
from backend.auth.session_manager import login_user, logout_user, is_authenticated
from backend.auth.rbac import login_required

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Use Case: User Authentication (Section 4.4.2)."""
    if is_authenticated():
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        login_as = request.form.get("login_as", "user").strip().lower()

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        user = User.get_by_username(username)
        if user is None or not user.validate_password(password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        if login_as not in {"admin", "user"}:
            flash("Invalid login type selected.", "error")
            return render_template("login.html")

        if login_as == "admin" and user.role != "administrator":
            flash("This account is not an administrator account.", "error")
            return render_template("login.html")

        if login_as == "user" and user.role == "administrator":
            flash("Use 'Administrator' login for admin accounts.", "error")
            return render_template("login.html")

        login_user(user)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard.index"))

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Admin-only user registration.
    Regular users cannot self-register; must be created by administrator.
    """
    if is_authenticated():
        return redirect(url_for("dashboard.index"))

    # For MVP, disable self-registration
    # In production, admins only create users via /admin/users
    flash("User registration is restricted. Please contact your administrator.", "error")
    return redirect(url_for("auth.login"))


@auth_bp.route("/logout")
@login_required
def logout():
    """Use Case: session termination (Section 4.4.2)."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
