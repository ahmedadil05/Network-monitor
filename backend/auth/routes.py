"""
auth/routes.py
Authentication routes — login and logout.
Source: Section 4.4.1 (Use Case: User Authentication)
'The administrator provides valid credentials to access the system.'
Section 4.5.1 — login validation and session management.
"""
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash
)
from backend.models.user import User
from backend.auth.session_manager import login_user, logout_user, login_required, is_authenticated

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Use Case: User Authentication (Section 4.4.2).
    GET:  Render login form.
    POST: Validate credentials; redirect to dashboard on success.
    """
    if is_authenticated():
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("login.html")

        user = User.get_by_username(username)
        if user is None or not user.validate_password(password):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        login_user(user)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard.index"))

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    """Use Case: session termination (Section 4.4.2)."""
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
