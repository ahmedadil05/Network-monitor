"""
backend/admin/routes.py
Admin panel routes for user and system management.
Only accessible by administrators.
Supports three roles: administrator, analyst, viewer.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from backend.auth.session_manager import admin_required, get_current_user
from backend.models.user import User
from backend.database.db import query_db, execute_db
from datetime import datetime, timedelta

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

# Valid roles
VALID_ROLES = ["administrator", "analyst", "viewer"]
ASSIGNABLE_ROLES = ["analyst", "viewer"]


@admin_bp.route("/users")
@admin_required
def users():
    """List all users."""
    all_users = User.get_all()
    return render_template("admin_users.html", users=all_users, current_user=get_current_user(), valid_roles=VALID_ROLES)


@admin_bp.route("/users/add", methods=["POST"])
@admin_required
def add_user():
    """Add a new user."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("admin.users"))

    if role not in ASSIGNABLE_ROLES:
        flash(f"Invalid role '{role}'. Must be one of: {', '.join(ASSIGNABLE_ROLES)}", "error")
        return redirect(url_for("admin.users"))

    try:
        User.create(username=username, password=password, role=role)
        # Log admin action
        _log_audit("CREATE_USER", f"user:{username}", f"Created user with role: {role}")
        flash(f"User '{username}' created successfully with role '{role}'.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("admin.users"))


@admin_bp.route("/users/edit/<int:user_id>", methods=["POST"])
@admin_required
def edit_user(user_id):
    """Edit a user."""
    user = User.get_by_id(user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin.users"))

    username = request.form.get("username", "").strip()
    role = request.form.get("role", user.role)
    password = request.form.get("password", "").strip()

    if not username:
        flash("Username is required.", "error")
        return redirect(url_for("admin.users"))

    if role not in ASSIGNABLE_ROLES:
        flash(f"Invalid role '{role}'. Must be one of: {', '.join(ASSIGNABLE_ROLES)}", "error")
        return redirect(url_for("admin.users"))

    try:
        changes = []
        if username != user.username:
            changes.append(f"username: {user.username} → {username}")
        if role != user.role:
            changes.append(f"role: {user.role} → {role}")
        if password:
            changes.append("password: updated")
        
        if password:
            User.update(user_id, username=username, role=role, password=password)
        else:
            User.update(user_id, username=username, role=role)
        
        # Log admin action
        _log_audit("UPDATE_USER", f"user:{user_id}", f"Updated user: {', '.join(changes)}")
        flash(f"User '{username}' updated successfully.", "success")
    except ValueError as e:
        flash(str(e), "error")

    return redirect(url_for("admin.users"))


@admin_bp.route("/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    """Delete a user."""
    current = get_current_user()
    if user_id == current.user_id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin.users"))

    user = User.get_by_id(user_id)
    if user:
        username = user.username
        User.delete(user_id)
        # Log admin action
        _log_audit("DELETE_USER", f"user:{user_id}", f"Deleted user: {username}")
        flash(f"User '{username}' deleted.", "success")
    else:
        flash("User not found.", "error")

    return redirect(url_for("admin.users"))


@admin_bp.route("/dashboard")
@admin_required
def index():
    """Admin dashboard overview."""
    total_users = query_db("SELECT COUNT(*) as c FROM users", one=True)["c"]
    total_logs = query_db("SELECT COUNT(*) as c FROM log_entries", one=True)["c"]
    total_anomalies = query_db("SELECT COUNT(*) as c FROM anomaly_results", one=True)["c"]
    total_files = query_db("SELECT COUNT(*) as c FROM raw_log_files", one=True)["c"]
    
    # Role distribution
    role_dist = query_db("SELECT role, COUNT(*) as count FROM users GROUP BY role")
    role_dict = {row["role"]: row["count"] for row in role_dist}
    
    # Recent anomalies
    recent_anomalies = query_db("""
        SELECT a.result_id, a.severity, a.detection_time, l.source_ip
        FROM anomaly_results a
        JOIN log_entries l ON a.log_id = l.log_id
        ORDER BY a.detection_time DESC LIMIT 10
    """)
    
    # Recent audit log
    recent_audit = query_db("""
        SELECT * FROM audit_log
        ORDER BY timestamp DESC LIMIT 20
    """)
    
    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_logs=total_logs,
        total_anomalies=total_anomalies,
        total_files=total_files,
        role_distribution=role_dict,
        recent_anomalies=recent_anomalies,
        recent_audit=recent_audit,
        current_user=get_current_user()
    )


@admin_bp.route("/audit-log")
@admin_required
def audit_log():
    """View audit log of admin actions."""
    page = request.args.get("page", 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page
    
    # Get total count
    total = query_db("SELECT COUNT(*) as c FROM audit_log", one=True)["c"]
    
    # Get paginated results
    logs = query_db("""
        SELECT * FROM audit_log
        ORDER BY timestamp DESC
        LIMIT %s OFFSET %s
    """, (per_page, offset))
    
    return render_template(
        "admin_audit_log.html",
        logs=logs,
        page=page,
        total=total,
        per_page=per_page,
        current_user=get_current_user()
    )


@admin_bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    """Admin settings."""
    if request.method == "POST":
        # TODO: Save settings to database
        flash("Settings saved successfully.", "success")
        return redirect(url_for("admin.settings"))
    
    return render_template("admin_settings.html", current_user=get_current_user())


def _log_audit(action, resource, details):
    """Log an admin action to the audit_log table."""
    current = get_current_user()
    execute_db(
        """
        INSERT INTO audit_log (user_id, action, resource, details, timestamp)
        VALUES (%s, %s, %s, %s, NOW())
        """,
        (current.user_id if current else None, action, resource, details)
    )
