"""
dashboard/routes.py
Dashboard and anomaly review routes.
Source: Section 4.4.2 — Use Cases: View Dashboard, View Anomalies, Log Analysis.
Section 4.5.6 — DashboardController mediates data for presentation.
"""
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, current_app, jsonify
)
from backend.auth.session_manager import login_required, get_current_user
from backend.dashboard.dashboard_controller import DashboardController
from backend.ingestion.log_reader import LogIngestionService

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    """Use Case: View Dashboard (Section 4.4.2)."""
    summary      = DashboardController.get_summary()
    recent       = DashboardController.get_recent_anomalies(limit=8)
    severity_dist = DashboardController.get_severity_distribution()
    protocol_dist = DashboardController.get_protocol_distribution()
    timeline     = DashboardController.get_timeline_data(days=7)
    event_types  = DashboardController.get_event_type_distribution(limit=8)
    return render_template(
        "dashboard.html",
        summary=summary,
        recent_anomalies=recent,
        severity_dist=severity_dist,
        protocol_dist=protocol_dist,
        timeline=timeline,
        event_types=event_types,
        current_user=get_current_user(),
    )


@dashboard_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Use Case: Log Analysis — upload log data (Section 4.4.2)."""
    current_user = get_current_user()
    file_history = DashboardController.get_file_history()

    if request.method == "POST":
        if "log_file" not in request.files:
            flash("No file selected.", "error")
            return render_template("upload.html", file_history=file_history, current_user=current_user)

        f = request.files["log_file"]
        if f.filename == "":
            flash("No file selected.", "error")
            return render_template("upload.html", file_history=file_history, current_user=current_user)

        service = LogIngestionService(current_app.config)
        if not service.allowed_file(f.filename):
            flash("File type not supported. Allowed: .csv, .txt, .log", "error")
            return render_template("upload.html", file_history=file_history, current_user=current_user)

        try:
            content = f.read().decode("utf-8", errors="replace")
            file_id, n_entries, n_anomalies = service.ingest(
                content, f.filename, current_user.user_id
            )
            flash(
                f"File processed: {n_entries} log entries analysed, "
                f"{n_anomalies} anomalies detected.",
                "success"
            )
            return redirect(url_for("dashboard.anomalies"))
        except Exception as exc:
            flash(f"Processing error: {exc}", "error")

    return render_template("upload.html", file_history=file_history, current_user=current_user)


@dashboard_bp.route("/anomalies")
@login_required
def anomalies():
    """Use Case: View Anomalies (Section 4.4.2)."""
    page     = request.args.get("page", 1, type=int)
    severity = request.args.get("severity", None)
    status   = request.args.get("status", None)
    result   = DashboardController.get_anomaly_list(page=page, severity=severity, status=status)
    return render_template(
        "anomalies.html",
        **result,
        current_severity=severity,
        current_status=status,
        current_user=get_current_user(),
    )


@dashboard_bp.route("/anomalies/<int:result_id>")
@login_required
def anomaly_detail(result_id):
    """Anomaly detail with explainable output (Section 4.6)."""
    detail = DashboardController.get_anomaly_detail(result_id)
    if detail is None:
        flash("Anomaly record not found.", "error")
        return redirect(url_for("dashboard.anomalies"))
    return render_template("anomaly_detail.html", anomaly=detail, current_user=get_current_user())


@dashboard_bp.route("/anomalies/<int:result_id>/status", methods=["POST"])
@login_required
def update_status(result_id):
    """Update anomaly status — REVIEWED or DISMISSED."""
    new_status = request.form.get("status", "")
    if DashboardController.update_anomaly_status(result_id, new_status):
        flash(f"Anomaly status updated to {new_status}.", "success")
    else:
        flash("Invalid status value.", "error")
    return redirect(url_for("dashboard.anomaly_detail", result_id=result_id))


@dashboard_bp.route("/api/chart-data")
@login_required
def chart_data():
    """Internal API for Chart.js (Section 3.4.7 — no external APIs)."""
    return jsonify({
        "severity":    DashboardController.get_severity_distribution(),
        "protocols":   DashboardController.get_protocol_distribution(),
        "timeline":    DashboardController.get_timeline_data(days=7),
        "event_types": DashboardController.get_event_type_distribution(limit=8),
    })
