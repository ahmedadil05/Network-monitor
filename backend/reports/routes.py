"""
backend/reports/routes.py
Report generation routes - API endpoints for generating reports.
"""
from flask import Blueprint, jsonify, request, Response, render_template
from backend.auth.session_manager import login_required, get_current_user
from backend.reports.report_generator import ReportGenerator

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/reports")
@login_required
def index():
    """Show available report types."""
    generator = ReportGenerator()
    report_types = generator.get_report_formats()
    return render_template(
        "reports.html",
        report_types=report_types,
        current_user=get_current_user()
    )


@reports_bp.route("/api/reports/summary")
@login_required
def summary_json():
    """Generate summary report in JSON format."""
    generator = ReportGenerator()
    report = generator.generate_summary_report()
    return jsonify(report)


@reports_bp.route("/api/reports/summary/csv")
@login_required
def summary_csv():
    """Download summary report as CSV."""
    generator = ReportGenerator()
    report = generator.generate_summary_report()
    csv_content = generator.to_csv(report)
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=summary_report_{generator.generated_at.replace(':', '-').replace(' ', '_')}.csv"
        }
    )


@reports_bp.route("/api/reports/anomalies")
@login_required
def anomalies_json():
    """Generate anomaly report with optional filters."""
    generator = ReportGenerator()
    severity = request.args.get("severity")
    status = request.args.get("status")
    
    report = generator.generate_anomaly_report(severity=severity, status=status)
    return jsonify(report)


@reports_bp.route("/api/reports/anomalies/csv")
@login_required
def anomalies_csv():
    """Download anomaly report as CSV."""
    generator = ReportGenerator()
    severity = request.args.get("severity")
    status = request.args.get("status")
    
    report = generator.generate_anomaly_report(severity=severity, status=status)
    csv_content = generator.to_csv(report)
    
    filename = f"anomalies_report"
    if severity:
        filename += f"_{severity.lower()}"
    if status:
        filename += f"_{status.lower()}"
    filename += f"_{generator.generated_at.replace(':', '-').replace(' ', '_')}.csv"
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@reports_bp.route("/api/reports/user")
@login_required
def user_report_json():
    """Generate user-specific activity report."""
    current_user = get_current_user()
    generator = ReportGenerator(user_id=current_user.user_id)
    report = generator.generate_user_report()
    return jsonify(report)


@reports_bp.route("/api/reports/user/csv")
@login_required
def user_report_csv():
    """Download user activity report as CSV."""
    current_user = get_current_user()
    generator = ReportGenerator(user_id=current_user.user_id)
    report = generator.generate_user_report()
    csv_content = generator.to_csv(report)
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=user_activity_{current_user.username}_{generator.generated_at.replace(':', '-').replace(' ', '_')}.csv"
        }
    )


@reports_bp.route("/api/reports/anomalies/html")
@login_required
def anomalies_html():
    """Generate anomaly report as HTML page."""
    generator = ReportGenerator()
    severity = request.args.get("severity")
    status = request.args.get("status")
    
    report = generator.generate_anomaly_report(severity=severity, status=status)
    
    return render_template(
        "report_anomalies.html",
        report=report,
        current_user=get_current_user()
    )


@reports_bp.route("/api/reports/user/html")
@login_required
def user_report_html():
    """Generate user activity report as HTML page."""
    current_user = get_current_user()
    generator = ReportGenerator(user_id=current_user.user_id)
    report = generator.generate_user_report()
    
    return render_template(
        "report_user.html",
        report=report,
        current_user=current_user
    )
