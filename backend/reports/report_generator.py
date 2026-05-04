"""
backend/reports/report_generator.py
Report generation for processed log data and anomaly detection results.
Supports multiple formats: JSON, CSV, HTML, and PDF report views.
"""
import csv
import io
import json
from datetime import datetime
from typing import List, Dict, Optional
from backend.database.db import query_db


class ReportGenerator:
    """Generates reports from processed log data and anomaly results."""

    def __init__(self, user_id: Optional[int] = None, username: Optional[str] = None):
        self.user_id = user_id
        self.username = username
        self.generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def generate_summary_report(self) -> Dict:
        """Generate a summary report of all system data."""
        total_entries = query_db(
            "SELECT COUNT(*) as c FROM log_entries", one=True
        )["c"]

        total_anomalies = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results", one=True
        )["c"]

        open_anomalies = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE status = 'OPEN'", one=True
        )["c"]

        high_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'HIGH'", one=True
        )["c"]

        medium_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'MEDIUM'", one=True
        )["c"]

        low_severity = query_db(
            "SELECT COUNT(*) as c FROM anomaly_results WHERE severity = 'LOW'", one=True
        )["c"]

        total_files = query_db(
            "SELECT COUNT(*) as c FROM raw_log_files", one=True
        )["c"]

        protocols = query_db(
            "SELECT protocol_type, COUNT(*) as count FROM log_entries GROUP BY protocol_type"
        )

        event_types = query_db(
            """SELECT event_type, COUNT(*) as count FROM log_entries
               WHERE event_type != 'NORMAL' GROUP BY event_type ORDER BY count DESC"""
        )

        severity_dist = query_db(
            "SELECT severity, COUNT(*) as count FROM anomaly_results GROUP BY severity"
        )

        return {
            "report_type": "summary",
            "generated_at": self.generated_at,
            "period": "all_time",
            "summary": {
                "total_log_entries": total_entries,
                "total_anomalies": total_anomalies,
                "open_anomalies": open_anomalies,
                "total_files_processed": total_files,
                "resolution_rate": round(((total_anomalies - open_anomalies) / total_anomalies * 100) if total_anomalies > 0 else 0, 2),
            },
            "severity_breakdown": {
                "high": high_severity,
                "medium": medium_severity,
                "low": low_severity,
            },
            "protocol_distribution": [dict(row) for row in protocols],
            "event_type_distribution": [dict(row) for row in event_types[:10]],
            "severity_distribution": [dict(row) for row in severity_dist],
        }

    def generate_anomaly_report(self, severity: Optional[str] = None, status: Optional[str] = None) -> Dict:
        """Generate a detailed report of anomalies with optional filters."""
        where_parts = []
        args = []

        if severity:
            where_parts.append("ar.severity = %s")
            args.append(severity.upper())
        if status:
            where_parts.append("ar.status = %s")
            args.append(status.upper())

        where_sql = ("WHERE " + " AND ".join(where_parts)) if where_parts else ""

        anomalies = query_db(
            f"""SELECT ar.result_id, ar.anomaly_score, ar.severity, ar.status,
                      ar.detection_time, ar.explanation,
                      le.log_id, le.timestamp, le.source_ip, le.destination_ip,
                      le.event_type, le.protocol_type, le.service,
                      le.src_bytes, le.dst_bytes, le.duration
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               {where_sql}
               ORDER BY ar.detection_time DESC""",
            args
        )

        return {
            "report_type": "anomaly_detail",
            "generated_at": self.generated_at,
            "filters": {
                "severity": severity,
                "status": status,
            },
            "total_anomalies": len(anomalies),
            "anomalies": [dict(row) for row in anomalies],
        }

    def generate_user_report(self) -> Dict:
        """Generate a report specific to the current user's data."""
        if not self.user_id:
            return {"error": "User ID required for user-specific report"}

        files_uploaded = query_db(
            "SELECT COUNT(*) as c FROM raw_log_files WHERE uploaded_by = %s",
            (self.user_id,), one=True
        )["c"]

        entries_processed = query_db(
            """SELECT COUNT(*) as c FROM log_entries le
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = %s""",
            (self.user_id,), one=True
        )["c"]

        anomalies_found = query_db(
            """SELECT COUNT(*) as c FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = %s""",
            (self.user_id,), one=True
        )["c"]

        open_issues = query_db(
            """SELECT COUNT(*) as c FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = %s AND ar.status = 'OPEN'""",
            (self.user_id,), one=True
        )["c"]

        user_files = query_db(
            """SELECT f.file_id, f.file_name, f.upload_time, f.row_count, f.processed
               FROM raw_log_files f
               WHERE f.uploaded_by = %s
               ORDER BY f.upload_time DESC""",
            (self.user_id,)
        )

        user_anomalies = query_db(
            """SELECT ar.result_id, ar.severity, ar.status, ar.detection_time,
                      le.event_type, le.protocol_type, le.source_ip
               FROM anomaly_results ar
               JOIN log_entries le ON ar.log_id = le.log_id
               JOIN raw_log_files f ON le.file_id = f.file_id
               WHERE f.uploaded_by = %s
               ORDER BY ar.detection_time DESC
               LIMIT 50""",
            (self.user_id,)
        )

        return {
            "report_type": "user_activity",
            "generated_at": self.generated_at,
            "user_id": self.user_id,
            "summary": {
                "files_uploaded": files_uploaded,
                "entries_processed": entries_processed,
                "anomalies_found": anomalies_found,
                "open_issues": open_issues,
            },
            "files": [dict(row) for row in user_files],
            "recent_anomalies": [dict(row) for row in user_anomalies],
        }

    def to_json(self, report_data: Dict) -> str:
        """Convert report data to JSON string."""
        return json.dumps(report_data, indent=2, default=str)

    def to_csv(self, report_data: Dict) -> str:
        """Convert report anomalies to CSV format."""
        output = io.StringIO()
        
        if report_data.get("report_type") == "anomaly_detail":
            anomalies = report_data.get("anomalies", [])
            if anomalies:
                fieldnames = [
                    "result_id", "log_id", "anomaly_score", "severity", "status",
                    "detection_time", "timestamp", "source_ip", "destination_ip",
                    "event_type", "protocol_type", "service", "src_bytes",
                    "dst_bytes", "duration", "explanation"
                ]
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for anomaly in anomalies:
                    writer.writerow(anomaly)
        
        elif report_data.get("report_type") == "user_activity":
            anomalies = report_data.get("recent_anomalies", [])
            if anomalies:
                fieldnames = ["result_id", "severity", "status", "detection_time", 
                             "event_type", "protocol_type", "source_ip"]
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                for anomaly in anomalies:
                    writer.writerow(anomaly)
        
        return output.getvalue()

    def get_report_formats(self) -> List[Dict]:
        """Return available report types and formats."""
        return [
            {
                "type": "summary",
                "name": "System Summary Report",
                "description": "Overview of all processed data and anomaly statistics",
                "formats": ["json", "csv", "pdf"]
            },
            {
                "type": "anomaly_detail",
                "name": "Anomaly Details Report",
                "description": "Detailed list of all detected anomalies with filtering options",
                "formats": ["json", "csv", "html", "pdf"]
            },
            {
                "type": "user_activity",
                "name": "User Activity Report",
                "description": "Personal report of your uploaded files and detected anomalies",
                "formats": ["json", "csv", "html", "pdf"]
            },
        ]

    def to_pdf(self, report_data: Dict) -> bytes:
        """Generate PDF report from data."""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.lib import colors
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.units import inch
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
            elements = []
            styles = getSampleStyleSheet()
            
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.HexColor('#1f4e79')
            )
            
            subtitle_style = ParagraphStyle(
                'Subtitle',
                parent=styles['Normal'],
                fontSize=10,
                textColor=colors.grey,
                spaceAfter=20
            )
            
            section_style = ParagraphStyle(
                'Section',
                parent=styles['Heading2'],
                fontSize=14,
                spaceBefore=20,
                spaceAfter=10,
                textColor=colors.HexColor('#1f4e79')
            )
            
            if report_data.get("report_type") == "summary":
                elements.append(Paragraph("Network Monitor - Summary Report", title_style))
                elements.append(Paragraph(f"Generated: {self.generated_at}", subtitle_style))
                
                summary = report_data.get("summary", {})
                elements.append(Paragraph("Overview", section_style))
                
                data = [
                    ["Metric", "Value"],
                    ["Total Log Entries", str(summary.get("total_log_entries", 0))],
                    ["Total Anomalies", str(summary.get("total_anomalies", 0))],
                    ["Open Anomalies", str(summary.get("open_anomalies", 0))],
                    ["Files Processed", str(summary.get("total_files_processed", 0))],
                    ["Resolution Rate", f"{summary.get('resolution_rate', 0)}%"],
                ]
                
                table = Table(data, colWidths=[3*inch, 2*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 11),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f4f6f9')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ]))
                elements.append(table)
                
                elements.append(Spacer(1, 20))
                elements.append(Paragraph("Severity Breakdown", section_style))
                
                severity = report_data.get("severity_breakdown", {})
                sev_data = [["Severity", "Count"], ["High", str(severity.get("high", 0))], 
                           ["Medium", str(severity.get("medium", 0))], 
                           ["Low", str(severity.get("low", 0))]]
                
                sev_table = Table(sev_data, colWidths=[2*inch, 2*inch])
                sev_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ]))
                elements.append(sev_table)
            
            elif report_data.get("report_type") == "anomaly_detail":
                elements.append(Paragraph("Network Monitor - Anomaly Report", title_style))
                elements.append(Paragraph(f"Generated: {self.generated_at}", subtitle_style))
                
                filters = report_data.get("filters", {})
                if filters.get("severity") or filters.get("status"):
                    filter_text = "Filters: "
                    if filters.get("severity"):
                        filter_text += f"Severity={filters['severity']} "
                    if filters.get("status"):
                        filter_text += f"Status={filters['status']}"
                    elements.append(Paragraph(filter_text, subtitle_style))
                
                elements.append(Paragraph(f"Total Anomalies: {report_data.get('total_anomalies', 0)}", subtitle_style))
                elements.append(Spacer(1, 10))
                
                anomalies = report_data.get("anomalies", [])[:50]
                if anomalies:
                    data = [["ID", "Severity", "Status", "Source IP", "Event Type", "Score"]]
                    for a in anomalies:
                        data.append([
                            str(a.get("result_id", "")),
                            a.get("severity", ""),
                            a.get("status", ""),
                            a.get("source_ip", ""),
                            a.get("event_type", "")[:15],
                            f"{a.get('anomaly_score', 0):.4f}"
                        ])
                    
                    table = Table(data, colWidths=[0.5*inch, 0.8*inch, 0.8*inch, 1.2*inch, 1.2*inch, 0.8*inch])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#dee2e6')),
                        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f6f9')]),
                    ]))
                    elements.append(table)
            
            elif report_data.get("report_type") == "user_activity":
                elements.append(Paragraph(f"Network Monitor - Activity Report for {self.username or 'User'}", title_style))
                elements.append(Paragraph(f"Generated: {self.generated_at}", subtitle_style))
                
                summary = report_data.get("summary", {})
                elements.append(Paragraph("Your Statistics", section_style))
                
                data = [
                    ["Metric", "Value"],
                    ["Files Uploaded", str(summary.get("files_uploaded", 0))],
                    ["Entries Processed", str(summary.get("entries_processed", 0))],
                    ["Anomalies Found", str(summary.get("anomalies_found", 0))],
                    ["Open Issues", str(summary.get("open_issues", 0))],
                ]
                
                table = Table(data, colWidths=[2.5*inch, 1.5*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ]))
                elements.append(table)
            
            elements.append(Spacer(1, 30))
            elements.append(Paragraph("Network Monitor - AI-Powered Log Anomaly Detection", subtitle_style))
            
            doc.build(elements)
            return buffer.getvalue()
            
        except ImportError:
            return self._generate_simple_pdf_fallback(report_data)

    def _generate_simple_pdf_fallback(self, report_data: Dict) -> bytes:
        """Simple text-based PDF fallback when reportlab is not available."""
        buffer = io.BytesIO()
        buffer.write(b"%PDF-1.4\n")
        buffer.write(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
        buffer.write(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
        
        report_type = report_data.get("report_type", "unknown")
        content = f"Network Monitor Report\nGenerated: {self.generated_at}\n\nType: {report_type}\n"
        
        if report_type == "summary":
            summary = report_data.get("summary", {})
            content += f"\nTotal Log Entries: {summary.get('total_log_entries', 0)}\n"
            content += f"Total Anomalies: {summary.get('total_anomalies', 0)}\n"
            content += f"Open Anomalies: {summary.get('open_anomalies', 0)}\n"
        
        content += "\n\nThis is a basic report. Install reportlab for formatted PDF output."
        
        buffer.write(f"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >> endobj\n".encode())
        buffer.write(f"4 0 obj << /Length {len(content) + 100} >> stream\n{content}\nendstream\nendobj\n".encode())
        buffer.write(b"xref\n0 5\ntrailer << /Size 5 /Root 1 0 R >>\nstartxref\n0\n%%EOF")
        return buffer.getvalue()
