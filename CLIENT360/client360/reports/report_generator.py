from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

from client360.models import Finding
from client360.analyzers.risk_engine import findings_to_rows


def generate_html_report(config: Dict, summary: Dict, findings: List[Finding], output_path: str) -> Path:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("client_report.html")
    html = template.render(
        client=config.get("client", {}),
        summary=summary,
        findings=findings_to_rows(findings),
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path


def generate_pdf_report(config: Dict, summary: Dict, findings: List[Finding], output_path: str) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=1.4 * cm, leftMargin=1.4 * cm, topMargin=1.2 * cm, bottomMargin=1.2 * cm)
    story = []

    client_name = config.get("client", {}).get("name", "Client")
    story.append(Paragraph(f"Client360 IT & Security Readiness Report - {client_name}", styles["Title"]))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph(f"Overall Score: {summary['score']} / 100", styles["Heading2"]))
    story.append(Paragraph(f"Risk Level: {summary['risk_label']}", styles["Heading2"]))
    story.append(Spacer(1, 0.4 * cm))

    sev_data = [["Severity", "Count"]] + [[k, v] for k, v in summary["severity_counts"].items()]
    table = Table(sev_data, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ]))
    story.append(table)
    story.append(Spacer(1, 0.5 * cm))

    story.append(Paragraph("Top Findings", styles["Heading2"]))
    for finding in findings[:18]:
        story.append(Paragraph(f"{finding.severity}: {finding.title}", styles["Heading3"]))
        story.append(Paragraph(f"Asset: {finding.asset}", styles["Normal"]))
        story.append(Paragraph(f"Evidence: {finding.evidence}", styles["Normal"]))
        story.append(Paragraph(f"Recommendation: {finding.recommendation}", styles["Normal"]))
        story.append(Spacer(1, 0.25 * cm))

    doc.build(story)
    return path
