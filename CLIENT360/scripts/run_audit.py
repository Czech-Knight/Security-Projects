import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client360.audit import run_audit, audit_summary
from client360.reports.report_generator import generate_html_report, generate_pdf_report
from client360.reports.diagram_generator import generate_mermaid_diagram


def main() -> None:
    config, data, findings = run_audit("config.example.yaml")
    summary = audit_summary(findings)

    html_path = generate_html_report(config, summary, findings, config["paths"]["report_html"])
    pdf_path = generate_pdf_report(config, summary, findings, config["paths"]["report_pdf"])
    diagram_path = generate_mermaid_diagram(config, config["paths"]["diagram_md"])

    print("Client360 audit completed")
    print(f"Score: {summary['score']} / 100")
    print(f"Risk level: {summary['risk_label']}")
    print(f"Findings: {summary['total_findings']}")
    print(f"HTML report: {html_path}")
    print(f"PDF report: {pdf_path}")
    print(f"Diagram: {diagram_path}")


if __name__ == "__main__":
    main()
