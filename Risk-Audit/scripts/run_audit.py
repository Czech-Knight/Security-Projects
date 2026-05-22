from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from infrascope.parsers.nmap_xml_parser import NmapXMLParser
from infrascope.analyzers.risk_engine import RiskEngine
from infrascope.reports.diagram_generator import DiagramGenerator
from infrascope.reports.report_generator import ReportGenerator
from infrascope.utils.file_utils import write_json, ensure_dir


def main() -> None:
    client_name = "Demo Client"
    sample_xml = PROJECT_ROOT / "data" / "sample" / "sample_nmap_scan.xml"
    reports_dir = ensure_dir(PROJECT_ROOT / "reports")

    parser = NmapXMLParser()
    hosts = parser.parse_file(sample_xml)

    risk_engine = RiskEngine()
    findings = risk_engine.analyze_hosts(hosts)
    score = risk_engine.calculate_score(findings)

    diagram_text = DiagramGenerator().generate_mermaid(client_name, hosts)
    diagram_path = reports_dir / "network_diagram.mmd"
    diagram_path.write_text(diagram_text, encoding="utf-8")

    html_path = reports_dir / "sample_client_report.html"
    ReportGenerator().generate_html(
        client_name=client_name,
        hosts=hosts,
        findings=findings,
        score=score,
        output_path=html_path,
        diagram_text=diagram_text,
    )

    json_path = reports_dir / "audit_results.json"
    write_json(
        json_path,
        {
            "client_name": client_name,
            "score": score,
            "hosts": [host.to_dict() for host in hosts],
            "findings": [finding.to_dict() for finding in findings],
        },
    )

    print("Audit completed successfully.")
    print(f"HTML report: {html_path.relative_to(PROJECT_ROOT)}")
    print(f"JSON results: {json_path.relative_to(PROJECT_ROOT)}")
    print(f"Mermaid diagram: {diagram_path.relative_to(PROJECT_ROOT)}")
    print(f"Risk score: {score['score']}/100 ({score['risk_level']})")
    print(f"Findings: {score['total_findings']}")


if __name__ == "__main__":
    main()
