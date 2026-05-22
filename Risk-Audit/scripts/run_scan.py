from pathlib import Path
import argparse
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from infrascope.collectors.nmap_runner import NmapRunner
from infrascope.parsers.nmap_xml_parser import NmapXMLParser
from infrascope.analyzers.risk_engine import RiskEngine
from infrascope.reports.diagram_generator import DiagramGenerator
from infrascope.reports.report_generator import ReportGenerator
from infrascope.utils.file_utils import write_json, ensure_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run an authorised Nmap scan and generate an InfraScope report.")
    parser.add_argument("--target", required=True, help="Authorised IP, hostname, or CIDR range to scan")
    parser.add_argument("--client", default="Client Network", help="Client name for the report")
    parser.add_argument("--profile", choices=["discovery", "service_inventory"], default="service_inventory")
    args = parser.parse_args()

    print("Ethical use reminder: only scan systems you own or are authorised to assess.")

    runner = NmapRunner(PROJECT_ROOT / "scan_outputs")
    xml_path = runner.run_scan(args.target, args.profile)

    hosts = NmapXMLParser().parse_file(xml_path)
    risk_engine = RiskEngine()
    findings = risk_engine.analyze_hosts(hosts)
    score = risk_engine.calculate_score(findings)

    reports_dir = ensure_dir(PROJECT_ROOT / "reports")
    diagram_text = DiagramGenerator().generate_mermaid(args.client, hosts)
    diagram_path = reports_dir / "network_diagram.mmd"
    diagram_path.write_text(diagram_text, encoding="utf-8")

    html_path = reports_dir / "live_client_report.html"
    ReportGenerator().generate_html(
        client_name=args.client,
        hosts=hosts,
        findings=findings,
        score=score,
        output_path=html_path,
        diagram_text=diagram_text,
    )

    json_path = reports_dir / "live_audit_results.json"
    write_json(
        json_path,
        {
            "client_name": args.client,
            "target": args.target,
            "profile": args.profile,
            "nmap_xml": str(xml_path.relative_to(PROJECT_ROOT)),
            "score": score,
            "hosts": [host.to_dict() for host in hosts],
            "findings": [finding.to_dict() for finding in findings],
        },
    )

    print("Live authorised scan completed successfully.")
    print(f"Nmap XML: {xml_path.relative_to(PROJECT_ROOT)}")
    print(f"HTML report: {html_path.relative_to(PROJECT_ROOT)}")
    print(f"JSON results: {json_path.relative_to(PROJECT_ROOT)}")
    print(f"Risk score: {score['score']}/100 ({score['risk_level']})")


if __name__ == "__main__":
    main()
