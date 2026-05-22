from pathlib import Path

from infrascope.parsers.nmap_xml_parser import NmapXMLParser
from infrascope.analyzers.risk_engine import RiskEngine
from infrascope.reports.report_generator import ReportGenerator
from infrascope.reports.diagram_generator import DiagramGenerator


SAMPLE_XML = Path(__file__).resolve().parents[1] / "data" / "sample" / "sample_nmap_scan.xml"


def test_report_generation(tmp_path):
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    engine = RiskEngine()
    findings = engine.analyze_hosts(hosts)
    score = engine.calculate_score(findings)
    diagram = DiagramGenerator().generate_mermaid("Test Client", hosts)

    output = tmp_path / "report.html"
    ReportGenerator().generate_html("Test Client", hosts, findings, score, output, diagram)

    assert output.exists()
    text = output.read_text(encoding="utf-8")
    assert "Test Client - Network Risk Assessment Report" in text
    assert "Risk Findings and Recommendations" in text
