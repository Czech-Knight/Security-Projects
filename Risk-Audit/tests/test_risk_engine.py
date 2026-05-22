from pathlib import Path

from infrascope.parsers.nmap_xml_parser import NmapXMLParser
from infrascope.analyzers.risk_engine import RiskEngine


SAMPLE_XML = Path(__file__).resolve().parents[1] / "data" / "sample" / "sample_nmap_scan.xml"


def test_risk_engine_detects_rdp():
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    findings = RiskEngine().analyze_hosts(hosts)
    titles = [finding.title for finding in findings]
    assert "Remote Desktop Protocol exposed" in titles


def test_risk_engine_detects_telnet():
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    findings = RiskEngine().analyze_hosts(hosts)
    titles = [finding.title for finding in findings]
    assert "Telnet service exposed" in titles


def test_risk_score_contains_counts():
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    engine = RiskEngine()
    findings = engine.analyze_hosts(hosts)
    score = engine.calculate_score(findings)
    assert score["total_findings"] == len(findings)
    assert score["counts"]["Critical"] >= 1
    assert 0 <= score["score"] <= 100
