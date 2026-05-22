from pathlib import Path

from infrascope.parsers.nmap_xml_parser import NmapXMLParser


SAMPLE_XML = Path(__file__).resolve().parents[1] / "data" / "sample" / "sample_nmap_scan.xml"


def test_parser_reads_hosts():
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    assert len(hosts) == 4
    assert hosts[0].ip == "192.168.10.10"
    assert hosts[0].hostname == "client-dc01"


def test_parser_reads_services():
    hosts = NmapXMLParser().parse_file(SAMPLE_XML)
    dc = hosts[0]
    ports = {service.port for service in dc.services}
    assert 3389 in ports
    assert 445 in ports
