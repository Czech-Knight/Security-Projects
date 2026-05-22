from pathlib import Path
from typing import List
import xml.etree.ElementTree as ET

from infrascope.models import Host, Service


class NmapXMLParser:
    """Parse Nmap XML output into Host and Service objects."""

    def parse_file(self, xml_path: str | Path) -> List[Host]:
        path = Path(xml_path)
        if not path.exists():
            raise FileNotFoundError(f"Nmap XML file not found: {path}")

        tree = ET.parse(path)
        root = tree.getroot()
        hosts: List[Host] = []

        for host_node in root.findall("host"):
            host = self._parse_host(host_node)
            if host:
                hosts.append(host)
        return hosts

    def _parse_host(self, host_node) -> Host | None:
        status_node = host_node.find("status")
        status = status_node.attrib.get("state", "unknown") if status_node is not None else "unknown"

        address_node = host_node.find("address[@addrtype='ipv4']") or host_node.find("address")
        if address_node is None:
            return None
        ip = address_node.attrib.get("addr", "unknown")

        hostname = ""
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            hostname_node = hostnames_node.find("hostname")
            if hostname_node is not None:
                hostname = hostname_node.attrib.get("name", "")

        os_guess = "Unknown"
        osmatch_node = host_node.find("os/osmatch")
        if osmatch_node is not None:
            os_guess = osmatch_node.attrib.get("name", "Unknown")

        services = []
        ports_node = host_node.find("ports")
        if ports_node is not None:
            for port_node in ports_node.findall("port"):
                service = self._parse_service(port_node)
                if service:
                    services.append(service)

        return Host(ip=ip, hostname=hostname, status=status, os_guess=os_guess, services=services)

    def _parse_service(self, port_node) -> Service | None:
        state_node = port_node.find("state")
        state = state_node.attrib.get("state", "unknown") if state_node is not None else "unknown"

        port_id = port_node.attrib.get("portid")
        protocol = port_node.attrib.get("protocol", "tcp")
        if not port_id:
            return None

        service_node = port_node.find("service")
        name = "unknown"
        product = ""
        version = ""
        if service_node is not None:
            name = service_node.attrib.get("name", "unknown")
            product = service_node.attrib.get("product", "")
            version = service_node.attrib.get("version", "")

        return Service(
            port=int(port_id),
            protocol=protocol,
            state=state,
            name=name,
            product=product,
            version=version,
        )
