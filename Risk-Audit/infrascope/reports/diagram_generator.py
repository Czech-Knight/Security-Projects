# from typing import List
# from infrascope.models import Host


# class DiagramGenerator:
#     """Generate a simple Mermaid network diagram from discovered hosts."""

#     def generate_mermaid(self, client_name: str, hosts: List[Host]) -> str:
#         lines = ["flowchart LR"]
#         client_node = self._safe_id(client_name or "Client")
#         lines.append(f"    Internet((Internet)) --> FW[Client Firewall / Gateway]")
#         lines.append(f"    FW --> LAN[{client_name} LAN]")

#         for index, host in enumerate(hosts, start=1):
#             label = host.hostname or host.ip
#             services = [f"{svc.port}/{svc.name}" for svc in host.services if svc.state == "open"]
#             service_text = "<br/>".join(services[:6]) if services else "No open services in scope"
#             node_id = f"H{index}"
#             lines.append(f"    LAN --> {node_id}[\"{label}<br/>{host.ip}<br/>{service_text}\"]")

#         return "\n".join(lines) + "\n"

#     @staticmethod
#     def _safe_id(value: str) -> str:
#         return "".join(ch for ch in value if ch.isalnum()) or "Client"

from typing import List
from infrascope.models import Host


class DiagramGenerator:
    """Generate a simple Mermaid network diagram from discovered hosts."""

    def generate_mermaid(self, client_name: str, hosts: List[Host]) -> str:
        lines = ["flowchart LR"]
        client_node = self._safe_id(client_name or "Client")
        lines.append(f"    Internet((Internet)) --> FW[Client Firewall / Gateway]")
        lines.append(f"    FW --> LAN[{self._escape_label(client_name)} LAN]")

        for index, host in enumerate(hosts, start=1):
            label = self._escape_label(host.hostname or host.ip)
            ip = self._escape_label(host.ip)

            services = [
                f"{svc.port}/{self._escape_label(svc.name)}"
                for svc in host.services
                if svc.state == "open"
            ]

            service_text = "<br/>".join(services[:6]) if services else "No open services in scope"
            node_id = f"H{index}"
            lines.append(f"    LAN --> {node_id}[\"{label}<br/>{ip}<br/>{service_text}\"]")

        return "\n".join(lines) + "\n"

    @staticmethod
    def _safe_id(value: str) -> str:
        return "".join(ch for ch in value if ch.isalnum()) or "Client"

    @staticmethod
    def _escape_label(value: str) -> str:
        return (
            str(value or "")
            .replace("\\", "\\\\")
            .replace('"', "#quot;")
            .replace("\n", " ")
            .replace("\r", " ")
        )