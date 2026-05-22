from __future__ import annotations

from typing import List, Dict, Any
from infrascope.models import Host, Service, Finding


class RiskEngine:
    """Convert discovered services into client-ready risk findings."""

    SEVERITY_POINTS = {
        "Critical": 25,
        "High": 15,
        "Medium": 8,
        "Low": 3,
    }

    RISKY_PORTS: Dict[int, Dict[str, str]] = {
        21: {
            "severity": "High",
            "title": "FTP service exposed",
            "impact": "FTP can expose credentials and files if not protected correctly.",
            "recommendation": "Disable FTP or replace it with SFTP/secure file transfer. Restrict access to trusted IP ranges.",
        },
        23: {
            "severity": "Critical",
            "title": "Telnet service exposed",
            "impact": "Telnet transmits data in clear text and is unsafe for modern administration.",
            "recommendation": "Disable Telnet and use SSH or a secure management channel instead.",
        },
        80: {
            "severity": "Low",
            "title": "HTTP service detected",
            "impact": "Unencrypted HTTP may expose web traffic or indicate an outdated service.",
            "recommendation": "Confirm whether HTTPS is enabled and redirect HTTP traffic to HTTPS where possible.",
        },
        139: {
            "severity": "Medium",
            "title": "NetBIOS/SMB-related service detected",
            "impact": "Legacy Windows file sharing exposure can increase lateral movement risk.",
            "recommendation": "Restrict SMB/NetBIOS access to internal trusted subnets only.",
        },
        445: {
            "severity": "High",
            "title": "SMB service detected",
            "impact": "SMB exposure can increase risk of credential attacks, file share abuse, and lateral movement.",
            "recommendation": "Restrict SMB to trusted internal networks and verify patching/hardening on Windows hosts.",
        },
        1433: {
            "severity": "Critical",
            "title": "Microsoft SQL Server port exposed",
            "impact": "Database services should not be broadly reachable because they may expose sensitive business data.",
            "recommendation": "Restrict SQL access to application servers/VPN and require strong authentication.",
        },
        3306: {
            "severity": "Critical",
            "title": "MySQL database port exposed",
            "impact": "Database exposure can allow attackers to attempt credential attacks or exploit database weaknesses.",
            "recommendation": "Restrict MySQL to trusted application hosts and remove broad network exposure.",
        },
        3389: {
            "severity": "Critical",
            "title": "Remote Desktop Protocol exposed",
            "impact": "RDP exposure is commonly targeted for brute-force attacks and remote access compromise.",
            "recommendation": "Restrict RDP behind VPN, conditional access, or trusted admin IP ranges. Enable MFA where possible.",
        },
        5900: {
            "severity": "High",
            "title": "VNC remote access service detected",
            "impact": "Remote desktop services can expose administrative access if weakly protected.",
            "recommendation": "Disable VNC if unnecessary or restrict it through VPN/trusted admin networks.",
        },
        8080: {
            "severity": "Medium",
            "title": "Alternative web management port detected",
            "impact": "Port 8080 often hosts admin panels, proxies, or test applications that may be forgotten.",
            "recommendation": "Confirm business need, restrict admin interfaces, and enforce HTTPS/authentication.",
        },
    }

    def analyze_hosts(self, hosts: List[Host]) -> List[Finding]:
        findings: List[Finding] = []
        for host in hosts:
            if host.status != "up":
                continue
            findings.extend(self._analyze_host(host))
        return findings

    def _analyze_host(self, host: Host) -> List[Finding]:
        findings: List[Finding] = []

        open_services = [svc for svc in host.services if svc.state == "open"]
        if not open_services:
            findings.append(
                Finding(
                    title="Host discovered with no open services in scan scope",
                    category="Network Inventory",
                    severity="Low",
                    asset=self._asset_label(host),
                    evidence="Host responded during discovery but no open ports were recorded in the scan scope.",
                    business_impact="The host should still be documented so support teams know it exists.",
                    recommendation="Identify the device owner and add it to the client asset inventory.",
                )
            )
            return findings

        for service in open_services:
            finding = self._service_to_finding(host, service)
            if finding:
                findings.append(finding)

        if len(open_services) >= 8:
            findings.append(
                Finding(
                    title="Host has many exposed services",
                    category="Attack Surface",
                    severity="Medium",
                    asset=self._asset_label(host),
                    evidence=f"{len(open_services)} open services detected on one host.",
                    business_impact="A larger service footprint increases maintenance effort and potential attack surface.",
                    recommendation="Review whether all open services are required and disable unnecessary services.",
                )
            )

        return findings

    def _service_to_finding(self, host: Host, service: Service) -> Finding | None:
        rule = self.RISKY_PORTS.get(service.port)
        if not rule:
            return None

        evidence = f"{service.protocol.upper()} port {service.port} open"
        if service.name:
            evidence += f" ({service.name})"
        if service.product:
            evidence += f" - {service.product} {service.version}".strip()

        return Finding(
            title=rule["title"],
            category="Open Port / Service Exposure",
            severity=rule["severity"],
            asset=self._asset_label(host),
            evidence=evidence,
            business_impact=rule["impact"],
            recommendation=rule["recommendation"],
        )

    def calculate_score(self, findings: List[Finding]) -> Dict[str, Any]:
        total_penalty = sum(self.SEVERITY_POINTS.get(f.severity, 0) for f in findings)
        score = max(0, 100 - total_penalty)

        if score <= 40:
            level = "Critical"
        elif score <= 70:
            level = "High"
        elif score <= 85:
            level = "Medium"
        else:
            level = "Low"

        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        return {
            "score": score,
            "risk_level": level,
            "total_findings": len(findings),
            "counts": counts,
            "total_penalty": total_penalty,
        }

    @staticmethod
    def _asset_label(host: Host) -> str:
        if host.hostname:
            return f"{host.hostname} ({host.ip})"
        return host.ip
