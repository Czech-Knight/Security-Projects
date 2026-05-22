from collections import Counter
from ipaddress import ip_address, ip_network
from typing import List
import pandas as pd
from client360.models import Finding


def analyze_network_devices(devices: pd.DataFrame) -> List[Finding]:
    findings: List[Finding] = []
    required_columns = {"device_name", "device_type", "ip_address", "subnet", "owner", "criticality"}
    missing = required_columns.difference(devices.columns)
    if missing:
        raise ValueError(f"Network device data missing columns: {sorted(missing)}")

    ip_counts = Counter(str(ip).strip() for ip in devices["ip_address"])
    for ip, count in ip_counts.items():
        if count > 1:
            findings.append(Finding(
                title="Duplicate IP address detected",
                category="Network",
                severity="High",
                asset=ip,
                evidence=f"IP address appears {count} times in inventory.",
                business_impact="Duplicate IP addresses can cause intermittent connectivity and troubleshooting issues.",
                recommendation="Confirm actual device assignments and update static/DHCP reservations.",
            ))

    for _, row in devices.iterrows():
        name = str(row["device_name"])
        ip = str(row["ip_address"]).strip()
        subnet = str(row["subnet"]).strip()
        owner = str(row["owner"]).strip()
        try:
            if ip_address(ip) not in ip_network(subnet, strict=False):
                findings.append(Finding(
                    title="Device IP outside documented subnet",
                    category="Network",
                    severity="Medium",
                    asset=name,
                    evidence=f"IP {ip} is outside subnet {subnet}.",
                    business_impact="Incorrect IP/subnet documentation can slow troubleshooting and migration work.",
                    recommendation="Verify the device network settings and update documentation.",
                ))
        except ValueError as exc:
            findings.append(Finding(
                title="Invalid network inventory value",
                category="Network Documentation",
                severity="Low",
                asset=name,
                evidence=str(exc),
                business_impact="Invalid documentation reduces confidence in the client environment inventory.",
                recommendation="Correct IP address and subnet formatting.",
            ))

        if owner.lower() in {"", "nan", "unknown", "tbc"}:
            findings.append(Finding(
                title="Network device missing owner",
                category="Network Documentation",
                severity="Low",
                asset=name,
                evidence="Owner field is missing or unknown.",
                business_impact="Unowned devices are harder to patch, replace, approve or retire.",
                recommendation="Assign a business or technical owner to the device.",
            ))

    return findings


def subnet_summary(subnet: str) -> dict:
    network = ip_network(subnet, strict=False)
    return {
        "subnet": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "usable_hosts": max(network.num_addresses - 2, 0),
        "prefix_length": network.prefixlen,
    }
