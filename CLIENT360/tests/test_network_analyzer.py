import pandas as pd
from client360.analyzers.network_analyzer import analyze_network_devices, subnet_summary


def test_duplicate_ip_detected():
    df = pd.DataFrame([
        {"device_name": "pc1", "device_type": "Workstation", "ip_address": "192.168.1.10", "subnet": "192.168.1.0/24", "owner": "IT", "criticality": "Low"},
        {"device_name": "pc2", "device_type": "Workstation", "ip_address": "192.168.1.10", "subnet": "192.168.1.0/24", "owner": "IT", "criticality": "Low"},
    ])
    findings = analyze_network_devices(df)
    assert any(f.title == "Duplicate IP address detected" for f in findings)


def test_subnet_summary():
    summary = subnet_summary("192.168.10.0/24")
    assert summary["usable_hosts"] == 254
    assert summary["prefix_length"] == 24
