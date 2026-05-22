import pandas as pd
from client360.analyzers.firewall_analyzer import analyze_firewall_rules


def test_public_rdp_detected():
    df = pd.DataFrame([
        {"rule_id": "FW-1", "source": "0.0.0.0/0", "destination": "10.0.0.5", "port": 3389, "protocol": "TCP", "action": "allow", "description": "Remote admin"},
    ])
    findings = analyze_firewall_rules(df)
    assert any("RDP" in f.title for f in findings)
