import sys
from pathlib import Path

# Allows running with: streamlit run app/dashboard.py
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from client360.audit import run_audit, audit_summary
from client360.analyzers.risk_engine import findings_to_rows
from client360.reports.report_generator import generate_html_report, generate_pdf_report
from client360.reports.diagram_generator import generate_mermaid_diagram

st.set_page_config(page_title="Client360", page_icon="🛡️", layout="wide")

st.title("🛡️ Client360 IT & Security Readiness Dashboard")
st.caption("Defensive MSP-style infrastructure, cloud, firewall, network and backup readiness review.")

CONFIG_PATH = st.sidebar.text_input("Config file", value="config.example.yaml")

try:
    config, data, findings = run_audit(CONFIG_PATH)
    summary = audit_summary(findings)
except Exception as exc:
    st.error(f"Could not load audit data: {exc}")
    st.stop()

client = config.get("client", {})
st.sidebar.success(f"Client: {client.get('name', 'Unknown')}")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Overall Score", f"{summary['score']}/100")
col2.metric("Risk Level", summary["risk_label"])
col3.metric("Total Findings", summary["total_findings"])
col4.metric("Critical", summary["severity_counts"].get("Critical", 0))

findings_df = pd.DataFrame(findings_to_rows(findings))
severity_df = pd.DataFrame([
    {"Severity": k, "Count": v} for k, v in summary["severity_counts"].items()
])
category_df = pd.DataFrame([
    {"Category": k, "Count": v} for k, v in summary["category_counts"].items()
])

tabs = st.tabs([
    "Overview", "Microsoft 365", "Cloud", "Firewall", "Network", "Backup/DR", "Report & Docs"
])

with tabs[0]:
    st.subheader("Risk Summary")
    c1, c2 = st.columns(2)
    with c1:
        st.bar_chart(severity_df.set_index("Severity"))
    with c2:
        if not category_df.empty:
            st.bar_chart(category_df.set_index("Category"))
    st.subheader("All Findings")
    st.dataframe(findings_df, use_container_width=True)

with tabs[1]:
    st.subheader("Microsoft 365 Audit")
    st.dataframe(data["microsoft365_users"], use_container_width=True)
    st.info("Checks include users without MFA, admin accounts without MFA, stale licensed accounts and temporary/test account naming patterns.")

with tabs[2]:
    st.subheader("Azure NSG Rules")
    st.dataframe(data["azure_nsg_rules"], use_container_width=True)
    st.subheader("AWS Security Group Rules")
    st.dataframe(data["aws_security_groups"], use_container_width=True)
    st.info("Checks include public RDP/SSH/database exposure and broad inbound allow rules.")

with tabs[3]:
    st.subheader("Firewall Rules")
    st.dataframe(data["firewall_rules"], use_container_width=True)
    st.info("Checks include any-to-any allow rules, public admin access, public database ports and undocumented firewall rules.")

with tabs[4]:
    st.subheader("Network Device Inventory")
    st.dataframe(data["network_devices"], use_container_width=True)
    st.info("Checks include duplicate IPs, IP addresses outside documented subnets and missing owners.")

with tabs[5]:
    st.subheader("Backup and Disaster Recovery")
    st.dataframe(data["backup_status"], use_container_width=True)
    st.info("Checks include failed jobs, stale backup age, short retention and missing recovery tests.")

with tabs[6]:
    st.subheader("Export Client Report")
    html_path = config["paths"].get("report_html", "reports/client360_report.html")
    pdf_path = config["paths"].get("report_pdf", "reports/client360_report.pdf")
    diagram_path = config["paths"].get("diagram_md", "reports/client360_architecture.md")

    if st.button("Generate HTML, PDF and Diagram"):
        generated_html = generate_html_report(config, summary, findings, html_path)
        generated_pdf = generate_pdf_report(config, summary, findings, pdf_path)
        generated_diagram = generate_mermaid_diagram(config, diagram_path)
        st.success("Reports generated successfully.")
        st.write(f"HTML: `{generated_html}`")
        st.write(f"PDF: `{generated_pdf}`")
        st.write(f"Diagram: `{generated_diagram}`")

    st.subheader("Recommended Next Actions")
    critical_findings = [f for f in findings if f.severity == "Critical"]
    if critical_findings:
        for f in critical_findings[:5]:
            st.warning(f"{f.title} — {f.asset}: {f.recommendation}")
    else:
        st.success("No critical findings detected in the current dataset.")
