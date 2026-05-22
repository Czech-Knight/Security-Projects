from pathlib import Path
import sys
import tempfile
import streamlit_mermaid as stmd
import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from infrascope.parsers.nmap_xml_parser import NmapXMLParser
from infrascope.analyzers.risk_engine import RiskEngine
from infrascope.reports.diagram_generator import DiagramGenerator
from infrascope.reports.report_generator import ReportGenerator
from infrascope.collectors.nmap_runner import NmapRunner, NmapNotInstalledError
from infrascope.utils.file_utils import write_json, ensure_dir


st.set_page_config(
    page_title="InfraScope MSP Risk Audit Tool",
    page_icon="🛡️",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stDeployButton { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("InfraScope: MSP Network Risk Assessment Tool")
st.caption("Defensive Nmap-based client network inventory, risk scoring, and documentation.")

with st.sidebar:
    st.header("Input")
    client_name = st.text_input("Client name", "Demo Client")
    input_mode = st.radio("Data source", ["Use sample Nmap XML", "Upload Nmap XML", "Run authorised live scan"])
    st.warning("Only scan networks you own or are authorised to assess.")


def load_hosts_from_selected_input():
    parser = NmapXMLParser()

    if input_mode == "Use sample Nmap XML":
        return parser.parse_file(PROJECT_ROOT / "data" / "sample" / "sample_nmap_scan.xml")

    if input_mode == "Upload Nmap XML":
        uploaded = st.sidebar.file_uploader("Upload Nmap XML", type=["xml"])
        if not uploaded:
            st.info("Upload an Nmap XML file or switch to sample mode.")
            st.stop()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name
        return parser.parse_file(tmp_path)

    target = st.sidebar.text_input("Authorised target", "192.168.1.0/24")
    profile = st.sidebar.selectbox("Scan profile", ["service_inventory", "discovery"])
    run_button = st.sidebar.button("Run authorised scan")
    if not run_button:
        st.info("Enter an authorised target and click Run authorised scan, or use sample mode.")
        st.stop()
    try:
        xml_path = NmapRunner(PROJECT_ROOT / "scan_outputs").run_scan(target, profile)
        st.sidebar.success(f"Scan saved: {xml_path.name}")
        return parser.parse_file(xml_path)
    except NmapNotInstalledError as exc:
        st.error(str(exc))
        st.stop()
    except Exception as exc:
        st.error(f"Scan failed: {exc}")
        st.stop()


hosts = load_hosts_from_selected_input()
risk_engine = RiskEngine()
findings = risk_engine.analyze_hosts(hosts)
score = risk_engine.calculate_score(findings)
diagram_text = DiagramGenerator().generate_mermaid(client_name, hosts)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Risk Score", f"{score['score']}/100")
col2.metric("Risk Level", score["risk_level"])
col3.metric("Discovered Hosts", len(hosts))
col4.metric("Total Findings", score["total_findings"])

st.divider()

tab1, tab2, tab3, tab4 = st.tabs(["Findings", "Assets", "Charts", "Report & Diagram"])

with tab1:
    st.subheader("Risk Findings")
    findings_df = pd.DataFrame([f.to_dict() for f in findings])
    if findings_df.empty:
        st.success("No risky services detected in the current scan scope.")
    else:
        severity_order = ["Critical", "High", "Medium", "Low"]
        findings_df["severity_rank"] = findings_df["severity"].apply(lambda x: severity_order.index(x) if x in severity_order else 99)
        st.dataframe(findings_df.sort_values("severity_rank").drop(columns=["severity_rank"]), use_container_width=True)

with tab2:
    st.subheader("Discovered Asset Inventory")
    rows = []
    for host in hosts:
        open_services = [svc for svc in host.services if svc.state == "open"]
        rows.append({
            "IP": host.ip,
            "Hostname": host.hostname or "-",
            "Status": host.status,
            "OS Guess": host.os_guess,
            "Open Services": ", ".join(f"{svc.port}/{svc.name}" for svc in open_services) or "None in scope",
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

with tab3:
    st.subheader("Risk Charts")
    if findings:
        counts_df = pd.DataFrame(
            [{"Severity": sev, "Count": count} for sev, count in score["counts"].items()]
        )
        fig = px.bar(counts_df, x="Severity", y="Count", title="Findings by Severity")
        st.plotly_chart(fig, use_container_width=True)

        category_df = pd.DataFrame([f.to_dict() for f in findings]).groupby("category").size().reset_index(name="Count")
        fig2 = px.pie(category_df, names="category", values="Count", title="Findings by Category")
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No findings available for charts.")

with tab4:
    st.subheader("Generate Report")
    reports_dir = ensure_dir(PROJECT_ROOT / "reports")

    if st.button("Generate HTML report and JSON output"):
        html_path = reports_dir / "dashboard_client_report.html"
        json_path = reports_dir / "dashboard_audit_results.json"
        mmd_path = reports_dir / "dashboard_network_diagram.mmd"

        mmd_path.write_text(diagram_text, encoding="utf-8")
        ReportGenerator().generate_html(client_name, hosts, findings, score, html_path, diagram_text)
        write_json(json_path, {
            "client_name": client_name,
            "score": score,
            "hosts": [host.to_dict() for host in hosts],
            "findings": [finding.to_dict() for finding in findings],
        })
        st.success("Report generated successfully.")
        st.code(f"{html_path}\n{json_path}\n{mmd_path}")

    st.subheader("Mermaid Network Diagram")
    try:
        stmd.st_mermaid(diagram_text)
    except Exception:
        st.warning("Mermaid preview failed. Showing diagram source instead.")
        st.code(diagram_text, language="mermaid")
