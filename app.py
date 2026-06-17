"""
ThreatOracle AI — Streamlit Frontend
Paste suspicious behaviour. Get ATT&CK diagnosis + D3FEND remediation in 15 seconds.
"""

import sys
import json
from pathlib import Path
import streamlit as st

sys.path.append(str(Path(__file__).parent))

from agents.normalization_agent import normalize
from agents.synthesis_agent import synthesize
from retrieval.hybrid_search import HybridRetriever
from retrieval.d3fend_lookup import D3FENDLookup

# --- Page Config ---

st.set_page_config(
    page_title="ThreatOracle AI",
    page_icon="⚔️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --- Styling ---

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #E53E3E;
    }
    .sub-header {
        font-size: 1rem;
        color: #A0AEC0;
        margin-top: -10px;
        margin-bottom: 30px;
    }
    .technique-card {
        background-color: #1A202C;
        border-left: 4px solid #E53E3E;
        padding: 12px 16px;
        border-radius: 4px;
        margin-bottom: 10px;
    }
    .confidence-high { color: #FC8181; font-weight: bold; }
    .confidence-med  { color: #F6AD55; font-weight: bold; }
    .confidence-low  { color: #68D391; font-weight: bold; }
    .stTextArea textarea {
        font-family: monospace;
        font-size: 0.85rem;
    }
    .report-box {
        background-color: #1A202C;
        border: 1px solid #2D3748;
        border-radius: 8px;
        padding: 20px;
        font-family: monospace;
        font-size: 0.85rem;
        white-space: pre-wrap;
    }
</style>
""", unsafe_allow_html=True)

# --- Demo Scenarios ---

DEMO_SCENARIOS = {
    "Select a demo scenario...": "",
    "🔴 Multi-Stage Network Intrusion": """02:14:33 - Host 192.168.1.45 attempting SSH connections to 47 internal hosts in 3 minutes
02:14:41 - Multiple failed authentication attempts on each host
02:15:12 - Successful authentication on 192.168.1.103
02:15:45 - New process spawned on .103: cmd.exe /c whoami
02:16:02 - New process spawned on .103: cmd.exe /c net user
02:16:34 - Outbound connection from .103 to 185.220.101.x (known Tor exit node)
02:17:01 - Large data transfer initiated: 2.3GB outbound""",
    "🟠 Plain English — Suspicious Behaviour": """Our EDR flagged unusual activity on a workstation. The user account hasn't logged in before from this machine. 
It looks like someone ran a bunch of PowerShell commands to dump credentials and then tried to move to other systems on the network. 
There was also a connection to an external IP we don't recognize.""",
    "🟡 AegisAI JSON Output": """{
  "attack_type": "DDoS",
  "confidence": 0.94,
  "source_ip": "203.0.113.42",
  "destination_ip": "10.0.0.5",
  "protocol": "UDP",
  "packet_rate": 850000,
  "timestamp": "2026-06-17T02:14:33Z",
  "anomaly_score": 0.91,
  "features": {
    "flow_duration": 0.003,
    "total_fwd_packets": 48291,
    "total_bwd_packets": 0,
    "fwd_packet_length_max": 1514
  }
}""",
}

# --- Load Resources (cached) ---

@st.cache_resource(show_spinner=False)
def load_retriever():
    return HybridRetriever()

@st.cache_resource(show_spinner=False)
def load_d3fend():
    return D3FENDLookup()

# --- Header ---

st.markdown('<div class="main-header">⚔️ThreatOracle AI</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Paste suspicious behaviour. Get ATT&CK diagnosis + D3FEND remediation in 15 seconds.</div>', unsafe_allow_html=True)

st.divider()

# --- Layout ---

col_input, col_output = st.columns([1, 1], gap="large")

with col_input:
    st.subheader("📥 Input")

    # Demo scenario selector
    selected_demo = st.selectbox("Load a demo scenario:", list(DEMO_SCENARIOS.keys()))

    # Text area — prepopulate from demo selector
    default_text = DEMO_SCENARIOS[selected_demo]
    raw_input = st.text_area(
        "Paste logs, describe suspicious behaviour, or drop AegisAI JSON here:",
        value=default_text,
        height=320,
        placeholder="Paste raw logs, plain English description, or AegisAI JSON output...",
    )

    analyze_btn = st.button("🔍 Analyze", type="primary", use_container_width=True)

    # Pipeline status
    if analyze_btn and raw_input.strip():
        status = st.empty()

        with col_output:
            st.subheader("📊 Diagnosis")
            output_placeholder = st.empty()

        try:
            # Step 1 — Normalize
            status.info("⚙️ Step 1/4 — Normalizing input...")
            normalized = normalize(raw_input)

            # Step 2 — Retrieve
            status.info("🔎 Step 2/4 — Querying ATT&CK knowledge base...")
            retriever = load_retriever()
            techniques = retriever.search_behaviours(normalized["behaviours"])

            # Step 3 — D3FEND
            status.info("🛡️ Step 3/4 — Loading D3FEND countermeasures...")
            d3fend = load_d3fend()

            # Step 4 — Synthesize
            status.info("📝 Step 4/4 — Generating analyst report...")
            report = synthesize(normalized, techniques, d3fend._lookup)

            status.success(f"✅ Done — {len(techniques)} techniques identified")

            # --- Output Tabs ---
            with output_placeholder.container():
                tab_report, tab_techniques, tab_normalized = st.tabs([
                    "📋 Analyst Report",
                    "🎯 Techniques",
                    "🔧 Normalized JSON",
                ])

                with tab_report:
                    st.markdown(f'<div class="report-box">{report}</div>', unsafe_allow_html=True)
                    st.download_button(
                        "⬇️ Download Report",
                        data=report,
                        file_name="threatoracle_report.txt",
                        mime="text/plain",
                        use_container_width=True,
                    )

                with tab_techniques:
                    for t in techniques:
                        confidence = t["confidence"]
                        if confidence >= 0.85:
                            badge = "🔴"
                        elif confidence >= 0.70:
                            badge = "🟠"
                        else:
                            badge = "🟡"

                        with st.expander(f"{badge} {t['technique_id']} — {t['name']} ({int(confidence*100)}%)"):
                            st.write(f"**Tactic:** {t.get('tactic_str', 'Unknown')}")
                            st.write(f"**Matched Behaviour:** {t.get('matched_behaviour', '')}")
                            if t.get("description"):
                                st.write(f"**ATT&CK Description:** {t['description'][:400]}...")
                            st.write(f"**ATT&CK URL:** {t.get('url', '')}")

                            # D3FEND countermeasures
                            cms = d3fend.get(t["technique_id"])
                            if cms:
                                st.write(f"**D3FEND Countermeasures ({len(cms)}):**")
                                for cm in cms[:6]:
                                    cat = cm["category"]
                                    emoji = "🛑" if cat == "Prevent" else "🔍" if cat == "Detect" else "🔧"
                                    st.write(f"{emoji} `{cm.get('d3fend_id', '')}` {cm['name']} [{cat}]")
                            else:
                                st.write("*No D3FEND countermeasures mapped for this technique.*")

                with tab_normalized:
                    st.json(normalized)

        except Exception as e:
            status.error(f"❌ Error: {e}")
            st.exception(e)

    elif analyze_btn and not raw_input.strip():
        st.warning("Please paste some input before analyzing.")

    else:
        with col_output:
            st.subheader("📊 Diagnosis")
            st.info("👈 Paste input and click Analyze to generate a threat diagnosis.")

# --- Footer ---
st.divider()
st.markdown(
    "<center><small>ThreatOracle AI · ATT&CK v16 · D3FEND · "
    "Component 2 of AI-powered SOC pipeline · "
    "<a href='https://aegisai.online'>AegisAI Detection Layer</a></small></center>",
    unsafe_allow_html=True,
)