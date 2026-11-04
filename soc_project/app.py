import streamlit as st
import pandas as pd
from engine import (load_logs, run_pipeline, simulate_action, response_summary,
                    asset_table, build_dot, incident_report)

st.set_page_config(page_title="Agentic SOC Responder", page_icon="🛡️", layout="wide")

SEV_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

# ---------- session state ----------
if "decisions" not in st.session_state:
    st.session_state.decisions = {}      # action id -> "approved" / "rejected"
if "audit" not in st.session_state:
    st.session_state.audit = []          # list of log lines

# ---------- sidebar ----------
st.sidebar.title("🛡️ Agentic SOC Responder")
st.sidebar.caption("Irbid National University – Graduation Project")
source = st.sidebar.radio("Log source", ["Sample attack scenario", "Upload my own CSV"])
events = None
try:
    if source == "Sample attack scenario":
        events = load_logs("sample_logs/attack_scenario.csv")
    else:
        up = st.sidebar.file_uploader("Upload CSV logs", type="csv")
        st.sidebar.caption("Columns: timestamp, source_ip, dest_host, event_type, details")
        if up:
            events = load_logs(up)
except Exception as ex:
    st.sidebar.error(str(ex))

st.title("Attack Chain Reconstruction & Human-Supervised Response")
st.caption("From scattered alerts to one attack story, then a response the analyst approves.")

if not events:
    st.info("Choose the sample scenario (left) or upload a CSV to start.")
    st.stop()

res = run_pipeline(events)
chains = res["chains"]

tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🕒 Attack Timeline", "🛡️ After Detection: Response", "🗺️ Roadmap"])

# ---------- Dashboard ----------
with tab1:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Log events", len(res["events"]))
    c2.metric("Alerts raised", len(res["alerts"]))
    c3.metric("False positives filtered", len(res["false_positives"]))
    c4.metric("Incidents (attack stories)", len(chains))
    st.subheader("Incidents by severity")
    for c in chains:
        st.write(f"{SEV_ICON[c['severity']]} **{c['id']}** – {c['severity']} – source `{c['source_ip']}` – "
                 f"{len(c['stages'])} attack stage(s)")
    if res["false_positives"]:
        st.subheader("Filtered as false positives")
        st.dataframe(pd.DataFrame([{"source_ip": a["source_ip"], "description": a["description"],
                                    "why filtered": a["reason"]} for a in res["false_positives"]]),
                     use_container_width=True, hide_index=True)
    st.subheader("Raw logs")
    st.dataframe(pd.DataFrame(res["events"]), use_container_width=True, hide_index=True)

# ---------- Timeline ----------
with tab2:
    if not chains:
        st.success("No incidents detected.")
    for c in chains:
        with st.expander(f"{SEV_ICON[c['severity']]} {c['id']} – {c['severity']} – {c['source_ip']}", expanded=(c is chains[0])):
            st.write(c["summary"])
            if c["threat_intel"]:
                st.warning(f"Threat intelligence: {c['threat_intel']}")
            st.markdown("**Attack path:** " + " ➜ ".join(c["stages"]))
            st.dataframe(pd.DataFrame([{
                "Time": a["timestamp"], "MITRE tactic": a["tactic"],
                "Technique": f"{a['technique_id']} {a['technique']}",
                "Host": a["host"], "Detail": a["description"]} for a in c["alerts"]]),
                use_container_width=True, hide_index=True)

# ---------- Response Center (after detection) ----------
with tab3:
    st.markdown("### After Detection: what happens next?")
    st.write("Detection ends when the alert is raised. This step turns the attack story into a **response plan**. "
             "The system recommends, the **analyst decides**, and every decision is logged. "
             "(Execution is simulated in this prototype.)")
    rs = response_summary(chains, st.session_state.decisions)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Recommended actions", rs["total"])
    m2.metric("Approved (mitigated)", rs["approved"])
    m3.metric("Pending decision", rs["pending"])
    m4.metric("Threat contained", f"{rs['contained_pct']}%")
    st.progress(rs["contained_pct"] / 100)

    for c in chains:
        st.divider()
        st.subheader(f"{SEV_ICON[c['severity']]} {c['id']} – {c['source_ip']}")
        st.graphviz_chart(build_dot(c, st.session_state.decisions), use_container_width=True)
        st.caption("Blue = pending, green = approved, grey = rejected")
        for a in c["actions"]:
            col1, col2, col3 = st.columns([5, 1, 1])
            col1.markdown(f"**{a['action']}** → `{a['target']}`  \n_{a['reason']}_")
            state = st.session_state.decisions.get(a["id"])
            if state:
                col2.write("✅ Approved" if state == "approved" else "❌ Rejected")
            else:
                if col2.button("Approve", key="ap_" + a["id"]):
                    st.session_state.decisions[a["id"]] = "approved"
                    st.session_state.audit.append(simulate_action(a))
                    st.rerun()
                if col3.button("Reject", key="rj_" + a["id"]):
                    st.session_state.decisions[a["id"]] = "rejected"
                    st.session_state.audit.append(f"[REJECTED] {a['action']} on {a['target']}")
                    st.rerun()
        st.download_button("⬇️ Download incident report", incident_report(c, st.session_state.decisions),
                           file_name=f"{c['id']}_report.txt", key="dl_" + c["id"])

    st.divider()
    st.subheader("Asset status")
    st.dataframe(pd.DataFrame(asset_table(chains, st.session_state.decisions)),
                 use_container_width=True, hide_index=True)
    st.subheader("Audit log")
    if st.session_state.audit:
        for line in st.session_state.audit:
            st.code(line)
    else:
        st.caption("No actions taken yet.")

# ---------- Roadmap ----------
with tab4:
    st.markdown("""
**Current prototype (v1):** rule-based detection, attack-chain grouping, MITRE ATT&CK mapping,
severity scoring, human-approved simulated response.

**Planned during the project:**
- LLM-based agents (LangChain / LangGraph) for log parsing, reasoning and explanations
- Real threat-intelligence APIs (VirusTotal, AbuseIPDB, AlienVault OTX)
- CIC-IDS2017 / Kaggle SOC datasets and full MITRE ATT&CK knowledge base
- Verifier Agent + prompt-injection testing
- Docker sandbox for realistic response execution
- Evaluation: precision, recall, F1, false-positive reduction, response time
""")
