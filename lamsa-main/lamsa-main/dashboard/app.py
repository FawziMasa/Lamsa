# -*- coding: utf-8 -*-
"""
lamsa Real-time Threat Intelligence & Security Dashboard
Streamlit dashboard for lamsa Open Banking API Security Shield.
"""
import streamlit as st
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import time
from typing import Dict, List, Any
import sys
import os

# Ensure backend modules can be imported directly if needed
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.simulator.traffic_gen import (
    simulate_bola_attack,
    simulate_credential_stuffing,
    simulate_sqli_attack,
    simulate_ai_anomaly,
    simulate_honeypot_probe,
    simulate_shadow_api_scan,
    simulate_fraud_transfer,
    simulate_legitimate_traffic
)

BACKEND_URL = os.getenv("FIN_BACKEND_URL", "http://localhost:3000")

st.set_page_config(
    page_title="lamsa | Security Shield",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS styling for modern sleek lowercase "lamsa" typography and fintech aesthetics
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;800&display=swap');

    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Outfit', -apple-system, sans-serif;
    }
    .brand-text {
        font-family: 'Outfit', sans-serif;
        font-size: 2.4rem;
        font-weight: 800;
        background: linear-gradient(135deg, #58a6ff 0%, #3fb950 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -1.5px;
        margin: 0;
        padding: 0;
        line-height: 1.1;
    }
    .brand-sub {
        font-size: 0.85rem;
        color: #8b949e;
        letter-spacing: 0.5px;
        margin-top: 2px;
        margin-bottom: 12px;
        font-weight: 500;
    }
    .metric-card {
        background: linear-gradient(135deg, #161b22 0%, #21262d 100%);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
    }
    .financial-card {
        background: linear-gradient(135deg, #0d2818 0%, #164222 100%);
        border: 1.5px solid #238636;
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 14px rgba(35, 134, 54, 0.35);
    }
    .metric-val {
        font-size: 2.0rem;
        font-weight: 700;
        margin-top: 4px;
    }
    .financial-val {
        font-size: 2.1rem;
        font-weight: 800;
        color: #3fb950;
        text-shadow: 0 0 10px rgba(63, 185, 80, 0.4);
    }
    .metric-lbl {
        font-size: 0.82rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions to fetch data from backend
def fetch_telemetry_stats() -> Dict[str, Any]:
    try:
        res = requests.get(f"{BACKEND_URL}/api/v1/admin/stats", timeout=2)
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return {
        "total_requests": 0,
        "blocked_requests": 0,
        "allowed_requests": 0,
        "block_rate_percent": 0.0,
        "attack_counts": {},
        "history": [],
        "ai_metrics": {"anomaly_ratio_percent": 0.0, "anomaly_count": 0, "total_evaluations": 0},
        "honeypot_stats": {"blacklisted_ip_count": 0, "trap_triggers_count": 0, "trap_logs": []},
        "responder_stats": {"revoked_user_count": 0, "automated_actions_count": 0, "actions_log": []},
        "financial_stats": {"total_prevented_loss_jod": 0.0, "prevented_breaches_count": 0, "prevented_log": []},
        "threat_sharing_feed": [],
        "shadow_api_logs": []
    }

def fetch_incident_logs() -> List[Dict[str, Any]]:
    try:
        res = requests.get(f"{BACKEND_URL}/api/v1/admin/logs?limit=50", timeout=2)
        if res.status_code == 200:
            return res.json().get("logs", [])
    except Exception:
        pass
    return []

# --- Sidebar Header Typography ---
st.sidebar.markdown("""
<div style="padding: 5px 0 10px 0;">
    <div style="font-family: 'Outfit', sans-serif; font-size: 2.5rem; font-weight: 700; color: #E2E8F0; letter-spacing: -1.5px; text-transform: lowercase; line-height: 1.0;">lamsa</div>
    <div style="font-size: 0.85rem; color: #94A3B8; font-weight: 400; margin-top: 4px; text-transform: lowercase;">open banking firewall</div>
</div>
""", unsafe_allow_html=True)

st.sidebar.subheader("⚔️ Attack Simulator Panel")
st.sidebar.write("Launch simulated attacks & probes against Open Banking endpoints:")

if st.sidebar.button("🚨 Simulate BOLA Attack", key="btn_bola"):
    with st.spinner("Executing BOLA attack payload..."):
        res = simulate_bola_attack(BACKEND_URL)
        st.sidebar.success(f"BOLA Sent ({res['attempts']} reqs)")

if st.sidebar.button("🔑 Simulate Credential Stuffing", key="btn_cred"):
    with st.spinner("Executing Credential Stuffing burst..."):
        res = simulate_credential_stuffing(BACKEND_URL)
        st.sidebar.warning(f"Credential Burst Sent ({res['attempts']} reqs)")

if st.sidebar.button("💉 Simulate SQL Injection / XSS", key="btn_sqli"):
    with st.spinner("Executing SQLi & XSS exploit vectors..."):
        res = simulate_sqli_attack(BACKEND_URL)
        st.sidebar.error(f"SQLi/XSS Sent ({res['attempts']} reqs)")

if st.sidebar.button("🧠 Simulate AI Behavioral Anomaly", key="btn_ai"):
    with st.spinner("Executing Out-of-Pattern Payload..."):
        res = simulate_ai_anomaly(BACKEND_URL)
        st.sidebar.error(f"AI Anomaly Sent ({res['attempts']} req)")

if st.sidebar.button("🍯 Probe Honeypot Trap", key="btn_honey"):
    with st.spinner("Probing Honeypot (/admin/system_keys)..."):
        res = simulate_honeypot_probe(BACKEND_URL)
        st.sidebar.error(f"Honeypot Probe Sent ({res['attempts']} reqs)")

if st.sidebar.button("🕵️ Probe Shadow API (/beta/test)", key="btn_shadow"):
    with st.spinner("Scanning unregistered Shadow API endpoint..."):
        res = simulate_shadow_api_scan(BACKEND_URL)
        st.sidebar.error(f"Shadow API Probe Sent ({res['attempts']} req)")

if st.sidebar.button("💰 Fraud Transfer (10,000 JOD)", key="btn_fraud"):
    with st.spinner("Executing High-Value Fraud Transfer..."):
        res = simulate_fraud_transfer(BACKEND_URL)
        st.sidebar.error(f"Fraud Transfer Sent ({res['attempts']} req)")

if st.sidebar.button("✅ Simulate Legitimate Traffic", key="btn_legit"):
    with st.spinner("Sending valid Open Banking requests..."):
        res = simulate_legitimate_traffic(BACKEND_URL)
        st.sidebar.info(f"Normal User Requests Sent ({res['attempts']} reqs)")

st.sidebar.markdown("---")

st.sidebar.subheader("⚙️ System Maintenance")
if st.sidebar.button("🧹 Clear All Telemetry & Traps"):
    try:
        requests.post(f"{BACKEND_URL}/api/v1/admin/clear", timeout=2)
        st.sidebar.success("All metrics and feeds reset clean.")
    except Exception as e:
        st.sidebar.error("Failed to clear backend metrics.")

auto_refresh = st.sidebar.checkbox("🔄 Auto-Refresh Dashboard (3s)", value=True)

# --- Main Dashboard Header ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;700&display=swap');
    
    .lamsa-title-container {
        font-family: 'Outfit', -apple-system, BlinkMacSystemFont, sans-serif;
        margin-bottom: 25px;
        display: flex;
        align-items: baseline;
        gap: 12px;
    }
    
    .lamsa-logo-text {
        font-size: 3.2rem;
        font-weight: 700;
        color: #E2E8F0;
        letter-spacing: -1.5px;
        text-transform: lowercase;
    }
    
    .lamsa-descriptor {
        font-size: 1.8rem;
        font-weight: 400;
        color: #94A3B8;
        letter-spacing: -0.5px;
        text-transform: lowercase;
    }
    
    .lamsa-subtitle {
        font-size: 1.05rem;
        color: #64748B;
        margin-top: -5px;
        font-family: 'Outfit', sans-serif;
    }
</style>

<div class="lamsa-title-container">
    <span class="lamsa-logo-text">lamsa</span>
    <span class="lamsa-descriptor">open banking firewall</span>
</div>
<div class="lamsa-subtitle">Inter-Bank Threat Intelligence Network & Fraud Loss Prevention</div>
""", unsafe_allow_html=True)

stats = fetch_telemetry_stats()
logs = fetch_incident_logs()
ai_metrics = stats.get("ai_metrics", {})
honeypot_stats = stats.get("honeypot_stats", {})
responder_stats = stats.get("responder_stats", {})
financial_stats = stats.get("financial_stats", {})
threat_sharing_feed = stats.get("threat_sharing_feed", [])
shadow_api_logs = stats.get("shadow_api_logs", [])

# Top 5 KPI Metrics Row
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    loss_jod = financial_stats.get('total_prevented_loss_jod', 0.0)
    st.markdown(f"""
    <div class="financial-card">
        <div class="metric-lbl" style="color: #7ee787;">Financial Loss Prevented</div>
        <div class="financial-val">{loss_jod:,.2f} JOD</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-lbl">Total Requests</div>
        <div class="metric-val" style="color: #58a6ff;">{stats.get('total_requests', 0)}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-lbl">Blocked Attacks</div>
        <div class="metric-val" style="color: #f85149;">{stats.get('blocked_requests', 0)}</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    block_rate = stats.get('block_rate_percent', 0.0)
    rate_color = "#f85149" if block_rate > 50 else ("#d29922" if block_rate > 20 else "#3fb950")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-lbl">Block Rate %</div>
        <div class="metric-val" style="color: {rate_color};">{block_rate}%</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    anom_ratio = ai_metrics.get("anomaly_ratio_percent", 0.0)
    anom_color = "#f85149" if anom_ratio > 20 else ("#d29922" if anom_ratio > 5 else "#3fb950")
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-lbl">AI Anomaly Index</div>
        <div class="metric-val" style="color: {anom_color};">{anom_ratio}%</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# Row 2: Live Traffic Timeline & AI Anomaly Gauge
row2_col1, row2_col2 = st.columns([6, 4])

with row2_col1:
    st.subheader("📈 Live Traffic & Threat Score History")
    history_data = stats.get("history", [])
    if history_data:
        df_hist = pd.DataFrame(history_data)
        fig_hist = px.line(
            df_hist,
            x="time",
            y="score",
            color="action",
            color_discrete_map={"BLOCK": "#f85149", "ALLOW": "#3fb950"},
            markers=True,
            title="Request Threat Score Timeline",
            labels={"score": "Threat Score (0-100)", "time": "Timestamp"}
        )
        fig_hist.update_layout(
            template="plotly_dark",
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            height=320,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        fig_hist.add_hline(y=60, line_dash="dash", line_color="#da3633", annotation_text="Block Threshold (60)")
        try:
            st.plotly_chart(fig_hist, use_container_width=True)
        except TypeError:
            st.plotly_chart(fig_hist)
    else:
        st.info("No traffic history recorded yet. Click a button in the sidebar to generate traffic!")

with row2_col2:
    st.subheader("🧠 AI Behavioral Anomaly Gauge")
    norm_cnt = ai_metrics.get("normal_count", 0)
    anom_cnt = ai_metrics.get("anomaly_count", 0)
    
    if norm_cnt + anom_cnt > 0:
        fig_gauge = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = anom_ratio,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Isolation Forest Outlier Rate (%)", 'font': {'size': 15}},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "white"},
                'bar': {'color': "#f85149"},
                'bgcolor': "#21262d",
                'borderwidth': 2,
                'bordercolor': "#30363d",
                'steps': [
                    {'range': [0, 15], 'color': 'rgba(35, 134, 54, 0.4)'},
                    {'range': [15, 40], 'color': 'rgba(210, 153, 34, 0.4)'},
                    {'range': [40, 100], 'color': 'rgba(218, 54, 51, 0.4)'}
                ],
            }
        ))
        fig_gauge.update_layout(
            template="plotly_dark",
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            height=320,
            margin=dict(l=30, r=30, t=40, b=20)
        )
        try:
            st.plotly_chart(fig_gauge, use_container_width=True)
        except TypeError:
            st.plotly_chart(fig_gauge)
    else:
        st.info("AI Isolation Forest ready. Waiting for initial traffic evaluations.")

# Row 3: Collaborative Threat Sharing Feed & Shadow API Audit Log
st.markdown("---")
row3_col1, row3_col2 = st.columns([5, 5])

with row3_col1:
    st.subheader("🌐 Collaborative Inter-Bank Threat Intelligence Feed")
    if threat_sharing_feed:
        df_feed = pd.DataFrame(threat_sharing_feed)
        try:
            st.dataframe(df_feed[["timestamp", "threat_hash", "attack_type", "threat_score", "consortium_status"]], use_container_width=True, height=260)
        except TypeError:
            st.dataframe(df_feed[["timestamp", "threat_hash", "attack_type", "threat_score", "consortium_status"]], height=260)
    else:
        st.info("No threat indicators broadcasted to consortium feed yet.")

with row3_col2:
    st.subheader("🕵️ Shadow API Discovery & Unmapped Route Audit")
    if shadow_api_logs:
        df_shadow = pd.DataFrame(shadow_api_logs)
        try:
            st.dataframe(df_shadow[["timestamp", "client_ip", "method", "unmapped_path", "compliance_status"]], use_container_width=True, height=260)
        except TypeError:
            st.dataframe(df_shadow[["timestamp", "client_ip", "method", "unmapped_path", "compliance_status"]], height=260)
    else:
        st.info("No unmapped shadow API probes detected.")

# Row 4: Automated Incident Actions & Prevented Loss Audit
st.markdown("---")
row4_col1, row4_col2 = st.columns([5, 5])

with row4_col1:
    st.subheader("⚡ Automated Incident Response Actions")
    actions_log = responder_stats.get("actions_log", [])
    if actions_log:
        df_actions = pd.DataFrame(actions_log)
        try:
            st.dataframe(df_actions[["timestamp", "type", "target", "reason", "status"]], use_container_width=True, height=240)
        except TypeError:
            st.dataframe(df_actions[["timestamp", "type", "target", "reason", "status"]], height=240)
    else:
        st.info("No active token revocations or alert dispatches triggered yet.")

with row4_col2:
    st.subheader("💰 Prevented Financial Breach Log (JOD)")
    prevented_log = financial_stats.get("prevented_log", [])
    if prevented_log:
        df_prev = pd.DataFrame(prevented_log)
        try:
            st.dataframe(df_prev[["timestamp", "client_ip", "target_endpoint", "prevented_amount_jod", "attack_type"]], use_container_width=True, height=240)
        except TypeError:
            st.dataframe(df_prev[["timestamp", "client_ip", "target_endpoint", "prevented_amount_jod", "attack_type"]], height=240)
    else:
        st.info("No financial transfer breaches blocked yet.")

# Row 5: Full Incident Log Table
st.markdown("---")
st.subheader("📋 Real-Time Firewall Incident Log Audit")

if logs:
    df_logs = pd.DataFrame(logs)
    df_logs["attack_types"] = df_logs["attack_types"].apply(lambda x: ", ".join(x) if isinstance(x, list) else str(x))
    df_logs["violations"] = df_logs["violations"].apply(lambda x: " | ".join(x) if isinstance(x, list) else str(x))
    
    display_df = df_logs[[
        "timestamp", "client_ip", "method", "path", "user_id", 
        "threat_score", "action", "severity", "attack_types", "violations"
    ]]

    def color_rows(val):
        if val == "BLOCK":
            return "background-color: rgba(218, 54, 51, 0.25); color: #ff7b72;"
        elif val == "ALLOW":
            return "background-color: rgba(35, 134, 54, 0.25); color: #56d364;"
        return ""

    styled_table = display_df.style.map(color_rows, subset=["action"])
    try:
        st.dataframe(styled_table, use_container_width=True, height=320)
    except TypeError:
        st.dataframe(styled_table, height=320)
else:
    st.info("Incident log audit table is currently empty.")

# Auto-refresh loop
if auto_refresh:
    time.sleep(3)
    st.rerun()
