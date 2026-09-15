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
    layout="wide"
)

# Gateway Flow background. Markdown handles CSS; a v2 component executes the
# canvas JavaScript (script tags in st.markdown do not execute).
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    .stApp {
        background-color: transparent !important;
        isolation: isolate;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }
    [data-testid="stAppViewContainer"] {
        background: transparent !important;
    }
    #gateway-bg-container {
        position: fixed;
        inset: 0;
        width: 100vw;
        height: 100vh;
        z-index: -1;
        pointer-events: none;
        background: #000000;
    }
    #flow-canvas {
        width: 100%;
        height: 100%;
        display: block;
    }

    /* Section Headers */
    .modern-section-header {
        font-size: 0.85rem !important;
        font-weight: 600 !important;
        text-transform: uppercase !important;
        letter-spacing: 1.5px !important;
        color: #94A3B8 !important;
        margin-top: 1.5rem !important;
        margin-bottom: 0.75rem !important;
    }

    /* Subtitles and Descriptions */
    .modern-subtext {
        font-size: 0.85rem !important;
        color: #64748B !important;
        font-weight: 400 !important;
        letter-spacing: 0.2px !important;
    }

    .sidebar-control-title {
        color: #E2E8F0;
        font-size: 1rem;
        font-weight: 600;
        letter-spacing: 1.8px;
        line-height: 1.2;
        padding: 0.4rem 0 0.75rem;
        text-transform: uppercase;
    }

    /* Liquid Metal Button Styling for Sidebar Buttons */
    div[data-testid="stSidebar"] button,
    section[data-testid="stSidebar"] button {
        background: linear-gradient(180deg, #1e2430 0%, #0a0d14 100%) !important;
        border: 1px solid rgba(255, 255, 255, 0.15) !important;
        border-radius: 100px !important;
        color: #e2e8f0 !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
        font-weight: 500 !important;
        font-size: 0.85rem !important;
        padding: 0.6rem 1rem !important;
        box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.5), inset 0px 1px 1px rgba(255, 255, 255, 0.15) !important;
        transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
        width: 100% !important;
        margin-bottom: 8px !important;
    }

    div[data-testid="stSidebar"] button:hover,
    section[data-testid="stSidebar"] button:hover {
        background: linear-gradient(180deg, #2a3242 0%, #121722 100%) !important;
        border-color: rgba(255, 255, 255, 0.4) !important;
        color: #ffffff !important;
        box-shadow: 0px 0px 15px rgba(255, 255, 255, 0.2), inset 0px 1px 2px rgba(255, 255, 255, 0.3) !important;
        transform: translateY(-1px) scale(1.02) !important;
    }

    div[data-testid="stSidebar"] button:active,
    section[data-testid="stSidebar"] button:active {
        transform: translateY(1px) scale(0.98) !important;
        box-shadow: inset 0px 2px 4px rgba(0, 0, 0, 0.7) !important;
    }
</style>
""", unsafe_allow_html=True)

gateway_background = st.components.v2.component(
    "lamsa_gateway_background",
    isolate_styles=False,
    html="""
    <div id="gateway-bg-container" aria-hidden="true">
        <canvas id="flow-canvas"></canvas>
    </div>
    """,
    js="""
export default function ({ parentElement }) {
    const canvas = parentElement.querySelector('#flow-canvas');
    const ctx = canvas?.getContext('2d');
    if (!ctx) return;

    // Draw the dotted curves once per resize, then only animate 70 particles.
    const backdrop = document.createElement('canvas');
    const backdropCtx = backdrop.getContext('2d');
    if (!backdropCtx) return;
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
    const paths = Array.from({ length: 70 }, (_, i) => ({
        isLeft: i % 2 === 0,
        startRatio: (i / 70) * 1.4 - 0.2,
        t: Math.random(),
        speed: (0.0012 + Math.random() * 0.0018) * 60,
    }));
    let width = 0;
    let height = 0;
    let dpr = 1;
    let frameId = null;
    let previousTime = null;
    let disposed = false;

    function resize() {
        width = window.innerWidth;
        height = window.innerHeight;
        // Keep high-DPI displays sharp without unbounded canvas memory/work.
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        canvas.width = backdrop.width = Math.round(width * dpr);
        canvas.height = backdrop.height = Math.round(height * dpr);
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        backdropCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
        const centerX = width / 2;
        const centerY = height / 2;
        backdropCtx.beginPath();
        for (const path of paths) {
            path.startY = path.startRatio * height;
            path.x0 = path.isLeft ? 0 : width;
            path.x1 = path.isLeft ? centerX * 0.5 : width - centerX * 0.5;
            path.x2 = path.isLeft ? centerX * 0.8 : width - centerX * 0.8;
            backdropCtx.moveTo(path.x0, path.startY);
            backdropCtx.bezierCurveTo(
                path.x1, path.startY, path.x2, centerY, centerX, centerY
            );
        }
        backdropCtx.strokeStyle = 'rgba(255, 255, 255, 0.25)';
        backdropCtx.lineWidth = 1;
        backdropCtx.setLineDash([1, 4]);
        backdropCtx.stroke();
        draw(0);
    }

    function draw(elapsed) {
        ctx.clearRect(0, 0, width, height);
        ctx.drawImage(backdrop, 0, 0, width, height);
        ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
        for (const path of paths) {
            path.t = (path.t + path.speed * elapsed) % 1;
            const t = path.t;
            const u = 1 - t;
            const x = u**3 * path.x0 + 3 * u**2 * t * path.x1
                + 3 * u * t**2 * path.x2 + t**3 * width / 2;
            const y = (u**3 + 3 * u**2 * t) * path.startY
                + (3 * u * t**2 + t**3) * height / 2;
            ctx.fillRect(x - 1.5, y - 1.5, 3, 3);
        }
    }

    function render(timestamp) {
        frameId = null;
        if (disposed || document.hidden || motionQuery.matches) return;
        if (dpr !== Math.min(window.devicePixelRatio || 1, 2)) resize();
        // Elapsed time keeps the flow speed consistent across refresh rates.
        const elapsed = previousTime === null ? 0
            : Math.min((timestamp - previousTime) / 1000, 0.05);
        previousTime = timestamp;
        draw(elapsed);
        frameId = requestAnimationFrame(render);
    }

    function syncMotion() {
        if (frameId !== null) cancelAnimationFrame(frameId);
        frameId = null;
        previousTime = null;
        if (!disposed && !document.hidden && !motionQuery.matches) {
            frameId = requestAnimationFrame(render);
        }
    }

    window.addEventListener('resize', resize, { passive: true });
    document.addEventListener('visibilitychange', syncMotion);
    motionQuery.addEventListener('change', syncMotion);
    resize();
    syncMotion();

    // Streamlit calls this when replacing/unmounting the component on reruns.
    return () => {
        disposed = true;
        if (frameId !== null) cancelAnimationFrame(frameId);
        window.removeEventListener('resize', resize);
        document.removeEventListener('visibilitychange', syncMotion);
        motionQuery.removeEventListener('change', syncMotion);
        backdrop.width = backdrop.height = 0;
    };
}
    """,
)
gateway_background(key="gateway_background", height=0)

# Custom CSS styling for the lamsa dashboard and metric cards
st.markdown("""
<style>
    .stApp {
        color: #c9d1d9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .brand-text {
        font-family: 'Inter', sans-serif;
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
<div class="sidebar-control-title">lamsa control panel</div>
""", unsafe_allow_html=True)

st.sidebar.markdown(
    '<div class="modern-section-header">Attack Simulator</div>',
    unsafe_allow_html=True,
)
st.sidebar.markdown(
    '<div class="modern-subtext">Run controlled probes against the Open Banking API.</div>',
    unsafe_allow_html=True,
)

if st.sidebar.button("BOLA Authorization Probe", key="btn_bola"):
    with st.spinner("Running BOLA authorization probe..."):
        res = simulate_bola_attack(BACKEND_URL)
        st.sidebar.success(f"BOLA probe complete ({res['attempts']} requests)")

if st.sidebar.button("Credential Stuffing Rate Limit", key="btn_cred"):
    with st.spinner("Testing credential rate limits..."):
        res = simulate_credential_stuffing(BACKEND_URL)
        st.sidebar.warning(f"Credential test complete ({res['attempts']} requests)")

if st.sidebar.button("SQL Injection / Payload Attack", key="btn_sqli"):
    with st.spinner("Testing SQL injection and payload vectors..."):
        res = simulate_sqli_attack(BACKEND_URL)
        st.sidebar.error(f"Payload test complete ({res['attempts']} requests)")

if st.sidebar.button("AI Behavioral Anomaly", key="btn_ai"):
    with st.spinner("Running behavioral anomaly simulation..."):
        res = simulate_ai_anomaly(BACKEND_URL)
        st.sidebar.error(f"Anomaly simulation complete ({res['attempts']} request)")

if st.sidebar.button("Honeypot Trap Probe", key="btn_honey"):
    with st.spinner("Probing the honeypot endpoint..."):
        res = simulate_honeypot_probe(BACKEND_URL)
        st.sidebar.error(f"Honeypot probe complete ({res['attempts']} requests)")

if st.sidebar.button("Shadow API Endpoint Scan", key="btn_shadow"):
    with st.spinner("Scanning the unregistered API endpoint..."):
        res = simulate_shadow_api_scan(BACKEND_URL)
        st.sidebar.error(f"Shadow API scan complete ({res['attempts']} request)")

if st.sidebar.button("High-Value Fraud Transfer", key="btn_fraud"):
    with st.spinner("Running the high-value transfer simulation..."):
        res = simulate_fraud_transfer(BACKEND_URL)
        st.sidebar.error(f"Transfer simulation complete ({res['attempts']} request)")

if st.sidebar.button("Legitimate User Traffic", key="btn_legit"):
    with st.spinner("Sending legitimate Open Banking requests..."):
        res = simulate_legitimate_traffic(BACKEND_URL)
        st.sidebar.info(f"Legitimate traffic complete ({res['attempts']} requests)")

st.sidebar.markdown("---")

st.sidebar.markdown(
    '<div class="modern-section-header">System Maintenance</div>',
    unsafe_allow_html=True,
)
if st.sidebar.button("Clear Telemetry and Traps"):
    try:
        requests.post(f"{BACKEND_URL}/api/v1/admin/clear", timeout=2)
        st.sidebar.success("All metrics and feeds reset clean.")
    except Exception as e:
        st.sidebar.error("Failed to clear backend metrics.")

auto_refresh = st.sidebar.checkbox("Auto-Refresh Dashboard (3s)", value=True)

# --- Main Dashboard Header ---
st.markdown("""
<style>
    .lamsa-title-container {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
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
        font-size: 0.9rem;
        font-weight: 500;
        color: #94A3B8;
        letter-spacing: 1.6px;
        text-transform: uppercase;
    }
    
    .lamsa-subtitle {
        font-size: 1.05rem;
        color: #64748B;
        margin-top: -5px;
        font-family: 'Inter', sans-serif;
    }
</style>

<div class="lamsa-title-container">
    <span class="lamsa-logo-text">lamsa</span>
    <span class="lamsa-descriptor">open banking firewall</span>
</div>
<div class="modern-subtext lamsa-subtitle">Inter-Bank Threat Intelligence Network &amp; Fraud Loss Prevention</div>
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
    st.markdown(
        '<div class="modern-section-header">Live Traffic & Threat Score</div>',
        unsafe_allow_html=True,
    )
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
            font=dict(family="Inter, -apple-system, BlinkMacSystemFont, sans-serif"),
            height=320,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        fig_hist.add_hline(y=60, line_dash="dash", line_color="#da3633", annotation_text="Block Threshold (60)")
        try:
            st.plotly_chart(fig_hist, use_container_width=True)
        except TypeError:
            st.plotly_chart(fig_hist)
    else:
        st.info("No traffic data yet. Run a simulation from the control panel to begin.")

with row2_col2:
    st.markdown(
        '<div class="modern-section-header">AI Anomaly Gauge</div>',
        unsafe_allow_html=True,
    )
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
            font=dict(family="Inter, -apple-system, BlinkMacSystemFont, sans-serif"),
            height=320,
            margin=dict(l=30, r=30, t=40, b=20)
        )
        try:
            st.plotly_chart(fig_gauge, use_container_width=True)
        except TypeError:
            st.plotly_chart(fig_gauge)
    else:
        st.info("AI anomaly detection is ready and awaiting traffic.")

# Row 3: Collaborative Threat Sharing Feed & Shadow API Audit Log
st.markdown("---")
row3_col1, row3_col2 = st.columns([5, 5])

with row3_col1:
    st.markdown(
        '<div class="modern-section-header">Inter-Bank Threat Intelligence</div>',
        unsafe_allow_html=True,
    )
    if threat_sharing_feed:
        df_feed = pd.DataFrame(threat_sharing_feed)
        try:
            st.dataframe(df_feed[["timestamp", "threat_hash", "attack_type", "threat_score", "consortium_status"]], use_container_width=True, height=260)
        except TypeError:
            st.dataframe(df_feed[["timestamp", "threat_hash", "attack_type", "threat_score", "consortium_status"]], height=260)
    else:
        st.info("No threat indicators have been shared with the consortium.")

with row3_col2:
    st.markdown(
        '<div class="modern-section-header">Shadow API Audit Log</div>',
        unsafe_allow_html=True,
    )
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
    st.markdown(
        '<div class="modern-section-header">Automated Incident Response</div>',
        unsafe_allow_html=True,
    )
    actions_log = responder_stats.get("actions_log", [])
    if actions_log:
        df_actions = pd.DataFrame(actions_log)
        try:
            st.dataframe(df_actions[["timestamp", "type", "target", "reason", "status"]], use_container_width=True, height=240)
        except TypeError:
            st.dataframe(df_actions[["timestamp", "type", "target", "reason", "status"]], height=240)
    else:
        st.info("No automated response actions have been recorded.")

with row4_col2:
    st.markdown(
        '<div class="modern-section-header">Prevented Financial Loss Log</div>',
        unsafe_allow_html=True,
    )
    prevented_log = financial_stats.get("prevented_log", [])
    if prevented_log:
        df_prev = pd.DataFrame(prevented_log)
        try:
            st.dataframe(df_prev[["timestamp", "client_ip", "target_endpoint", "prevented_amount_jod", "attack_type"]], use_container_width=True, height=240)
        except TypeError:
            st.dataframe(df_prev[["timestamp", "client_ip", "target_endpoint", "prevented_amount_jod", "attack_type"]], height=240)
    else:
        st.info("No prevented financial losses have been recorded.")

# Row 5: Full Incident Log Table
st.markdown("---")
st.markdown(
    '<div class="modern-section-header">Real-Time Incident Audit Trail</div>',
    unsafe_allow_html=True,
)

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
    st.info("No incidents have been recorded.")

# Auto-refresh loop
if auto_refresh:
    time.sleep(3)
    st.rerun()
