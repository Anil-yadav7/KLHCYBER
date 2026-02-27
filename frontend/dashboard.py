"""BreachShield user-facing dashboard.

This module provides a Streamlit-powered Web UI that interacts asynchronously
with the FastAPI backend backend to manage monitored emails and visualize threats.
"""

import os
import time
from datetime import datetime
from typing import Any, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# Application Shell Configuration
st.set_page_config(
    page_title="BreachShield — Dark Web Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Backend Connectivity Configuration
API_BASE_URL: str = os.getenv("API_BASE_URL", "http://localhost:8000/api/v1")


# -------------------------------------------------------------------------
# API Helper Methods
# -------------------------------------------------------------------------

def api_get(endpoint: str, params: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any] | list[Any]]:
    """Safely execute an HTTP GET request against the BreachShield API.
    
    Args:
        endpoint: Relative API route (e.g., '/emails/').
        params: Optional URL query string parameters.
        
    Returns:
        The deserialized JSON response payload, or None if the request failed.
    """
    try:
        response = requests.get(f"{API_BASE_URL}{endpoint}", params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger_name: str = "FrontendAPI"
        # Standard Streamlit error surface
        st.error(f"Failed to communicate with API backend: {e}")
        return None


def api_post(endpoint: str, data: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Safely execute an HTTP POST request to mutate state on the backend.
    
    Args:
        endpoint: Relative API route to post data towards.
        data: Payload dictionary to serialize as JSON.
        
    Returns:
        The deserialized Server response, or None if the transmission failed.
    """
    try:
        response = requests.post(f"{API_BASE_URL}{endpoint}", json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        if hasattr(e, "response") and e.response is not None:
            err_detail = e.response.json().get("detail", "Unknown error")
            st.error(f"Request Rejected: {err_detail}")
        else:
            st.error(f"Network error while connecting to backend: {e}")
        return None


def api_delete(endpoint: str) -> bool:
    """Execute an HTTP DELETE request safely."""
    try:
        response = requests.delete(f"{API_BASE_URL}{endpoint}", timeout=10)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        st.error(f"Failed to delete resource: {e}")
        return False


# -------------------------------------------------------------------------
# Session State Management
# -------------------------------------------------------------------------

if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

# Implement 5-minute passive auto-refresh loop
if time.time() - st.session_state.last_refresh > 300:
    st.session_state.last_refresh = time.time()
    st.rerun()


# -------------------------------------------------------------------------
# Sidebar Component: Email Surface Area Administration
# -------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## 🛡️ BreachShield")
    st.caption("Dark Web Intelligence Tracker")
    st.divider()
    
    st.markdown("### Threat Surface")
    new_email: str = st.text_input("Add Email to Monitor", placeholder="you@example.com")
    new_phone: str = st.text_input("SMS Alerts Number (Optional)", placeholder="+15551234567")
    
    if st.button("Start Monitoring", type="primary", use_container_width=True):
        if new_email:
            with st.spinner("Provisioning monitoring tasks..."):
                payload = {"email": new_email}
                if new_phone:
                    payload["phone_number"] = new_phone
                    
                result = api_post("/emails/", payload)
                if result:
                    st.success(f"Now monitoring email: {result.get('email_preview')}")
                    time.sleep(1)
                    st.rerun()  # Refresh sidebar list immediately
        else:
            st.warning("Please enter a valid email address.")
            
    st.divider()
    
    # Active Tracking Roster
    st.markdown("**Actively Monitored Identities**")
    monitored_emails = api_get("/emails/")
    if monitored_emails:
        for identity in monitored_emails:
            c1, c2 = st.columns([3, 1])
            preview: str = identity.get("email_preview", "Unknown")
            c1.markdown(f"`{preview}`")
            if c2.button("🗑️", key=f"del_{identity['id']}", help=f"Stop monitoring {preview}"):
                if api_delete(f"/emails/{identity['id']}"):
                    st.toast(f"Halted monitoring for {preview}")
                    time.sleep(1)
                    st.rerun()
    else:
        st.info("No addresses currently monitored.")


# -------------------------------------------------------------------------
# Main Core Dashboard Navigation
# -------------------------------------------------------------------------

tab_overview, tab_breaches, tab_alerts, tab_settings = st.tabs([
    "🏠 Overview", "🔍 Breaches", "📬 Alerts", "⚙️ Settings"
])

# -------------------------------------------------------------------------
# TAB 1: Real-time Strategic Overview
# -------------------------------------------------------------------------
with tab_overview:
    st.header("Security Posture Overview")
    
    stats_payload = api_get("/breaches/stats")
    
    if stats_payload:
        # High-level Metrics Ticker
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔴 Critical Exfiltrations", stats_payload.get("critical_count", 0))
        c2.metric("🟠 High Risk Incidents", stats_payload.get("high_count", 0))
        c3.metric("🟡 Medium Impact", stats_payload.get("medium_count", 0))
        c4.metric("🟢 Low Impact", stats_payload.get("low_count", 0))
        
        st.divider()
        
        col_gauge, col_chart = st.columns([1, 2])
        
        # Threat Compass: Objective Risk Gauge
        with col_gauge:
            current_risk: int = stats_payload.get("risk_score", 0)
            
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=current_risk,
                domain={"x": [0, 1], "y": [0, 1]},
                title={"text": "Global Threat Surface Index"},
                gauge={
                    "axis": {"range": [None, 100], "tickwidth": 1},
                    "bar": {"color": "black"},
                    "steps": [
                        {"range": [0, 40], "color": "#2E7D32"},    # Green/Safe
                        {"range": [40, 70], "color": "#ED6C02"},   # Orange/Warning
                        {"range": [70, 100], "color": "#D32F2F"}   # Red/Critical
                    ],
                    "threshold": {
                        "line": {"color": "black", "width": 4},
                        "thickness": 0.75,
                        "value": current_risk
                    }
                }
            ))
            fig_gauge.update_layout(height=350, margin=dict(l=20, r=20, t=50, b=20))
            st.plotly_chart(fig_gauge, use_container_width=True)
            
        # Incident Frequency Distribution Chart
        with col_chart:
            # We must fetch the full unpaginated breach list to construct the timeline
            # Note: Production scale would rely on a distinct aggregator endpoint, but we map here.
            timeline_data = api_get("/breaches/", params={"limit": 100})
            
            if timeline_data and timeline_data.get("items"):
                df = pd.DataFrame(timeline_data["items"])
                
                # Normalize schema nulls into workable timeline bands
                df["breach_date"] = pd.to_datetime(df["breach_date"]).dt.date
                df = df.dropna(subset=["breach_date"])
                
                if not df.empty:
                    # Aggregate total breaches incident by date mapped against severity vectors
                    timeline_df = df.groupby(["breach_date", "severity"]).size().reset_index(name="count")
                    
                    # Lock standard hex code mappings across UI
                    color_discrete_map = {
                        "CRITICAL": "#D32F2F",
                        "HIGH": "#ED6C02",
                        "MEDIUM": "#FFB300",
                        "LOW": "#2E7D32"
                    }
                    
                    fig_bar = px.bar(
                        timeline_df, 
                        x="breach_date", 
                        y="count", 
                        color="severity",
                        title="Breach Timetable Vector Mapping",
                        color_discrete_map=color_discrete_map,
                        labels={"breach_date": "Incident Date", "count": "Registered Breaches"}
                    )
                    fig_bar.update_layout(height=350, margin=dict(l=20, r=20, t=50, b=20))
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.info("Insufficient structured date data to map temporal breach timeline.")
            else:
                st.info("No timeline data currently available.")
    else:
        st.warning("Core telemetry engine is currently initializing or unreachable.")


# -------------------------------------------------------------------------
# TAB 2: Breach Analysis & Remediation Log
# -------------------------------------------------------------------------
with tab_breaches:
    st.header("Compromise Analytics")
    
    # Filtering Control Bar
    f_col1, f_col2, f_col3 = st.columns([1, 1, 2])
    severity_filter = f_col1.selectbox(
        "Filter Vector Stage", 
        ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    )
    # Basic pagination constraints for standard UI performance
    limit_filter: int = st.session_state.get("breach_limit", 50)
    
    query_params: dict[str, Any] = {"limit": limit_filter}
    if severity_filter != "ALL":
        query_params["severity"] = severity_filter
        
    f_col3.markdown("<br>", unsafe_allow_html=True)
    if f_col3.button("Export CSV Manifest", type="secondary"):
        st.markdown(f"**[Click here to securely download data export]({API_BASE_URL}/breaches/export/csv)**")

    breaches_payload = api_get("/breaches/", params=query_params)
    
    if breaches_payload and breaches_payload.get("items"):
        breach_items = breaches_payload["items"]
        
        for breach in breach_items:
            badge_color: str = "grey"
            if breach["severity"] == "CRITICAL": badge_color = "red"
            elif breach["severity"] == "HIGH": badge_color = "orange"
            elif breach["severity"] == "MEDIUM": badge_color = "yellow"
            elif breach["severity"] == "LOW": badge_color = "green"
            
            # Format cleanly parsed times
            detected_str: str = "Unknown"
            if breach["detected_at"]:
                # Convert ISO back to friendly format
                detected_time = datetime.fromisoformat(breach["detected_at"].replace("Z", "+00:00"))
                detected_str = detected_time.strftime("%Y-%m-%d %H:%M UTC")

            header_markdown: str = f"**:{badge_color}[{breach['severity']}]** {breach['breach_name']} *(Detected: {detected_str})*"
            
            with st.expander(header_markdown):
                b_col1, b_col2 = st.columns([2, 1])
                
                with b_col1:
                    st.markdown("**Stolen Data Topologies:**")
                    classes: list[str] = breach.get("data_classes", [])
                    if classes:
                        tags_html: str = " ".join([f"<span style='background:#f0f2f6;color:black;padding:3px 8px;border-radius:12px;font-size:12px;margin-right:5px;'>{c}</span>" for c in classes])
                        st.markdown(tags_html, unsafe_allow_html=True)
                    else:
                        st.write("Target vectors unknown or unpublished.")
                
                with b_col2:
                    if st.button("Re-trigger Alert", key=f"resend_{breach['id']}", use_container_width=True):
                        if api_post(f"/alerts/{breach['id']}/resend", data={}):
                            st.toast("Alert transmission forced into queue.")
                
                st.markdown("<hr style='margin:10px 0'>", unsafe_allow_html=True)
                
                # Fetch deeper details payload inline to keep primary listing list highly performant
                with st.spinner("Fetching AI Action Plan..."):
                    details = api_get(f"/breaches/{breach['id']}")
                    if details and details.get("remediation_text"):
                        st.markdown("**🛡️ AI Tactical Action Plan:**")
                        st.markdown(f"```text\n{details['remediation_text']}\n```")
                    else:
                        st.info("Action plan processing. Check back momentarily.")
    else:
        st.success("Your footprint remains secure. Zero tracking events detected under current filters.")


# -------------------------------------------------------------------------
# TAB 3: Delivery Alert Subsystem
# -------------------------------------------------------------------------
with tab_alerts:
    st.header("Notification Triggers & Network Logs")
    
    alert_stats = api_get("/alerts/stats")
    if alert_stats:
        ac1, ac2, ac3 = st.columns(3)
        ac1.metric("Lifetime Delivered", alert_stats["total_sent"])
        ac2.metric("Transmission Failures", alert_stats["total_failed"])
        ac3.metric("Network Reliability Rate", f"{alert_stats['success_rate']}%")
        
    st.divider()
    
    alert_logs = api_get("/alerts/")
    if alert_logs:
        df_alerts = pd.DataFrame(alert_logs)
        # Prune dataset to front-facing columns only
        display_df = df_alerts[["sent_at", "channel", "recipient", "status", "error_message"]].copy()
        display_df["sent_at"] = pd.to_datetime(display_df["sent_at"]).dt.strftime("%Y-%m-%d %H:%M:%S")
        
        # Color coding mechanism leveraging Streamlit dataframe styler
        def highlight_status(val: Any) -> str:
            color = "#D32F2F" if str(val).lower() == "failed" else "#2E7D32" if str(val).lower() == "sent" else ""
            return f'color: {color}; font-weight: bold;'
            
        styled_df = display_df.style.map(highlight_status, subset=["status"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)
    else:
        st.info("No outbound transmission logs registered on this footprint.")


# -------------------------------------------------------------------------
# TAB 4: Core System Configuration
# -------------------------------------------------------------------------
with tab_settings:
    st.header("Engine Configuration Matrix")
    
    st.markdown("### Global Scanning Cadence")
    st.info("The external HIBP intelligence ingestion framework is rigidly scheduled via Celery workers to sweep active identities every 6 hours.")
    
    st.markdown("### Subsystem State")
    health_data = api_get("/health")  # Using FastAPI health route
    if health_data:
        st.code(f"""
Deployment App: {health_data.get('app', 'UNKNOWN')}
Container Version: v{health_data.get('version', '0.0.0')}
State: {health_data.get('status', 'OFFLINE').upper()}
Database Multiplexer: {health_data.get('database', 'UNKNOWN').upper()}
        """, language="yaml")
    else:
        st.error("Cannot resolve engine state telemetry.")
    
    if st.button("Force Synchronous Cache Sweep", type="primary", disabled=True, help="Administrator override locked."):
        pass
