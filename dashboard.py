"""
NetGuard-Agent: Streamlit Dashboard
Dashboard بسيط وسريع لعرض الـ alerts والإحصائيات
"""

import streamlit as st
import sys
import os
from datetime import datetime, timedelta
import plotly.express as px
import pandas as pd

# Add app to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.detector import get_detector
from app.services.alert_store import get_alert_store
from app.services.llm_explainer import get_explainer

st.set_page_config(
    page_title="NetGuard-Agent Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =============================================
# Styling
# =============================================

st.markdown("""
<style>
    .metric-card {
        padding: 20px;
        border-radius: 10px;
        background-color: #f0f2f6;
        border-left: 4px solid #1f77b4;
    }
    .critical {border-left-color: #d62728;}
    .high {border-left-color: #ff7f0e;}
    .medium {border-left-color: #ffbb78;}
    .low {border-left-color: #98df8a;}
</style>
""", unsafe_allow_html=True)

# =============================================
# Sidebar
# =============================================

st.sidebar.title("🛡️ NetGuard-Agent")
st.sidebar.markdown("---")

mode = st.sidebar.radio("Select Mode", ["Dashboard", "Test Detection", "Alert Details"])

# =============================================
# Initialize services
# =============================================

@st.cache_resource
def init_services():
    detector = get_detector()
    store = get_alert_store(persist=False)
    explainer = get_explainer()
    return detector, store, explainer

detector, store, explainer = init_services()

# =============================================
# Page: Dashboard
# =============================================

if mode == "Dashboard":
    st.title("🛡️ Security Alerts Dashboard")
    
    # Stats
    stats = store.get_stats()
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Alerts", stats['total_alerts'], delta=None)
    
    with col2:
        st.metric(
            "Anomalies",
            stats['anomalies_detected'],
            delta=None,
            delta_color="inverse"
        )
    
    with col3:
        critical = stats['severity_distribution'].get('critical', 0)
        st.metric("Critical 🔴", critical, delta=None)
    
    with col4:
        processed = stats['total_processed']
        st.metric("Flows Analyzed", processed)
    
    st.markdown("---")
    
    # Severity distribution
    if stats['total_alerts'] > 0:
        col1, col2 = st.columns([1, 1])
        
        with col1:
            # Pie chart
            severity_data = stats['severity_distribution']
            df_severity = pd.DataFrame([
                {"Severity": k.upper(), "Count": v}
                for k, v in severity_data.items()
                if v > 0
            ])
            
            if not df_severity.empty:
                fig_pie = px.pie(
                    df_severity,
                    values='Count',
                    names='Severity',
                    color_discrete_map={
                        'CRITICAL': '#d62728',
                        'HIGH': '#ff7f0e',
                        'MEDIUM': '#ffbb78',
                        'LOW': '#98df8a',
                    }
                )
                st.plotly_chart(fig_pie, use_container_width=True)
        
        with col2:
            st.subheader("Recent Alerts")
            recent = store.get_recent(limit=10)
            if recent:
                for alert in recent:
                    severity = alert.get('severity', 'unknown').upper()
                    color_map = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠',
                        'MEDIUM': '🟡',
                        'LOW': '🟢',
                    }
                    emoji = color_map.get(severity, '⚪')
                    
                    with st.container():
                        st.write(
                            f"{emoji} **{alert.get('title', 'Unknown')}** "
                            f"({alert.get('source_ip', 'N/A')})"
                        )
                        st.caption(
                            f"Score: {alert.get('anomaly_score', 0):.2f} | "
                            f"ML: {alert.get('ml_flagged', False)}"
                        )
    else:
        st.info("No alerts yet. Run detection to generate alerts.")

# =============================================
# Page: Test Detection
# =============================================

elif mode == "Test Detection":
    st.title("🧪 Test Detection Engine")
    
    st.write(
        "Generate test flows to see the detector in action. "
        "Choose a scenario and analyze it."
    )
    
    scenario = st.selectbox(
        "Select Attack Scenario",
        [
            "Normal Traffic",
            "Port Scanning Attack",
            "Data Exfiltration",
            "UDP Flood",
            "Mixed (All)",
        ]
    )
    
    scenarios = {
        "Normal Traffic": [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "142.250.80.46",
                "source_port": 52341,
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_sent": 1500,
                "bytes_received": 45000,
            },
        ],
        "Port Scanning Attack": [
            {
                "source_ip": "203.0.113.99",
                "destination_ip": "192.168.1.10",
                "source_port": 63412,
                "destination_port": 22,
                "protocol": "TCP",
                "bytes_sent": 60,
                "bytes_received": 0,
            },
        ],
        "Data Exfiltration": [
            {
                "source_ip": "192.168.1.55",
                "destination_ip": "185.220.101.45",
                "source_port": 49201,
                "destination_port": 8080,
                "protocol": "TCP",
                "bytes_sent": 25_000_000,
                "bytes_received": 150,
            },
        ],
        "UDP Flood": [
            {
                "source_ip": "203.0.113.5",
                "destination_ip": "8.8.8.8",
                "source_port": 55000,
                "destination_port": 53,
                "protocol": "UDP",
                "bytes_sent": 10_000_000,
                "bytes_received": 0,
            },
        ],
        "Mixed (All)": [
            {
                "source_ip": "192.168.1.10",
                "destination_ip": "142.250.80.46",
                "source_port": 52341,
                "destination_port": 443,
                "protocol": "TCP",
                "bytes_sent": 1500,
                "bytes_received": 45000,
            },
            {
                "source_ip": "203.0.113.99",
                "destination_ip": "192.168.1.10",
                "source_port": 63412,
                "destination_port": 22,
                "protocol": "TCP",
                "bytes_sent": 60,
                "bytes_received": 0,
            },
            {
                "source_ip": "192.168.1.55",
                "destination_ip": "185.220.101.45",
                "source_port": 49201,
                "destination_port": 8080,
                "protocol": "TCP",
                "bytes_sent": 25_000_000,
                "bytes_received": 150,
            },
        ],
    }
    
    if st.button("🔍 Analyze", key="analyze_btn"):
        flows = scenarios[scenario]
        
        with st.spinner("Analyzing flows..."):
            from app.core.detector import build_alerts
            
            results = detector.predict(flows)
            alerts = build_alerts(results, flows)
            
            # Store alerts
            store.add_alerts(alerts)
        
        st.success(f"✅ Analysis complete! Generated {len(alerts)} alert(s)")
        
        # Display results
        if alerts:
            st.subheader("🚨 Alerts Generated")
            for alert in alerts:
                severity = alert['severity'].upper()
                color_map = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢',
                }
                emoji = color_map.get(severity, '⚪')
                
                with st.expander(f"{emoji} {alert['title']} ({severity})"):
                    st.write(f"**Source:** {alert['source_ip']}")
                    st.write(f"**Destination:** {alert['destination_ip']}")
                    st.write(f"**Anomaly Score:** {alert['anomaly_score']:.4f}")
                    st.write(f"**Description:** {alert['description']}")
                    
                    if alert['rule_detections']:
                        st.write("**Rule Detections:**")
                        for rule in alert['rule_detections']:
                            st.write(f"- {rule['rule_name']}: {rule['description']}")

# =============================================
# Page: Alert Details
# =============================================

elif mode == "Alert Details":
    st.title("📋 Alert Details & Analysis")
    
    alerts = store.get_recent(limit=100)
    
    if not alerts:
        st.info("No alerts stored yet.")
    else:
        # Filter by severity
        col1, col2 = st.columns([1, 2])
        
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
            )
        
        with col2:
            search_ip = st.text_input("Search by Source IP")
        
        # Apply filters
        filtered = alerts
        if severity_filter != "All":
            filtered = [a for a in filtered if a.get('severity', '').upper() == severity_filter]
        if search_ip:
            filtered = [a for a in filtered if search_ip in a.get('source_ip', '')]
        
        st.write(f"Showing {len(filtered)} alert(s) out of {len(alerts)}")
        
        # Display detailed alert
        if filtered:
            selected_alert = st.selectbox(
                "Select Alert",
                [f"{a['title']} ({a['source_ip']})" for a in filtered],
                key="alert_select"
            )
            
            alert_idx = [
                f"{a['title']} ({a['source_ip']})" for a in filtered
            ].index(selected_alert)
            alert = filtered[alert_idx]
            
            st.subheader(alert['title'])
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Severity", alert.get('severity', 'N/A').upper())
            with col2:
                st.metric("Anomaly Score", f"{alert.get('anomaly_score', 0):.4f}")
            with col3:
                st.metric("ML Flagged", "Yes" if alert.get('ml_flagged') else "No")
            
            st.markdown("---")
            
            st.write(f"**Source IP:** {alert['source_ip']}")
            st.write(f"**Destination IP:** {alert['destination_ip']}")
            st.write(f"**Description:** {alert['description']}")
            
            # LLM Explanation
            if st.button("🤖 Get AI Explanation"):
                with st.spinner("Generating explanation..."):
                    explanation = explainer.explain(alert)
                
                st.subheader("AI Analysis")
                st.write(f"**Provider:** {explanation.get('provider', 'api')}")
                
                st.write(f"**Risk Analysis:** {explanation.get('risk_analysis', 'N/A')}")
                st.write(f"**Recommended Actions:**")
                for i, action in enumerate(explanation.get('recommended_actions', []), 1):
                    st.write(f"{i}. {action}")

st.sidebar.markdown("---")
st.sidebar.caption("NetGuard-Agent v1.0 | Hybrid Detection System")
