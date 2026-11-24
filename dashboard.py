
import sqlite3
from pathlib import Path

import pandas as pd
import streamlit as st

DB_PATH = Path(__file__).resolve().parent / "data" / "ids.db"

st.set_page_config(
    page_title="NIDS Security Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Network Intrusion Detection System")
st.caption("Real-Time Network Security Monitoring")

if not DB_PATH.exists():
    st.warning("Database not found. Start the IDS engine first.")
    st.stop()

def read_data(query):
    with sqlite3.connect(DB_PATH, timeout=10) as conn:
        return pd.read_sql_query(query, conn)

traffic = read_data("""
    SELECT * FROM traffic
    ORDER BY id DESC
    LIMIT 5000
""")

alerts = read_data("""
    SELECT * FROM alerts
    ORDER BY id DESC
    LIMIT 500
""")

total_packets = len(traffic)
total_alerts = len(alerts)
unique_ips = traffic["source_ip"].nunique() if not traffic.empty else 0
high_alerts = (
    len(alerts[alerts["severity"] == "HIGH"])
    if not alerts.empty else 0
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Captured Packets", total_packets)
col2.metric("Unique Source IPs", unique_ips)
col3.metric("Security Alerts", total_alerts)
col4.metric("High Severity", high_alerts)

st.divider()

st.subheader("Protocol Distribution")

if not traffic.empty:
    protocol_counts = traffic["protocol"].value_counts()
    st.bar_chart(protocol_counts)
else:
    st.info("Waiting for network traffic...")

st.subheader("Recent Network Traffic")

if not traffic.empty:
    st.dataframe(
        traffic.head(100),
        use_container_width=True
    )

st.divider()

st.subheader("Security Alerts")

if not alerts.empty:
    st.dataframe(
        alerts,
        use_container_width=True
    )
else:
    st.success("No security alerts recorded yet.")

if st.button("Refresh Dashboard"):
    st.rerun()

st.caption("Educational IDS | Rule-based detection")
