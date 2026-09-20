import streamlit as st

from src.parser import loadlogs
from src.detection import (
    get_failed_logins,
    count_ip,
    detect_brute_force,
    detect_failed_then_success,
    detect_suspicious_powershell,
    detect_admin_account_creation
)
from src.ai_analyzer import analyze_alert


st.title("CyberWatch")
st.subheader("AI-Assisted Security Monitoring Dashboard")


logs = loadlogs("data/sample_logs.csv")

failed_logs = get_failed_logins(logs)
ip_counts = count_ip(failed_logs)

all_alerts = []

all_alerts.extend(detect_brute_force(ip_counts))
all_alerts.extend(detect_failed_then_success(logs))
all_alerts.extend(detect_suspicious_powershell(logs))
all_alerts.extend(detect_admin_account_creation(logs))


critical_count = sum(1 for alert in all_alerts if alert["severity"] == "Critical")
high_count = sum(1 for alert in all_alerts if alert["severity"] == "High")
medium_count = sum(1 for alert in all_alerts if alert["severity"] == "Medium")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Logs", len(logs))
col2.metric("Total Alerts", len(all_alerts))
col3.metric("Critical Alerts", critical_count)
col4.metric("High Alerts", high_count)

st.subheader("Alert Overview")

st.dataframe(all_alerts, use_container_width=True)
st.subheader("Detailed Alerts")

for i, alert in enumerate(all_alerts):

    with st.expander(
        f"{alert['severity']} | {alert['alert_type']} | {alert['source_IP']}"
    ):

        st.write("Description:", alert["description"])
        st.write("Evidence:", alert["evidence"])

        if "username" in alert:
            st.write("Username:", alert["username"])

        if st.button("Analyze with AI", key=f"analyze_{i}"):

            try:
                with st.spinner("Analyzing alert..."):
                    analysis = analyze_alert(alert)

                st.markdown(analysis)

            except Exception:
                st.error(
                    "AI analysis is unavailable. Make sure Ollama is running."
                )