import sys
from pathlib import Path

# Allow importing from src/ when running via `streamlit run dashboard/app.py`
sys.path.append(str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from dashboard_utils import DashboardLoader
from src.reporter import ReportGenerator

loader = DashboardLoader()

alerts = loader.load_alerts()
stats = loader.statistics()

st.set_page_config(
    page_title="Redstone SOC",
    page_icon="⛏️",
    layout="wide"
)

st.title("⛏️ Redstone SOC")
st.caption("Minecraft-inspired Security Operations Center")

st.divider()

# ==========================================
# Metrics
# ==========================================

scores = [a.get("threat_score", 0) for a in alerts]
avg_score = round(sum(scores) / len(scores), 1) if scores else 0

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("🔴 Critical", stats.get("CRITICAL", 0))
c2.metric("🟠 High", stats.get("HIGH", 0))
c3.metric("🟡 Medium", stats.get("MEDIUM", 0))
c4.metric("🟢 Safe", stats.get("INFO", 0))
c5.metric("📊 Avg Score", f"{avg_score}/100")

st.divider()

# ==========================================
# Base table
# ==========================================

table = pd.DataFrame(alerts)

# ==========================================
# Filters (Day 19)
# ==========================================

if not table.empty:

    table["timestamp_parsed"] = pd.to_datetime(table["timestamp"])

    with st.expander("🔍 Filters"):

        f1, f2, f3 = st.columns(3)

        with f1:
            severity_options = sorted(table["severity"].dropna().unique())
            selected_severity = st.multiselect(
                "⚠️ Severity",
                severity_options,
                default=severity_options
            )

        with f2:
            status_options = sorted(table["status"].dropna().unique())
            selected_status = st.multiselect(
                "📌 Status",
                status_options,
                default=status_options
            )

        with f3:
            min_date = table["timestamp_parsed"].min().date()
            max_date = table["timestamp_parsed"].max().date()

            date_range = st.date_input(
                "🗓️ Period",
                value=(min_date, max_date),
                min_value=min_date,
                max_value=max_date
            )

    table = table[
        table["severity"].isin(selected_severity)
        & table["status"].isin(selected_status)
    ]

    if isinstance(date_range, tuple) and len(date_range) == 2:

        start_date, end_date = date_range

        table = table[
            (table["timestamp_parsed"].dt.date >= start_date)
            & (table["timestamp_parsed"].dt.date <= end_date)
        ]

    table = table.drop(columns=["timestamp_parsed"])

# ==========================================
# Search
# ==========================================

search = st.text_input("🔍 Search filename")

if not table.empty and search:

    table = table[
        table["file_name"].str.contains(
            search,
            case=False,
            na=False
        )
    ]

# ==========================================
# Alert Table
# ==========================================

st.subheader("📄 Alerts")

if table.empty:

    st.info("No alerts found.")

else:

    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True
    )

    # ==========================================
    # Export Report (Day 20)
    # ==========================================

    filtered_alerts = table.to_dict("records")

    filtered_summary = {
        severity: int((table["severity"] == severity).sum())
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "INFO")
    }

    exp1, exp2 = st.columns(2)

    with exp1:
        st.download_button(
            "⬇️ Export CSV",
            data=ReportGenerator.generate_csv(filtered_alerts),
            file_name="redstone_soc_report.csv",
            mime="text/csv",
            use_container_width=True
        )

    with exp2:
        st.download_button(
            "⬇️ Export PDF",
            data=ReportGenerator.generate_pdf(filtered_alerts, filtered_summary),
            file_name="redstone_soc_report.pdf",
            mime="application/pdf",
            use_container_width=True
        )

    st.divider()

    # ==========================================
    # Timeline
    # ==========================================

    st.subheader("🕒 Alert Timeline")

    severity_icon = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "INFO": "🟢"
    }

    for _, row in table.iterrows():

        icon = severity_icon.get(
            row["severity"],
            "⚪"
        )

        with st.container():

            st.markdown(
                f"""
### {icon} {row['file_name']}

**Severity:** {row['severity']}

**Status:** {row['status']}

**Time:** {row['timestamp']}

**Reason:** {row['reason']}
"""
            )

            st.divider()

    # ==========================================
    # Threat Details
    # ==========================================

    st.subheader("🚨 Threat Details")

    selected = st.selectbox(
        "Select an alert",
        table["file_name"]
    )

    alert = table[
        table["file_name"] == selected
    ].iloc[0]

    col1, col2 = st.columns(2)

    with col1:

        st.write(f"**📄 File:** {alert['file_name']}")
        st.write(f"**🚨 Severity:** {alert['severity']}")
        st.write(f"**📌 Status:** {alert['status']}")
        st.write(f"**💬 Reason:** {alert['reason']}")

        st.write(
            f"**🎯 MITRE:** {alert.get('mitre', 'N/A')}"
        )

    with col2:

        st.write(f"**🕒 Timestamp:** {alert['timestamp']}")
        st.write(f"**🔐 SHA256:** {alert['sha256']}")
        st.write(f"**📂 Path:** {alert['path']}")
        st.write(f"**📦 Size:** {alert['size']} bytes")

    st.divider()

    # ==========================================
    # Threat Score Gauge (Redstone Power Level)
    # ==========================================

    st.subheader("⚡ Redstone Power Level (Threat Score)")

    threat_score = alert.get("threat_score", 0)
    if pd.isna(threat_score):
        threat_score = 0

    gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=threat_score,
        number={"suffix": " / 100"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "#8B0000"},
            "steps": [
                {"range": [0, 30], "color": "#3ba55d"},
                {"range": [30, 60], "color": "#f1c40f"},
                {"range": [60, 80], "color": "#e67e22"},
                {"range": [80, 100], "color": "#e74c3c"}
            ]
        }
    ))

    gauge.update_layout(
        height=280,
        margin=dict(t=30, b=10, l=30, r=30)
    )

    st.plotly_chart(gauge, use_container_width=True)

    st.divider()

    st.subheader("🛡 Recommendation")

    recommendation = alert.get(
        "recommendation",
        "No recommendation available."
    )

    st.info(recommendation)