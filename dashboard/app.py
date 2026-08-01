import streamlit as st
import pandas as pd

from dashboard_utils import DashboardLoader

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

c1, c2, c3, c4 = st.columns(4)

c1.metric("🔴 Critical", stats.get("CRITICAL", 0))
c2.metric("🟠 High", stats.get("HIGH", 0))
c3.metric("🟡 Medium", stats.get("MEDIUM", 0))
c4.metric("🟢 Safe", stats.get("INFO", 0))

st.divider()

# ==========================================
# Search
# ==========================================

search = st.text_input("🔍 Search filename")

table = pd.DataFrame(alerts)

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

    st.subheader("🛡 Recommendation")

    recommendation = alert.get(
        "recommendation",
        "No recommendation available."
    )

    st.info(recommendation)