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

c1.metric("🔴 Critical", stats["CRITICAL"])
c2.metric("🟠 High", stats["HIGH"])
c3.metric("🟡 Medium", stats["MEDIUM"])
c4.metric("🟢 Safe", stats["INFO"])

st.divider()

# ==========================================
# Search
# ==========================================

search = st.text_input(
    "🔍 Search filename"
)

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
# Alert List
# ==========================================

st.subheader("📄 Alerts")

if table.empty:

    st.info("No alerts found.")

else:

    files = table["file_name"].tolist()

    selected = st.selectbox(
        "Select an alert",
        files
    )

    alert = table[
        table["file_name"] == selected
    ].iloc[0]

    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True
    )

    st.divider()

    st.subheader("🚨 Threat Details")

    col1, col2 = st.columns(2)

    with col1:

        st.write(f"**📄 File:** {alert['file_name']}")
        st.write(f"**🚨 Severity:** {alert['severity']}")
        st.write(f"**📌 Status:** {alert['status']}")
        st.write(f"**💬 Reason:** {alert['reason']}")

    with col2:

        st.write(f"**🕒 Timestamp:** {alert['timestamp']}")
        st.write(f"**🔐 SHA256:** {alert['sha256']}")
        st.write(f"**📂 Path:** {alert['path']}")
        st.write(f"**📦 Size:** {alert['size']} bytes")