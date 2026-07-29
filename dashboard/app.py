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

col1, col2, col3, col4 = st.columns(4)

col1.metric("🔴 Critical", stats["CRITICAL"])
col2.metric("🟠 High", stats["HIGH"])
col3.metric("🟡 Medium", stats["MEDIUM"])
col4.metric("🟢 Safe", stats["INFO"])

st.divider()

# ==========================================
# Charts
# ==========================================

st.subheader("📊 Alert Statistics")

chart_data = pd.DataFrame({
    "Severity": list(stats.keys()),
    "Alerts": list(stats.values())
})

st.bar_chart(
    chart_data.set_index("Severity")
)

st.divider()

# ==========================================
# Table
# ==========================================

st.subheader("📄 Recent Alerts")

if len(alerts) == 0:

    st.info("No alerts generated yet.")

else:

    search = st.text_input(
        "🔍 Search filename"
    )

    table = pd.DataFrame(alerts)

    if search:

        table = table[
            table["file_name"].str.contains(
                search,
                case=False
            )
        ]

    st.dataframe(
        table,
        use_container_width=True,
        hide_index=True
    )