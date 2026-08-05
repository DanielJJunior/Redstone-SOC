import sys
from pathlib import Path

# Allow importing from src/ when running via `streamlit run dashboard/app.py`
sys.path.append(str(Path(__file__).resolve().parent.parent))

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

from dashboard_utils import DashboardLoader
from src.reporter import ReportGenerator
from src.threat_intelligence import ThreatIntelligence

# ==========================================
# Shared severity constants (Day 24)
# ==========================================

SEVERITY_ORDER = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]

SEVERITY_COLORS = {
    "INFO": "#3ba55d",
    "MEDIUM": "#f1c40f",
    "HIGH": "#e67e22",
    "CRITICAL": "#e74c3c"
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "INFO": "🟢"
}

REDSTONE_RED = "#FF4C4C"

loader = DashboardLoader()

alerts = loader.load_alerts()
stats = loader.statistics()

st.set_page_config(
    page_title="Redstone SOC",
    page_icon="⛏️",
    layout="wide"
)


# ==========================================
# Visual Theme (Day 26)
# ==========================================

def inject_custom_css():

    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Press+Start+2P&display=swap');

        .redstone-banner {{
            border-bottom: 3px solid {REDSTONE_RED};
            padding-bottom: 14px;
            margin-bottom: 10px;
        }}

        .redstone-banner h1 {{
            font-family: 'Press Start 2P', monospace;
            font-size: 26px;
            color: {REDSTONE_RED};
            margin-bottom: 6px;
        }}

        .redstone-banner p {{
            font-family: monospace;
            color: #AAAAAA;
            font-size: 14px;
            margin: 0;
        }}

        h2, h3 {{
            font-family: 'Press Start 2P', monospace !important;
            font-size: 16px !important;
            color: {REDSTONE_RED} !important;
        }}

        [data-testid="stMetric"] {{
            background-color: #2A2A2E;
            border: 1px solid #3A3A3E;
            border-radius: 10px;
            padding: 12px 8px;
        }}

        .stButton>button,
        [data-testid="stDownloadButton"] button {{
            border: 1px solid {REDSTONE_RED};
            border-radius: 6px;
        }}

        .stButton>button:hover,
        [data-testid="stDownloadButton"] button:hover {{
            border-color: {REDSTONE_RED};
            color: {REDSTONE_RED};
        }}
        </style>
        """,
        unsafe_allow_html=True
    )


def render_banner():

    st.markdown(
        """
        <div class="redstone-banner">
            <h1>⛏️ REDSTONE SOC</h1>
            <p>Minecraft-inspired Security Operations Center</p>
        </div>
        """,
        unsafe_allow_html=True
    )


inject_custom_css()
render_banner()

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
        for severity in SEVERITY_ORDER
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
    # Statistics (Day 24)
    # ==========================================

    st.subheader("📊 Statistics")

    stats_df = table.copy()
    stats_df["timestamp_dt"] = pd.to_datetime(stats_df["timestamp"])

    stat_col1, stat_col2 = st.columns(2)

    with stat_col1:

        st.markdown("**Severity Distribution**")

        severity_counts = (
            stats_df["severity"]
            .value_counts()
            .reindex(SEVERITY_ORDER)
            .fillna(0)
        )

        severity_counts = severity_counts[severity_counts > 0]

        pie = go.Figure(go.Pie(
            labels=severity_counts.index,
            values=severity_counts.values,
            marker=dict(colors=[SEVERITY_COLORS[s] for s in severity_counts.index]),
            hole=0.4
        ))

        pie.update_layout(
            height=300,
            margin=dict(t=10, b=10, l=10, r=10)
        )

        st.plotly_chart(pie, use_container_width=True)

    with stat_col2:

        st.markdown("**Alerts by Hour of Day**")

        hourly_counts = (
            stats_df["timestamp_dt"].dt.hour
            .value_counts()
            .reindex(range(24), fill_value=0)
            .sort_index()
        )

        hour_bar = go.Figure(go.Bar(
            x=[f"{h:02d}h" for h in hourly_counts.index],
            y=hourly_counts.values,
            marker=dict(color=REDSTONE_RED)
        ))

        hour_bar.update_layout(
            height=300,
            margin=dict(t=10, b=10, l=10, r=10),
            xaxis=dict(tickangle=-45)
        )

        st.plotly_chart(hour_bar, use_container_width=True)

    st.markdown("**Top 5 Detected Extensions**")

    top_extensions = (
        stats_df["extension"]
        .replace("", "(no extension)")
        .value_counts()
        .head(5)
        .sort_values()
    )

    ext_bar = go.Figure(go.Bar(
        x=top_extensions.values,
        y=top_extensions.index,
        orientation="h",
        marker=dict(color="#8B0000")
    ))

    ext_bar.update_layout(
        height=250,
        margin=dict(t=10, b=10, l=10, r=10),
        xaxis=dict(title="Count")
    )

    st.plotly_chart(ext_bar, use_container_width=True)

    st.divider()

    # ==========================================
    # Timeline (Day 23)
    # ==========================================

    st.subheader("🕒 Alert Timeline")

    timeline_df = table.copy()
    timeline_df["timestamp_dt"] = pd.to_datetime(timeline_df["timestamp"])

    if "threat_score" not in timeline_df.columns:
        timeline_df["threat_score"] = 0

    timeline_df["threat_score"] = timeline_df["threat_score"].fillna(0)

    timeline_fig = go.Figure()

    for severity in SEVERITY_ORDER:

        subset = timeline_df[timeline_df["severity"] == severity]

        if subset.empty:
            continue

        marker_sizes = 10 + (subset["threat_score"] / 100) * 25

        timeline_fig.add_trace(go.Scatter(
            x=subset["timestamp_dt"],
            y=subset["severity"],
            mode="markers",
            name=severity,
            marker=dict(
                size=marker_sizes,
                color=SEVERITY_COLORS[severity],
                line=dict(width=1, color="white")
            ),
            customdata=subset[["file_name", "status", "reason", "threat_score"]],
            hovertemplate=(
                "<b>%{customdata[0]}</b><br>"
                "Status: %{customdata[1]}<br>"
                "Reason: %{customdata[2]}<br>"
                "Score: %{customdata[3]}/100<br>"
                "%{x}<extra></extra>"
            )
        ))

    timeline_fig.update_yaxes(
        categoryorder="array",
        categoryarray=SEVERITY_ORDER,
        title="Severity"
    )

    timeline_fig.update_xaxes(title="Time")

    timeline_fig.update_layout(
        height=350,
        margin=dict(t=20, b=20, l=20, r=20),
        legend_title_text="Severity"
    )

    st.plotly_chart(timeline_fig, use_container_width=True)

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
                {"range": [0, 30], "color": SEVERITY_COLORS["INFO"]},
                {"range": [30, 60], "color": SEVERITY_COLORS["MEDIUM"]},
                {"range": [60, 80], "color": SEVERITY_COLORS["HIGH"]},
                {"range": [80, 100], "color": SEVERITY_COLORS["CRITICAL"]}
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

    # ==========================================
    # VirusTotal Lookup (Day 25)
    # ==========================================

    vt_result = alert.get("virustotal")

    if vt_result:

        st.divider()
        st.subheader("🧪 VirusTotal Lookup")

        if vt_result.get("found"):

            total = (
                vt_result["malicious"]
                + vt_result["suspicious"]
                + vt_result["harmless"]
                + vt_result["undetected"]
            )

            vt_c1, vt_c2, vt_c3, vt_c4 = st.columns(4)

            vt_c1.metric("🔴 Malicious", vt_result["malicious"])
            vt_c2.metric("🟠 Suspicious", vt_result["suspicious"])
            vt_c3.metric("🟢 Harmless", vt_result["harmless"])
            vt_c4.metric("⚪ Undetected", vt_result["undetected"])

            if vt_result["malicious"] > 0:
                st.error(
                    f"⚠️ Flagged as malicious by {vt_result['malicious']} out of {total} engines."
                )
            else:
                st.success("No engines flagged this file as malicious.")

            st.markdown(f"[🔗 View full report on VirusTotal]({vt_result['permalink']})")

        elif vt_result.get("error"):
            st.warning(f"⚠️ {vt_result['error']}")

        else:
            st.info(vt_result.get("message", "This file hash was not found in VirusTotal's database."))

st.divider()

# ==========================================
# IOC Database Panel (Day 22)
# ==========================================

st.subheader("🗃️ IOC Database — Threat Intelligence")
st.caption(
    "All indicators currently loaded in Redstone SOC's threat intelligence base "
    "— not just the ones that triggered an alert."
)

ti = ThreatIntelligence()
ioc_data = ti.data

ioc_c1, ioc_c2, ioc_c3, ioc_c4 = st.columns(4)

ioc_c1.metric("📄 Filename IOCs", len(ioc_data.get("filenames", [])))
ioc_c2.metric("🔐 Hash IOCs", len(ioc_data.get("hashes", [])))
ioc_c3.metric("⚠️ Dangerous Extensions", len(ioc_data.get("extensions", [])))
ioc_c4.metric("🟢 Safe Extensions", len(ioc_data.get("safe_extensions", [])))

ioc_search = st.text_input("🔍 Search IOC (filename or family)")

# --- Filename indicators ---

filename_df = pd.DataFrame(ioc_data.get("filenames", []))

if not filename_df.empty and ioc_search:

    mask = (
        filename_df["name"].str.contains(ioc_search, case=False, na=False)
        | filename_df["family"].str.contains(ioc_search, case=False, na=False)
    )

    filename_df = filename_df[mask]

if not filename_df.empty:

    filename_df = filename_df.copy()
    filename_df["severity"] = filename_df["severity"].apply(
        lambda s: f"{SEVERITY_ICONS.get(s, '⚪')} {s}"
    )

st.markdown("**📄 Filename Indicators**")

if filename_df.empty:
    st.info("No filename IOCs match your search.")
else:
    st.dataframe(
        filename_df[["name", "family", "severity", "mitre", "recommendation"]],
        use_container_width=True,
        hide_index=True
    )

# --- Hash indicators ---

hash_df = pd.DataFrame(ioc_data.get("hashes", []))

if not hash_df.empty and ioc_search:

    mask = hash_df["family"].str.contains(ioc_search, case=False, na=False)

    hash_df = hash_df[mask]

if not hash_df.empty:

    hash_df = hash_df.copy()
    hash_df["severity"] = hash_df["severity"].apply(
        lambda s: f"{SEVERITY_ICONS.get(s, '⚪')} {s}"
    )

st.markdown("**🔐 Hash Indicators**")

if hash_df.empty:
    st.info("No hash IOCs match your search.")
else:
    st.dataframe(
        hash_df[["sha256", "family", "severity", "mitre", "recommendation"]],
        use_container_width=True,
        hide_index=True
    )

# --- Extensions ---

ext_c1, ext_c2 = st.columns(2)

with ext_c1:
    st.markdown("**⚠️ Dangerous Extensions**")
    st.write(", ".join(ioc_data.get("extensions", [])))

with ext_c2:
    st.markdown("**🟢 Safe Extensions**")
    st.write(", ".join(ioc_data.get("safe_extensions", [])))