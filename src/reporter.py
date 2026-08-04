from datetime import datetime

import pandas as pd
from fpdf import FPDF


class ReportGenerator:
    """
    Generates exportable reports (CSV and PDF) from a list of alerts.
    Used by the dashboard's export buttons (Day 20).
    """

    CSV_COLUMNS = [
        "timestamp",
        "file_name",
        "severity",
        "status",
        "threat_score",
        "reason",
        "mitre",
        "sha256"
    ]

    @staticmethod
    def generate_csv(alerts):

        df = pd.DataFrame(alerts)

        if df.empty:
            df = pd.DataFrame(columns=ReportGenerator.CSV_COLUMNS)

        columns = [c for c in ReportGenerator.CSV_COLUMNS if c in df.columns]

        return df[columns].to_csv(index=False).encode("utf-8")

    @staticmethod
    def generate_pdf(alerts, severity_summary):

        pdf = FPDF()
        pdf.add_page()

        # Header

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Redstone SOC - Threat Report", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 10)

        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        pdf.cell(0, 8, f"Generated at: {generated_at}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"Total alerts in this report: {len(alerts)}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        # Summary

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Summary by Severity", new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 10)

        for severity in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
            pdf.cell(0, 6, f"{severity}: {severity_summary.get(severity, 0)}", new_x="LMARGIN", new_y="NEXT")

        pdf.ln(6)

        # Table

        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Alerts", new_x="LMARGIN", new_y="NEXT")

        col_widths = (32, 45, 22, 30, 20, 41)
        headers = ("Timestamp", "File", "Severity", "Status", "Score", "Reason")

        pdf.set_font("Helvetica", "B", 9)

        for width, header in zip(col_widths, headers):
            pdf.cell(width, 7, header, border=1)

        pdf.ln()

        pdf.set_font("Helvetica", "", 8)

        for alert in alerts:

            row = (
                str(alert.get("timestamp", ""))[:19],
                str(alert.get("file_name", ""))[:28],
                str(alert.get("severity", "")),
                str(alert.get("status", ""))[:18],
                str(alert.get("threat_score", 0)),
                str(alert.get("reason", ""))[:26]
            )

            for width, value in zip(col_widths, row):
                pdf.cell(width, 6, value, border=1)

            pdf.ln()

        return bytes(pdf.output())