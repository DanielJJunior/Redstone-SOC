import json
from pathlib import Path


class DashboardLoader:

    def __init__(self):

        self.alert_folder = Path("alerts")

    def load_alerts(self):

        alerts = []

        if not self.alert_folder.exists():
            return alerts

        for file in sorted(
            self.alert_folder.glob("*.json"),
            reverse=True
        ):

            with open(file, encoding="utf-8") as f:

                alerts.append(json.load(f))

        return alerts

    def statistics(self):

        alerts = self.load_alerts()

        stats = {

            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "INFO": 0

        }

        for alert in alerts:

            severity = alert["severity"]

            if severity in stats:
                stats[severity] += 1

        return stats