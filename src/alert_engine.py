import json
from pathlib import Path
from datetime import datetime


class AlertEngine:

    def __init__(self):

        self.alert_folder = Path("alerts")
        self.alert_folder.mkdir(exist_ok=True)

    def generate_alert(self, info, detection, sha256):

        timestamp = datetime.now()

        alert = {

            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),

            "file_name": info["name"],

            "extension": info["extension"],

            "size": info["size"],

            "sha256": sha256,

            "severity": detection["severity"],

            "status": detection["status"],

            "reason": detection["reason"],

            "threat_score": detection.get("threat_score", 0),

            "path": info["path"],

            "mitre": detection.get("mitre", "N/A"),

            "recommendation": detection.get(
                "recommendation",
                "No recommendation available."
            )
        }

        filename = f"alert_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"

        output = self.alert_folder / filename

        with open(output, "w", encoding="utf-8") as file:
            json.dump(alert, file, indent=4)

        history = self.alert_folder / "history.log"

        with open(history, "a", encoding="utf-8") as log:
            log.write(
                f"[{alert['timestamp']}] "
                f"{alert['severity']} "
                f"{alert['file_name']}\n"
            )

        return output, alert