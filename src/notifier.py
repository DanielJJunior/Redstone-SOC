import json
from pathlib import Path

import requests


class DiscordNotifier:
    """
    Creeper Alert - sends a real-time notification to a Discord channel
    via Webhook whenever a high-confidence, high-severity detection occurs.

    Disabled by default: if no webhook is configured, every call becomes
    a safe no-op instead of raising an error.
    """

    SEVERITY_COLOR = {
        "CRITICAL": 0xE74C3C,
        "HIGH": 0xE67E22,
        "MEDIUM": 0xF1C40F,
        "INFO": 0x3BA55D
    }

    def __init__(self, config_path="config/settings.json"):
        self.webhook_url = self._load_webhook_url(config_path)

    def _load_webhook_url(self, config_path):

        path = Path(config_path)

        if not path.exists():
            return None

        try:
            with open(path, "r", encoding="utf-8") as file:
                settings = json.load(file)

            url = settings.get("discord_webhook_url", "").strip()

            return url if url else None

        except (json.JSONDecodeError, OSError):
            return None

    def is_enabled(self):
        return self.webhook_url is not None

    def send_alert(self, alert):

        if not self.is_enabled():
            return False

        severity = alert.get("severity", "MEDIUM")
        color = self.SEVERITY_COLOR.get(severity, 0x95A5A6)

        payload = {
            "username": "Redstone SOC",
            "embeds": [
                {
                    "title": "💥 Creeper Alert! Suspicious file detected",
                    "color": color,
                    "fields": [
                        {"name": "📄 File", "value": alert.get("file_name", "N/A"), "inline": True},
                        {"name": "⚠️ Severity", "value": severity, "inline": True},
                        {"name": "📊 Threat Score", "value": f"{alert.get('threat_score', 0)}/100", "inline": True},
                        {"name": "📌 Status", "value": alert.get("status", "N/A"), "inline": True},
                        {"name": "💬 Reason", "value": alert.get("reason", "N/A"), "inline": False},
                        {"name": "🎯 MITRE", "value": alert.get("mitre", "N/A"), "inline": True},
                        {"name": "🕒 Timestamp", "value": alert.get("timestamp", "N/A"), "inline": True}
                    ],
                    "footer": {"text": "⛏️ Redstone SOC"}
                }
            ]
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            return response.status_code in (200, 204)

        except requests.RequestException:
            return False