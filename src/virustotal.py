import json
from pathlib import Path

import requests


class VirusTotalClient:
    """
    Optional integration with the VirusTotal public API (v3).

    Enriches HIGH/CRITICAL detections with a second opinion from
    70+ antivirus engines, based on the file's SHA256 hash.

    Disabled by default: if no API key is configured, every call
    becomes a safe no-op instead of raising an error or consuming quota.
    """

    API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"

    def __init__(self, config_path="config/settings.json"):
        self.api_key = self._load_api_key(config_path)

    def _load_api_key(self, config_path):

        path = Path(config_path)

        if not path.exists():
            return None

        try:
            with open(path, "r", encoding="utf-8") as file:
                settings = json.load(file)

            key = settings.get("virustotal_api_key", "").strip()

            return key if key else None

        except (json.JSONDecodeError, OSError):
            return None

    def is_enabled(self):
        return self.api_key is not None

    def lookup_hash(self, sha256):

        if not self.is_enabled():
            return None

        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(
                self.API_URL.format(sha256=sha256),
                headers=headers,
                timeout=10
            )

        except requests.RequestException:
            return {
                "checked": True,
                "found": False,
                "error": "VirusTotal request failed (network error)."
            }

        if response.status_code == 404:
            return {
                "checked": True,
                "found": False,
                "message": "This file hash has not been seen by VirusTotal before."
            }

        if response.status_code == 429:
            return {
                "checked": True,
                "found": False,
                "error": "VirusTotal rate limit reached. Try again in a minute."
            }

        if response.status_code != 200:
            return {
                "checked": True,
                "found": False,
                "error": f"VirusTotal returned status {response.status_code}."
            }

        try:
            data = response.json()
            attributes = data["data"]["attributes"]
            result_stats = attributes["last_analysis_stats"]

            return {
                "checked": True,
                "found": True,
                "malicious": result_stats.get("malicious", 0),
                "suspicious": result_stats.get("suspicious", 0),
                "harmless": result_stats.get("harmless", 0),
                "undetected": result_stats.get("undetected", 0),
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}"
            }

        except (KeyError, ValueError):
            return {
                "checked": True,
                "found": False,
                "error": "Unexpected response format from VirusTotal."
            }