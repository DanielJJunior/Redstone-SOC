import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class AttackNavigatorExporter:
    """
    Exports Redstone SOC data as MITRE ATT&CK Navigator layers (Day 26).

    Two views:
      - coverage: which techniques the detection rules (config/iocs.json)
                  can catch, weighted by the highest severity of each rule.
      - alerts:   which techniques were actually triggered, weighted by
                  the number of alerts.

    Open the generated JSON at https://mitre-attack.github.io/attack-navigator/
    -> "Open Existing Layer" -> "Upload from local".
    """

    SEVERITY_WEIGHT = {
        "INFO": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    # Built-in heuristic in DetectionEngine (dangerous extension -> T1204)
    EXTENSION_RULE_TECHNIQUE = "T1204"

    # Redstone palette: light -> redstone red
    GRADIENT = ["#fff1e6", "#ff9f68", "#ff4c4c"]

    @staticmethod
    def _valid_technique(value):

        if not value or not isinstance(value, str):
            return None

        value = value.strip().upper()

        return value if value.startswith("T") else None

    @classmethod
    def _base_layer(cls, name, description, techniques, max_value):

        return {
            "name": name,
            "description": description,
            "domain": "enterprise-attack",
            "versions": {"layer": "4.5"},
            "sorting": 3,
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": cls.GRADIENT,
                "minValue": 0,
                "maxValue": max_value
            },
            "metadata": [
                {"name": "generated_by", "value": "Redstone SOC"},
                {"name": "generated_at", "value": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            ]
        }

    @classmethod
    def coverage_layer(cls, ioc_data):

        rules = defaultdict(list)
        best = defaultdict(int)

        indicators = [
            (item.get("name"), item)
            for item in ioc_data.get("filenames", [])
        ] + [
            (f"hash {item.get('sha256', '')[:12]}...", item)
            for item in ioc_data.get("hashes", [])
        ]

        for label, item in indicators:

            technique = cls._valid_technique(item.get("mitre"))

            if not technique:
                continue

            severity = item.get("severity", "MEDIUM")

            rules[technique].append(f"{label} [{severity}] - {item.get('family', '')}")
            best[technique] = max(best[technique], cls.SEVERITY_WEIGHT.get(severity, 2))

        if ioc_data.get("extensions"):

            rules[cls.EXTENSION_RULE_TECHNIQUE].append(
                "Dangerous extension rule [HIGH]: " + ", ".join(ioc_data["extensions"])
            )
            best[cls.EXTENSION_RULE_TECHNIQUE] = max(
                best[cls.EXTENSION_RULE_TECHNIQUE],
                cls.SEVERITY_WEIGHT["HIGH"]
            )

        techniques = [
            {
                "techniqueID": technique,
                "score": best[technique],
                "comment": f"{len(rules[technique])} detection rule(s): " + " | ".join(rules[technique]),
                "enabled": True
            }
            for technique in sorted(rules)
        ]

        return cls._base_layer(
            "Redstone SOC - Detection Coverage",
            f"Techniques covered by Redstone SOC detection rules ({len(techniques)} techniques). "
            "Score = highest severity of the rules (1 INFO - 4 CRITICAL).",
            techniques,
            max(cls.SEVERITY_WEIGHT.values())
        )

    @classmethod
    def alerts_layer(cls, alerts):

        counts = defaultdict(int)
        files = defaultdict(list)

        for alert in alerts:

            technique = cls._valid_technique(alert.get("mitre"))

            if not technique:
                continue

            counts[technique] += 1
            files[technique].append(f"{alert.get('file_name', 'unknown')} ({alert.get('severity', 'N/A')})")

        techniques = [
            {
                "techniqueID": technique,
                "score": counts[technique],
                "comment": f"{counts[technique]} alert(s): " + "; ".join(files[technique][:10]),
                "enabled": True
            }
            for technique in sorted(counts)
        ]

        return cls._base_layer(
            "Redstone SOC - Triggered Alerts",
            f"{sum(counts.values())} alerts across {len(techniques)} techniques. Score = number of alerts.",
            techniques,
            max(counts.values(), default=1)
        )

    @staticmethod
    def load_alerts(alert_folder="alerts"):

        alerts = []

        for file in sorted(Path(alert_folder).glob("alert_*.json")):

            try:
                with open(file, encoding="utf-8") as handle:
                    alerts.append(json.load(handle))

            except (json.JSONDecodeError, OSError):
                continue

        return alerts

    @staticmethod
    def to_json(layer):

        return json.dumps(layer, indent=2, ensure_ascii=False).encode("utf-8")
