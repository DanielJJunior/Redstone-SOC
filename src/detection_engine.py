from src.threat_intelligence import ThreatIntelligence


class DetectionEngine:

    # Base score por severidade (escala 0-100)
    SEVERITY_BASE_SCORE = {
        "INFO": 5,
        "MEDIUM": 40,
        "HIGH": 70,
        "CRITICAL": 95
    }

    # Modificador de confiança pelo método de detecção
    CONFIDENCE_MODIFIER = {
        "Hash Match": 10,      # Correspondência criptográfica exata
        "IOC Detected": 5,     # Nome de arquivo malicioso conhecido
        "Safe File": -5        # Reduz ruído de arquivos conhecidos como seguros
    }

    def __init__(self):
        self.ti = ThreatIntelligence()

    def analyze(self, file_info, sha256):

        filename = file_info["name"]
        extension = file_info["extension"]

        # 1 - Verifica HASH

        hash_ioc = self.ti.hash_lookup(sha256)

        if hash_ioc:

            severity = hash_ioc["severity"]
            status = "Hash Match"

            return {
                "severity": severity,
                "status": status,
                "reason": hash_ioc["family"],
                "mitre": hash_ioc.get("mitre", "N/A"),
                "recommendation": hash_ioc.get(
                    "recommendation",
                    "No recommendation available."
                ),
                "threat_score": self.calculate_threat_score(severity, status)
            }

        # 2 - Verifica NOME DO ARQUIVO

        ioc = self.ti.filename_lookup(filename)

        if ioc:

            severity = ioc["severity"]
            status = "IOC Detected"

            return {
                "severity": severity,
                "status": status,
                "reason": ioc["family"],
                "mitre": ioc.get("mitre", "N/A"),
                "recommendation": ioc.get(
                    "recommendation",
                    "No recommendation available."
                ),
                "threat_score": self.calculate_threat_score(severity, status)
            }

        # 3 - Verifica EXTENSÃO PERIGOSA

        if self.ti.extension_lookup(extension):

            severity = "HIGH"
            status = "Executable File"

            return {
                "severity": severity,
                "status": status,
                "reason": "Potentially dangerous extension",
                "mitre": "T1204",
                "recommendation": "Review the file's origin before execution. "
                                   "Confirm it was expected by the user.",
                "threat_score": self.calculate_threat_score(severity, status)
            }

        # 4 - Verifica EXTENSÃO SEGURA

        if self.ti.safe_extension_lookup(extension):

            severity = "INFO"
            status = "Safe File"

            return {
                "severity": severity,
                "status": status,
                "reason": "Known safe extension",
                "mitre": "N/A",
                "recommendation": "No action required.",
                "threat_score": self.calculate_threat_score(severity, status)
            }

        # 5 - DESCONHECIDO

        severity = "MEDIUM"
        status = "Unknown File"

        return {
            "severity": severity,
            "status": status,
            "reason": "Unknown extension",
            "mitre": "N/A",
            "recommendation": "Manually review the file before taking further action.",
            "threat_score": self.calculate_threat_score(severity, status)
        }

    @classmethod
    def calculate_threat_score(cls, severity, status):
        """
        Calcula o Threat Score (0-100) — o 'Redstone Power Level' da detecção.

        O valor base vem da severidade. Um modificador de confiança é
        aplicado dependendo de COMO o arquivo foi sinalizado: um match
        exato de hash é mais confiável que uma checagem heurística de
        extensão, então pesa mais no score final.
        """

        score = cls.SEVERITY_BASE_SCORE.get(severity, 50)
        score += cls.CONFIDENCE_MODIFIER.get(status, 0)

        return max(0, min(100, score))

    @staticmethod
    def severity_icon(severity):

        icons = {
            "INFO": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }

        return icons.get(severity, "⚪")