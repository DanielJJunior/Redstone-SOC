from src.threat_intelligence import ThreatIntelligence

class DetectionEngine:

    def __init__(self):
        self.ti = ThreatIntelligence()

    def analyze(self, file_info, sha256):

        filename = file_info["name"]
        extension = file_info["extension"]

        # 1 - Verifica HASH 

        hash_ioc = self.ti.hash_lookup(sha256)

        if hash_ioc:

            return {
                "severity": hash_ioc["severity"],
                "status": "Hash Match",
                "reason": hash_ioc["family"]
            }

        # 2 - Verifica NOME DO ARQUIVO

        ioc = self.ti.filename_lookup(filename)

        if ioc:

            return {
                "severity": ioc["severity"],
                "status": "IOC Detected",
                "reason": ioc["family"]
            }

        # 3 - Verifica EXTENSÃO

        if self.ti.extension_lookup(extension):

            return {
                "severity": "HIGH",
                "status": "Executable File",
                "reason": "Potentially dangerous extension"
            }

        # 4 - Verifica EXTENSÃO SEGURA

        if self.ti.safe_extension_lookup(extension):

            return {
                "severity": "INFO",
                "status": "Safe File",
                "reason": "Known safe extension"
            }

        # 5 - DESCONHECIDO

        return {
            "severity": "MEDIUM",
            "status": "Unknown File",
            "reason": "Unknown extension"
        }
    @staticmethod
    def severity_icon(severity):

        icons = {
            "INFO": "🟢",
            "MEDIUM": "🟡",
            "HIGH": "🟠",
            "CRITICAL": "🔴"
        }

        return icons.get(severity, "⚪")