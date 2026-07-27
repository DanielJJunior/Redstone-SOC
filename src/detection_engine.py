from pathlib import Path


class DetectionEngine:
    
    SUSPICIOUS_FILES = [
        "mimikatz.exe",
        "nc.exe",
        "nmap.exe",
        "psexec.exe",
        "procdump.exe"
    ]

    HIGH_RISK_EXTENSIONS = [
        ".exe",
        ".dll",
        ".ps1",
        ".bat",
        ".vbs"
    ]

    SAFE_EXTENSIONS = [
        ".txt",
        ".pdf",
        ".jpg",
        ".jpeg",
        ".png",
        ".docx"
    ]

    def analyze(self, file_info):

        filename = file_info["name"].lower()
        extension = file_info["extension"].lower()

        # IOC by filename
        if filename in self.SUSPICIOUS_FILES:

            return {
                "severity": "CRITICAL",
                "status": "IOC Detected",
                "reason": "Known malicious tool"
            }

        # IOC by extension
        if extension in self.HIGH_RISK_EXTENSIONS:

            return {
                "severity": "HIGH",
                "status": "Executable File",
                "reason": "Executable extension detected"
            }

        # Known safe
        if extension in self.SAFE_EXTENSIONS:

            return {
                "severity": "INFO",
                "status": "Safe File",
                "reason": "Known safe extension"
            }

        return {
            "severity": "MEDIUM",
            "status": "Unknown File",
            "reason": "Unknown extension"
        }