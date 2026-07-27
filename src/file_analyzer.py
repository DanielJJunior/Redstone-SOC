from pathlib import Path
from datetime import datetime


class FileAnalyzer:

    def analyze(self, file_path):

        file = Path(file_path)

        info = {
            "name": file.name,
            "extension": file.suffix,
            "size": file.stat().st_size,
            "created": datetime.fromtimestamp(file.stat().st_ctime),
            "path": str(file.resolve())
        }

        return info