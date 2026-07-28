import json
from pathlib import Path


class ThreatIntelligence:

    def __init__(self):

        database = Path("config/iocs.json")

        with open(database, encoding="utf-8") as file:
            self.data = json.load(file)

    def filename_lookup(self, filename):

        filename = filename.lower()

        for item in self.data["filenames"]:

            if item["name"].lower() == filename:
                return item

        return None

    def extension_lookup(self, extension):

        extension = extension.lower()

        return extension in self.data["extensions"]

    def safe_extension_lookup(self, extension):

        extension = extension.lower()

        return extension in self.data["safe_extensions"]

    # NOVO MÉTODO
    def hash_lookup(self, sha256):

        sha256 = sha256.lower()

        for item in self.data["hashes"]:

            if item["sha256"].lower() == sha256:
                return item

        return None