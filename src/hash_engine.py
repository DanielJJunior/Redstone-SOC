import hashlib
import time


class HashEngine:

    @staticmethod
    def calculate_sha256(file_path):

        for _ in range(5):

            try:

                sha256 = hashlib.sha256()

                with open(file_path, "rb") as file:

                    while chunk := file.read(4096):
                        sha256.update(chunk)

                return sha256.hexdigest()

            except (PermissionError, FileNotFoundError, OSError):

                time.sleep(0.2)

        return "HASH_ERROR"