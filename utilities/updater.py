import os
import sys
import requests
import hashlib
import subprocess
import platform

class EncryptHomeUpdater:
    def __init__(self, current_version: str, update_json_url: str):
        self.current_version = current_version
        self.update_json_url = update_json_url

        self.base_dir = os.path.dirname(sys.argv[0])
        self.update_dir = os.path.join(self.base_dir, "update_temp")
        os.makedirs(self.update_dir, exist_ok=True)

    # -------------------------
    # Prüfen ob Update verfügbar + Infos zurückgeben
    # -------------------------
    def run(self) -> dict:
        """
        Prüft latest.json und gibt die Daten zurück.
        Status:
            NO_UPDATE - keine neue Version
            UPDATE_AVAILABLE - neue Version verfügbar
        """
        data = self._fetch_latest_json()
        latest_version = data["version"]

        if latest_version == self.current_version:
            return {"status": "NO_UPDATE", "data": data}

        # Update verfügbar, Setup noch nicht gestartet
        return {"status": "UPDATE_AVAILABLE", "data": data}

    # -------------------------
    # Installer starten
    # -------------------------
    def start_update(self):
        """
        Lädt die Setup-Datei herunter und startet sie.
        Beendet anschließend die aktuelle Anwendung.
        """
        data = self._fetch_latest_json()
        setup_url = data["url"]
        sha256 = data.get("sha256", "")
        setup_path = os.path.join(self.update_dir, "Update.exe")

        self._download_file(setup_url, setup_path)

        if sha256:
            if not self._verify_sha256(setup_path, sha256):
                raise RuntimeError("SHA256-Prüfung fehlgeschlagen")

        if platform.system() == "Windows":
            subprocess.Popen([setup_path], shell=True)
        else:
            subprocess.Popen([setup_path])
        sys.exit(0)

    # -------------------------
    # interne Helfer
    # -------------------------
    def _fetch_latest_json(self) -> dict:
        r = requests.get(self.update_json_url, timeout=5)
        r.raise_for_status()
        return r.json()

    def _download_file(self, url: str, dest: str):
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

    def _verify_sha256(self, file_path: str, expected_hash: str) -> bool:
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest().lower() == expected_hash.lower()
