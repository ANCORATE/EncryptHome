# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------
# Versionsvergleich (zentral, robust)
# ---------------------------------------------------------------
def parse_version(version) -> tuple:
    """
    Convert a version into a comparable tuple.

    Keeps the first three components in these positions:
    [0] major, [1] minor, [2] patch.

    Additional components are compared before the
    prerelease identifier.
    """
    raw = str(version).strip()

    # Separate and validate build metadata.
    if "+" in raw:
        raw, build = raw.split("+", 1)

        if not re.fullmatch(r"[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*", build):
            raise ValueError("Invalid build metadata.")

    pattern = (
        r"^(?P<core>\d+(?:\.\d+)*)"
        r"(?:-?(?P<prerelease>[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
    )

    match = re.fullmatch(pattern, raw)

    if not match:
        raise ValueError(f"Invalid version: {version}")

    # Numeric components.
    core_parts = [int(part) for part in match.group("core").split(".")]

    while len(core_parts) < 3:
        core_parts.append(0)

    major, minor, patch = core_parts[:3]
    extra_parts = core_parts[3:]

    # Remove trailing zero-valued additional components.
    while extra_parts and extra_parts[-1] == 0:
        extra_parts.pop()

    # Prerelease identifiers.
    prerelease = match.group("prerelease")

    if prerelease:
        identifiers = []

        for part in prerelease.split("."):
            if part.isdigit():
                if len(part) > 1 and part.startswith("0"):
                    raise ValueError("Invalid numeric identifier.")

                identifiers.append((0, int(part)))
            else:
                identifiers.append((1, part))

        prerelease_key = tuple(identifiers)
        release_flag = 0
    else:
        prerelease_key = ()
        release_flag = 1

    return (
        major,
        minor,
        patch,
        tuple(extra_parts),
        release_flag,
        prerelease_key,
    )

def is_newer_version(latest, current) -> bool:
    """True, wenn latest eine neuere Version ist als current."""
    try:
        return parse_version(latest) > parse_version(current)
    except Exception:
        return False


# ---------------------------------------------------------------
# Manifest-Validierung
# ---------------------------------------------------------------
_REQUIRED_FIELDS = ("version", "url")


def _is_https_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.scheme == "https" and bool(parsed.netloc)
    except Exception:
        return False


def _is_valid_sha256(value) -> bool:
    if not isinstance(value, str):
        return False
    return re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def validate_latest_json(data) -> dict:
    """
    Validiert das Update-Manifest strikt und liefert eine normierte Kopie.

    Wird ein Pflichtfeld verletzt, wird ValueError mit einer verständlichen
    Meldung geworfen – niemals ungeprüft übernommen.
    """
    if not isinstance(data, dict):
        raise ValueError("Update-Manifest ist kein gültiges JSON-Objekt.")

    missing = [k for k in _REQUIRED_FIELDS if k not in data]
    if missing:
        raise ValueError(
            "Update-Manifest unvollständig; fehlende Felder: " + ", ".join(missing)
        )

    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("Update-Manifest enthält keine gültige 'version'.")

    parse_version(version)

    url = data.get("url")
    if not isinstance(url, str) or not _is_https_url(url):
        raise ValueError("Update-URL ist ungültig oder nicht https.")

    sha256 = data.get("sha256")
    if sha256 is not None and not _is_valid_sha256(sha256):
        raise ValueError("Update-Manifest enthält einen ungültigen 'sha256'.")

    size_mb = data.get("size_mb")
    if size_mb is not None:
        if not isinstance(size_mb, (int, float)) or size_mb < 0:
            raise ValueError("Update-Manifest enthält eine ungültige 'size_mb'.")

    return data


def manifest_fresh(data: dict, max_age_seconds: int = 7 * 24 * 3600) -> tuple[bool, str]:
    """Prüft, ob das Manifest frisch ist (via published_at/date/release_date)."""
    for key in ("published_at", "date", "release_date"):
        raw = data.get(key)
        if not raw:
            continue
        try:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except Exception:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        if age > max_age_seconds:
            return False, key
    return True, ""


def normalize_version_label(version) -> str:
    """Stellt eine lesbare, konsistente Versionsangabe für Anzeigen sicher."""
    if not version:
        return "unbekannt"
    return str(version).strip()


# ---------------------------------------------------------------
# Download-Helfer
# ---------------------------------------------------------------
_CHUNK = 64 * 1024


class EncryptHomeUpdater:
    def __init__(self, current_version: str, update_json_url: str, channel: str = "stable"):
        self.current_version = current_version
        self.update_json_url = update_json_url
        self.channel = (channel or "stable").lower()

        self.base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.update_dir = os.path.join(self.base_dir, "update_temp")
        os.makedirs(self.update_dir, exist_ok=True)

    # -------------------------
    # Prüfen ob Update verfügbar + Infos zurückgeben
    # -------------------------
    def run(self) -> dict:
        """
        Prüft latest.json, validiert das Manifest und gibt die Daten zurück.

        Status:
            NO_UPDATE          - keine neue Version
            UPDATE_AVAILABLE   - neue Version verfügbar (Manifest validiert)

        Wirft bei Netzwerk- oder Validierungsfehlern Exceptions.
        """
        data = self.fetch_manifest()
        latest_version = normalize_version_label(data["version"])

        # Allow switching from a pre-release (beta) to a stable release
        # of the same or a newer core version, even if the version number
        # itself is not strictly greater.
        current_is_prerelease = "-" in str(self.current_version)
        latest_is_stable = "-" not in str(latest_version)
        if (
            self.channel == "stable"
            and current_is_prerelease
            and latest_is_stable
        ):
            try:
                cur_core = tuple(int(p) for p in str(self.current_version).split("-")[0].split(".")[:3])
                lat_core = tuple(int(p) for p in str(latest_version).split("-")[0].split(".")[:3])
                if lat_core >= cur_core:
                    return {"status": "UPDATE_AVAILABLE", "data": data}
            except Exception:
                pass

        if not is_newer_version(latest_version, self.current_version):
            return {"status": "NO_UPDATE", "data": data}

        return {"status": "UPDATE_AVAILABLE", "data": data}

    # -------------------------
    # Standalone-EXE selbst aktualisieren (PyInstaller-onefile)
    # -------------------------
    def _start_standalone_update(self, expected_sha256: str | None = None):
        data = self.fetch_manifest()
        setup_url = data["url"]
        sha256 = expected_sha256 or data.get("sha256", "")

        url_name = os.path.basename(urlparse(setup_url).path).strip()
        if not url_name:
            url_name = "EncryptHome" + (".exe" if platform.system() == "Windows" else "")
        setup_path = os.path.join(self.update_dir, url_name)

        self._download_file(setup_url, setup_path)

        if sha256:
            if not self._verify_sha256(setup_path, sha256):
                self._cleanup_file(setup_path)
                self._download_file(setup_url, setup_path, resume=False)
                if not self._verify_sha256(setup_path, sha256):
                    raise RuntimeError(
                        "SHA256-Prüfung fehlgeschlagen; die Datei wurde mehrfach "
                        "fehlerhaft übertragen."
                    )

        if not os.path.getsize(setup_path) > 0:
            raise RuntimeError("Der heruntergeladene Update ist leer.")

        current = sys.executable
        pid = os.getpid()

        if platform.system() == "Windows":
            script = os.path.join(self.update_dir, "update_replace.bat")
            with open(script, "w", encoding="utf-8") as f:
                f.write("@echo off\n")
                f.write(":wait\n")
                f.write(f'tasklist /FI "PID eq {pid}" 2>NUL | find "{pid}" >NUL\n')
                f.write("if %ERRORLEVEL%==0 (\n")
                f.write("  timeout /t 1 /nobreak >NUL\n")
                f.write("  goto wait\n")
                f.write(")\n")
                f.write(f'move /Y "{setup_path}" "{current}"\n')
                f.write(f'start "" "{current}"\n')
                f.write('del "%~f0"\n')
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            subprocess.Popen(
                ["cmd", "/c", script],
                creationflags=CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS,
                close_fds=True,
            )
        else:
            script = os.path.join(self.update_dir, "update_replace.sh")
            with open(script, "w", encoding="utf-8") as f:
                f.write("#!/bin/sh\n")
                f.write(f"while kill -0 {pid} 2>/dev/null; do sleep 1; done\n")
                f.write(f'cp "{setup_path}" "{current}"\n')
                f.write(f'chmod +x "{current}"\n')
                f.write(f'"{current}" &\n')
                f.write('rm -f "$0"\n')
            os.chmod(script, 0o755)
            subprocess.Popen(["/bin/sh", script], start_new_session=True, close_fds=True)

        sys.exit(0)

    # -------------------------
    # Installer starten
    # -------------------------
    def start_update(self, expected_sha256: str | None = None):
        # Standalone-Builds aktualisieren sich selbst
        if getattr(sys, "frozen", False):
            return self._start_standalone_update(expected_sha256)


        """
        Lädt die Setup-Datei herunter, verifiziert ihre Integrität und startet sie.
        Beendet anschließend die aktuelle Anwendung.

        expected_sha256: optional exakter SHA256, gegen den die Datei geprüft wird.
        """
        data = self.fetch_manifest()
        setup_url = data["url"]
        sha256 = expected_sha256 or data.get("sha256", "")

        # Installer-Dateiname plattformunabhängig aus der Manifest-URL ableiten
        url_name = os.path.basename(urlparse(setup_url).path).strip()
        if not url_name:
            url_name = "Update.exe" if platform.system() == "Windows" else "Update.AppImage"
        setup_path = os.path.join(self.update_dir, url_name)

        self._download_file(setup_url, setup_path)

        if sha256:
            if not self._verify_sha256(setup_path, sha256):
                # Einmal neu herunterladen (korrupte/unterbrochene Übertragung)
                self._cleanup_file(setup_path)
                self._download_file(setup_url, setup_path, resume=False)
                if not self._verify_sha256(setup_path, sha256):
                    raise RuntimeError(
                        "SHA256-Prüfung fehlgeschlagen; die Datei wurde mehrfach "
                        "fehlerhaft übertragen. Download kann sie nicht verifizieren."
                    )

        if not os.path.getsize(setup_path) > 0:
            raise RuntimeError("Der heruntergeladene Installer ist leer.")

        if platform.system() == "Windows":
            try:
                import ctypes

                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", setup_path, None, None, 1
                )
            except Exception:
                subprocess.Popen([setup_path], shell=False)
        elif platform.system() == "Darwin":
            # macOS: ausführbar machen; je nach Format korrekt öffnen/installieren
            os.chmod(setup_path, os.stat(setup_path).st_mode | 0o111)
            if url_name.lower().endswith((".dmg", ".pkg")):
                subprocess.Popen(["open", setup_path])
            else:
                subprocess.Popen([setup_path])
        else:
            # Linux: ausführbar machen (AppImage/Deb-Skripte) und starten
            os.chmod(setup_path, os.stat(setup_path).st_mode | 0o111)
            subprocess.Popen([setup_path])
        sys.exit(0)

    # -------------------------
    # Manifest abrufen + validieren
    # -------------------------
    @staticmethod
    def _github_release_asset(data: dict) -> dict | None:
        assets = data.get("assets") or []
        system = platform.system().lower()
        keywords = []
        if system == "windows":
            keywords = ["windows", ".exe"]
        elif system == "darwin":
            keywords = ["macos", "mac", "darwin"]
        else:
            keywords = ["linux"]

        for asset in assets:
            name = str(asset.get("name", "")).lower()
            if any(keyword in name for keyword in keywords):
                return asset
        return assets[0] if assets else None

    @staticmethod
    def _github_release_to_manifest(data: dict) -> dict:
        tag = str(data.get("tag_name", "")).strip().lstrip("v")
        asset = EncryptHomeUpdater._github_release_asset(data)
        if not asset:
            raise ValueError("GitHub-Release enthält keine passende Datei.")
        url = asset.get("browser_download_url")
        if not url:
            raise ValueError("GitHub-Release-Asset hat keine Download-URL.")
        return {
            "version": tag,
            "url": url,
            "sha256": None,
            "size_mb": None,
            "published_at": data.get("published_at"),
            "changelog": data.get("body") or data.get("name") or "",
        }

    def _release_list_url(self) -> str:
        url = self.update_json_url
        if self.channel == "beta":
            # /releases/latest -> /releases (includes prereleases)
            if url.endswith("/releases/latest"):
                return url[: -len("/latest")]
            if url.endswith("/releases"):
                return url
            return url
        return url

    def fetch_manifest(self, timeout: int = 8) -> dict:
        url = self._release_list_url() if self.channel == "beta" else self.update_json_url
        try:
            response = requests.get(url, timeout=timeout)
        except requests.RequestException as e:
            raise ConnectionError(f"Keine Antwort vom Update-Server: {e}") from e
        if response.status_code != 200:
            raise ConnectionError(
                f"Update-Server antwortete mit HTTP {response.status_code}."
            )
        try:
            data = response.json()
        except Exception as e:
            raise ValueError(f"Update-Manifest ist kein gültiges JSON: {e}") from e

        # Beta channel: /releases returns a list; take the first (newest)
        if isinstance(data, list):
            if not data:
                raise ValueError("Keine Releases gefunden.")
            data = data[0]

        if isinstance(data, dict) and "tag_name" in data and "assets" in data:
            data = self._github_release_to_manifest(data)

        return validate_latest_json(data)

    # -------------------------
    # interne Helfer
    # -------------------------
    def _download_file(self, url: str, dest: str, resume: bool = True):
        # Nur HTTPS-Downloads sind erlaubt (rohe HTTP-Umleitung verboten)
        if not _is_https_url(url):
            raise ValueError("Nur sichere (https) Downloads sind erlaubt.")

        partial = dest + ".part"
        headers = {}
        if resume and os.path.exists(partial) and os.path.getsize(partial) > 0:
            headers["Range"] = f"bytes={os.path.getsize(partial)}-"

        try:
            with requests.get(url, stream=True, headers=headers, timeout=30) as r:
                r.raise_for_status()
                if headers and r.status_code == 206:
                    mode = "ab"
                else:
                    mode = "wb"
                    if os.path.exists(partial):
                        os.remove(partial)
                with open(partial, mode) as f:
                    for chunk in r.iter_content(chunk_size=_CHUNK):
                        if not chunk:
                            continue
                        f.write(chunk)

            # Atomar an den Zielpfad verschieben (kein halber Zustand sichtbar)
            os.replace(os.path.abspath(partial), os.path.abspath(dest))
        except Exception:
            # Teil-Download bleibt für einen erneuten Versuch erhalten
            raise
        finally:
            # Erfolgreich heruntergeladen; übrig gebliebene Teil-Datei aufräumen
            if os.path.exists(dest):
                try:
                    os.remove(partial)
                except Exception:
                    pass

    @staticmethod
    def _cleanup_file(path: str):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    @staticmethod
    def _verify_sha256(file_path: str, expected_hash: str) -> bool:
        if not _is_valid_sha256(expected_hash):
            return False
        h = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(_CHUNK), b""):
                    h.update(chunk)
        except Exception:
            return False
        return h.hexdigest().lower() == expected_hash.lower()

    @staticmethod
    def _parse_version(version: str) -> tuple:
        # Kompatibilitäts-Wrapper (frühere API)
        return parse_version(version)


# ---------------------------------------------------------------
# Cache / Cooldown für wiederholte Checks
# ---------------------------------------------------------------
class UpdateCheckCache:
    """
    Vermeidet, dass die GUI den Update-Server bei jedem Öffnen/Start nervt.

    Speichert das letzte Check-Ergebnis samt Zeitstempel in dem
    Update-Verzeichnis und erlaubt eine schnelle Antwort innerhalb eines
    konfigurierbaren Cooldowns.
    """

    def __init__(self, update_dir: str, cooldown_seconds: int = 3600):
        self.path = os.path.join(update_dir, "check_cache.json")
        self.cooldown_seconds = cooldown_seconds

    def _now(self) -> float:
        return time.time()

    def load(self) -> dict | None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "checked_at" in data and "status" in data:
                return data
        except Exception:
            return None
        return None

    def is_fresh(self) -> bool:
        cached = self.load()
        if not cached:
            return False
        return (self._now() - cached.get("checked_at", 0)) < self.cooldown_seconds

    def store(self, status: str, data: dict | None):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(
                    {"checked_at": self._now(), "status": status, "data": data or {}},
                    f,
                    indent=2,
                )
        except Exception:
            pass

    def clear(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except Exception:
            pass


def is_network_reachable(host: str = "8.8.8.8", port: int = 53, timeout: float = 2.0) -> bool:
    """Schneller Konnektivitäts-Check, bevor ein Update-Request gestartet wird."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
