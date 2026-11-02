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
import tempfile
import shutil
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# ---------------------------------------------------------------
# Versionsvergleich (zentral, robust)
# ---------------------------------------------------------------
_PRERELEASE_ORDER = {
    "alpha": -3,
    "a": -3,
    "beta": -2,
    "b": -2,
    "rc": -1,
    "final": 0,
    "release": 0,
    "ga": 0,
    "gold": 0,
    "stable": 0,
}


def parse_version(version) -> tuple:
    """
    Zerlegt eine Versionsnummer in ein vergleichbares Tupel.

    Unterstützt:
      - numerische Kernversion  "1.2.3"
      - Prä-Release             "1.2.3-beta.1", "1.2.3rc1"
      - Build-Metadaten         "1.2.3+abc" (wird ignoriert)

    Gibt immer ein Tupel zurück, das lexikografisch verglichen werden kann:
    (maj, min, patch, prerelease_key, prerelease_part). Eine Release-Version
    ist immer GRÖSSER als jede Prä-Release der gleichen Kernversion.
    """
    raw = str(version).strip()
    # Build-Metadaten abtrennen (werden für den Vergleich ignoriert)
    raw = raw.split("+", 1)[0]

    match = re.match(r"^(\d+(?:\.\d+)*)(?:[-.]?([a-zA-Z]+)\.?(\d*))?$", raw)
    if not match:
        # Nicht parsbare Angabe -> als 0.0.0-Relealse behandeln
        return (0, 0, 0, _PRERELEASE_ORDER.get("", 0), 0,)

    core, pre_kind, pre_num = match.groups()

    core_parts = [int(p) for p in core.split(".")]
    while len(core_parts) < 3:
        core_parts.append(0)
    maj, mid, mind = core_parts[:3]

    if not pre_kind:
        # Voll freigegebene Version: höchste Priorität
        return (maj, mid, mind, 0, 0)

    key = _PRERELEASE_ORDER.get(pre_kind.lower(), -99)
    part = int(pre_num) if pre_num else 0
    return (maj, mid, mind, key, part)

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
        self.update_dir = self._user_update_dir()
        os.makedirs(self.update_dir, exist_ok=True)

    @staticmethod
    def _user_update_dir() -> str:
        """Return a writable per-user directory for downloads and cache data."""
        if platform.system() == "Windows":
            root = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
            path = os.path.join(root, "ANCORATE", "EncryptHome", "update_temp")
        elif platform.system() == "Darwin":
            path = os.path.expanduser(
                "~/Library/Application Support/ANCORATE/EncryptHome/update_temp"
            )
        else:
            root = os.environ.get(
                "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
            )
            path = os.path.join(root, "ANCORATE", "EncryptHome", "update_temp")

        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            fallback = os.path.join(tempfile.gettempdir(), "ANCORATE", "EncryptHome")
            os.makedirs(fallback, exist_ok=True)
            return fallback

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
        current = os.path.abspath(sys.executable)
        current_writable = self._path_is_writable(current)

        # Release-Daten einmal laden; Asset-Auswahl abhaengig vom Installationsort.
        release = self._fetch_release_data()
        use_installer = (not current_writable) and platform.system() == "Windows"
        asset = None
        if use_installer:
            asset = self._github_release_asset(release, installer=True)
        if asset is None:
            asset = self._github_release_asset(release, installer=False)
            use_installer = False

        data = self._github_release_to_manifest(release, asset=asset)
        setup_url = data["url"]
        sha256 = expected_sha256 or data.get("sha256", "")

        url_name = os.path.basename(urlparse(setup_url).path).strip()
        if not url_name:
            url_name = "EncryptHome-Setup.exe" if use_installer else (
                "EncryptHome" + (".exe" if platform.system() == "Windows" else "")
            )
        setup_path = os.path.join(self.update_dir, url_name)

        self._download_file(setup_url, setup_path)

        if sha256:
            if not self._verify_sha256(setup_path, sha256):
                self._cleanup_file(setup_path)
                self._download_file(setup_url, setup_path, resume=False)
                if not self._verify_sha256(setup_path, sha256):
                    raise RuntimeError(
                        "SHA256-Pruefung fehlgeschlagen; die Datei wurde mehrfach "
                        "fehlerhaft uebertragen."
                    )

        if not os.path.getsize(setup_path) > 0:
            raise RuntimeError("Der heruntergeladene Update ist leer.")

        # Installer-Modus: Inno-Setup uebernimmt die Aktualisierung (inkl. UAC),
        # auch in schreibgeschuetzten Installationsordnern wie Program Files.
        if use_installer:
            if platform.system() == "Windows":
                import ctypes
                result = ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", setup_path, None, os.path.dirname(setup_path), 1
                )
                if result <= 32:
                    raise RuntimeError("Der Installer konnte nicht gestartet werden.")
            else:
                os.chmod(setup_path, os.stat(setup_path).st_mode | 0o111)
                subprocess.Popen([setup_path], close_fds=True, start_new_session=True)
            sys.exit(0)

        pid = os.getpid()

        if current_writable:
            target = current
        else:
            target = self._user_install_path(setup_path)

        if target != current:
            self._install_user_binary(setup_path, target)
            self._launch_binary(target)
            sys.exit(0)

        if platform.system() == "Windows":
            script = os.path.join(self.update_dir, "update_replace.bat")
            with open(script, "w", encoding="utf-8") as f:
                f.write("@echo off\n")
                f.write(":wait\n")
                f.write('tasklist /FI "PID eq %d" 2>NUL | find "%d" >NUL\n' % (pid, pid))
                f.write("if %ERRORLEVEL%==0 (\n")
                f.write("  timeout /t 1 /nobreak >NUL\n")
                f.write("  goto wait\n")
                f.write(")\n")
                f.write('move /Y "%s" "%s"\n' % (setup_path, current))
                f.write('start "" "%s"\n' % current)
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
                f.write("while kill -0 %d 2>/dev/null; do sleep 1; done\n" % pid)
                f.write('cp "%s" "%s"\n' % (setup_path, current))
                f.write('chmod +x "%s"\n' % current)
                f.write('"%s" &\n' % current)
                f.write('rm -f "$0"\n')
            os.chmod(script, 0o755)
            subprocess.Popen(["/bin/sh", script], start_new_session=True, close_fds=True)

        sys.exit(0)

    @staticmethod
    def _path_is_writable(path: str) -> bool:
        """Check directory write access without requiring administrator rights."""
        directory = os.path.dirname(path) or os.curdir
        try:
            os.makedirs(directory, exist_ok=True)
            fd, probe = tempfile.mkstemp(prefix=".update-write-", dir=directory)
            os.close(fd)
            os.remove(probe)
            return True
        except OSError:
            return False

    def _user_install_path(self, downloaded_path: str) -> str:
        name = "EncryptHome.exe" if platform.system() == "Windows" else "EncryptHome"
        install_dir = os.path.join(os.path.dirname(self.update_dir), "app")
        os.makedirs(install_dir, exist_ok=True)
        return os.path.join(install_dir, name)

    @staticmethod
    def _install_user_binary(source: str, target: str) -> None:
        target_dir = os.path.dirname(target)
        os.makedirs(target_dir, exist_ok=True)
        temporary = target + ".new"
        shutil.copy2(source, temporary)
        if platform.system() != "Windows":
            os.chmod(temporary, os.stat(temporary).st_mode | 0o111)
        os.replace(temporary, target)

    @staticmethod
    def _launch_binary(path: str) -> None:
        if platform.system() != "Windows":
            os.chmod(path, os.stat(path).st_mode | 0o111)
        subprocess.Popen([path], close_fds=True, start_new_session=True)

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

        # Release assets are portable executables. Launch them directly instead
        # of invoking an elevated installer, so updates work for normal users.
        target = self._user_install_path(setup_path)
        self._install_user_binary(setup_path, target)
        self._launch_binary(target)
        sys.exit(0)

    # -------------------------
    # Manifest abrufen + validieren
    # -------------------------
    @staticmethod
    def _github_release_asset(data: dict, installer: bool = False) -> dict | None:
        assets = data.get("assets") or []
        system = platform.system().lower()

        if system == "windows":
            if installer:
                preferred = [
                    asset for asset in assets
                    if ("setup" in str(asset.get("name", "")).lower()
                        or "installer" in str(asset.get("name", "")).lower())
                ]
            else:
                preferred = [
                    asset for asset in assets
                    if "windows" in str(asset.get("name", "")).lower()
                    and "setup" not in str(asset.get("name", "")).lower()
                    and "installer" not in str(asset.get("name", "")).lower()
                ]
        elif system == "darwin":
            preferred = [
                asset for asset in assets
                if any(
                    keyword in str(asset.get("name", "")).lower()
                    for keyword in ("macos", "darwin")
                )
                and (
                    not installer
                    or "setup" in str(asset.get("name", "")).lower()
                    or "installer" in str(asset.get("name", "")).lower()
                )
            ]
        else:
            preferred = [
                asset for asset in assets
                if "linux" in str(asset.get("name", "")).lower()
                and (
                    not installer
                    or "setup" in str(asset.get("name", "")).lower()
                    or "installer" in str(asset.get("name", "")).lower()
                )
            ]

        if preferred:
            return preferred[0]

        if installer:
            return None

        raise ValueError(
            f"GitHub-Release enthält kein passendes {system}-Programm."
        )

    @staticmethod
    def _github_release_to_manifest(data: dict, asset: dict | None = None) -> dict:
        tag = str(data.get("tag_name", "")).strip().lstrip("v")
        if asset is None:
            asset = EncryptHomeUpdater._github_release_asset(data)
        if not asset:
            raise ValueError("GitHub-Release enthält keine passende Datei.")
        url = asset.get("browser_download_url")
        if not url:
            raise ValueError("GitHub-Release-Asset hat keine Download-URL.")
        digest = str(asset.get("digest") or "").strip()
        if digest.lower().startswith("sha256:"):
            digest = digest.split(":", 1)[1]
        return {
            "version": tag,
            "url": url,
            "sha256": digest or None,
            "size_mb": (
                round(int(asset["size"]) / (1024 * 1024), 2)
                if asset.get("size")
                else None
            ),
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

    def _fetch_release_data(self, timeout: int = 8) -> dict:
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

        # Beta/custom channel endpoints return a release list.
        if isinstance(data, list):
            if not data:
                raise ValueError("Keine Releases gefunden.")
            releases = [
                item for item in data
                if isinstance(item, dict)
                and bool(item.get("prerelease")) == (self.channel == "beta")
            ]
            if not releases:
                raise ValueError("Kein passendes Release für den Update-Kanal gefunden.")
            releases.sort(
                key=lambda item: parse_version(item.get("tag_name", "")),
                reverse=True,
            )
            data = releases[0]

        if not (isinstance(data, dict) and "tag_name" in data and "assets" in data):
            raise ValueError("GitHub-Release enthält keine verwertbaren Daten.")

        return data

    def fetch_manifest(self, timeout: int = 8) -> dict:
        data = self._fetch_release_data(timeout=timeout)
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
