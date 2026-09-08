import hashlib
import json
import os
import sys
from datetime import datetime
from PyQt6.QtWidgets import QApplication, QMessageBox

from utilities import get_app_icon

def get_base_dir():
    # PyInstaller (onefile & onedir)
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    # Normaler Python-Start
    return os.path.dirname(os.path.abspath(__file__))

BASE_DIR = get_base_dir()

UTILITIES_DIR = os.path.join(BASE_DIR, "utilities")
CHECKSUM_FILE = os.path.join(UTILITIES_DIR, "checksums.json")

# === CONFIG ===
CHECKSUM_LOG = os.path.join(BASE_DIR, "checksum_log.json")


# --- Hilfsfunktionen für QApplication ---
def _get_app():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


# --- Checksumme berechnen ---
def calculate_checksum(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


# --- Meldungen ---
def show_warning(message: str):
    app = _get_app()
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Warning)
    msg.setWindowTitle("ANCORATE – Integritätsprüfung")
    msg.setText(message)
    msg.setWindowIcon(get_app_icon())
    msg.exec()


def show_info(message: str):
    app = _get_app()
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Information)
    msg.setWindowTitle("ANCORATE – Integritätsprüfung")
    msg.setText(message)
    msg.setWindowIcon(get_app_icon())
    msg.exec()


def ask_user_confirmation(message: str) -> bool:
    app = _get_app()
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Question)
    msg.setWindowTitle("ANCORATE – Integritätsprüfung")
    msg.setText(message)
    msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    msg.setWindowIcon(get_app_icon())
    result = msg.exec()
    return result == QMessageBox.StandardButton.Yes


# --- Checksummen-Datei laden/speichern ---
def load_checksums() -> dict:
    if os.path.exists(CHECKSUM_FILE):
        with open(CHECKSUM_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return {}
    return {}


def save_checksums(data: dict):
    with open(CHECKSUM_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


# --- Logging ---
def log_checksum_action(filename: str, old_checksum: str, new_checksum: str, action: str):
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "file": filename,
        "old_checksum": old_checksum,
        "new_checksum": new_checksum,
        "action": action
    }

    logs = []
    if os.path.exists(CHECKSUM_LOG):
        try:
            with open(CHECKSUM_LOG, "r", encoding="utf-8") as f:
                logs = json.load(f)
        except Exception:
            logs = []

    logs.append(log_entry)

    try:
        with open(CHECKSUM_LOG, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Fehler beim Schreiben der Log-Datei: {e}")


# --- Integritätsprüfung ---
def verify_file_integrity(file_path: str = None, update=False):
    """
    Verify file integrity by checking checksums.

    Returns:
        True if integrity check passed or file is new.
        False if user rejected the update (caller should consider aborting).
    Raises:
        SystemExit: Only if file_path is missing (critical error).
    """
    if file_path is None:
        file_path = os.path.abspath(sys.argv[0])

    if not os.path.exists(file_path):
        show_warning(f"Die Datei '{file_path}' wurde nicht gefunden.")
        raise FileNotFoundError(f"Integrity check failed: file not found: {file_path}")

    checksums = load_checksums()
    new_checksum = calculate_checksum(file_path)
    filename = os.path.basename(file_path)
    old_checksum = checksums.get(filename, "")

    if filename in checksums:
        if checksums[filename] != new_checksum:
            # Datei verändert
            show_warning( f"ANCORATE Software-Systemdateien wurden verändert!\n\n" "Das kann durch ein Update, eine lokale Änderung oder eine potenzielle Manipulation verursacht worden sein.\n" "Wenn du diese Änderung nicht erwartest, brich die Nutzung im nächsten Dialog ab und überprüfe die Datei genauer." )
            log_checksum_action(filename, old_checksum, new_checksum, "verified")

            if update:
                want_update = ask_user_confirmation( "Die gespeicherte Checksumme unterscheidet sich von der aktuell signierten Versionsdatei.\n\n" "Möchtest du die neue Checksumme als vertrauenswürdig speichern?\n\n" "→ Ja: Speichert die neue Checksumme (Akzeptiere diese Version).\n" "→ Nein: Die Anwendung wird beendet (sichere Maßnahme)." )
                if want_update:
                    checksums[filename] = new_checksum
                    save_checksums(checksums)
                    log_checksum_action(filename, old_checksum, new_checksum, "updated")
                else:
                    log_checksum_action(filename, old_checksum, new_checksum, "user_rejected")
                    show_warning("Die Anwendung wird aus Sicherheitsgründen beendet.")
                    return False
        else:
            # unverändert
            log_checksum_action(filename, old_checksum, new_checksum, "verified")
    else:
        # neue Datei registrieren
        checksums[filename] = new_checksum
        save_checksums(checksums)
        log_checksum_action(filename, "", new_checksum, "registered")
        show_info(f"Neue Version registriert und Checksumme gespeichert.\nSie sehen diese Meldung, weil Sie entweder ein Update eingespielt oder ANCORATE Software neu installiert haben.")
    return True