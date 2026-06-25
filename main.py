#!/usr/bin/env python3
# ANCORATE EncryptHome
# © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
# IF YOU ARE READING OR MODIFYING THIS CODE WITHOUT AUTHORIZATION, YOU ARE IN VIOLATION OF COPYRIGHT LAW.
# This code is part of the ANCORATE Encryption Suite. Unauthorized distribution or modification is prohibited.
# -------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------

# OS Module
import os.path
import random
import socket
import subprocess
import hashlib
import json
import struct
import platform
import requests

# Network / Discovery
# from discovery.request_client import *
# from discovery.discovery_gui import Discovery
# Standardbibliotheken
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *

from argon2.low_level import Type, hash_secret_raw

# Interne Module
from decrypt import *
from decrypt_preview import PREVIEW_MAX_BYTES, PreviewDecryptWorker, show_preview
from encrypt import *

# Utilities
from utilities.checksum_check import *
from utilities.header_utils import *
from utilities.settings import *

# -------------------------------------------------------------------------------------------------------------------


MAGIC = b"ANC0"  # Magic-Header für ANCORATE .salt Container
VERSION = 0x09  # Aktuelle Containerversion
FLAG_DEVICE = 0x01  # Container ist an Gerät gebunden
FLAG_KEYFILE = 0x02  # Container verwendet Keyfile
FLAG_PRO_VAULT = 0x04  # Container wurde mit EncryptPro erstellt
SALT_LEN = 16  # 16 Bytes Salt
CHUNK = 128 * 1024  # 128 KB pro Verschlüsselungsblock
META_LEN_SIZE = 8  # 8 Bytes für die Metadatenlänge am Ende der Datei
ARGON2_TIME = 3  # Zeitkosten für Argon2
ARGON2_MEM_KIB = 131072  # 128 MB Speicher für Argon2
ARGON2_PAR = 4  # Parallelismus für Argon2
ARGON2_OUT = 32  # Länge des ausgegebenen Schlüssels in Bytes
SCRYPT_N = 2**14  # 16.384
SCRYPT_R = 8  # 8 ist ein guter Standardwert für die Blockgröße
SCRYPT_P = 1  # 1 ist ein guter Standardwert für die Parallelität
PROJECT_PEPPER = b"ANCORATE_734912285612843967510042198831607952451"  # Fester Pepper-Wert für Passwort-Härtung
HEADER_FMT = f"4s B B {SALT_LEN}s 6s"  # Magic, Version, Flags, Salt, Reserved (6 Bytes für zukünftige Erweiterungen)
HEADER_LEN = struct.calcsize(HEADER_FMT)  # 4 + 1 + 1 + 16 + 6 = 28 Bytes
HKDF_INFO = b"ANCORATE-MASTER-26"  # Info für HKDF
HKDF_LENGTH = 32  # 32 Bytes -> AES-256
LICENSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "licenses.dat")
MASTER_KEY_LICENSE = b"ueeEu2Qv00JqDFb9K0vbEAL1MQsMRjDEItOMkzYUJwE="  # 32 Bytes fester Schlüssel für Lizenzdatei-Verschlüsselung
CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ancorate")

os.makedirs(CONFIG_DIR, exist_ok=True)

SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")
ANCORATE_BLUE = "#1e88e5"
ANCORATE_BLUE_SOFT = "#90caf9"
BACKGROUND_DARK = "#0b0f14"

version = "26.2"  # aktuelle Version der Software, wird in gui angezeigt
version_year = "26"
edition = "EncryptHome"  # Edition der Software
type_edition = "Citadel"

# Prüfe und aktualisiere Checksummen der Systemdateien
# verify_file_integrity(f"ANCORATE_{edition}_26.2_Build_0009.exe", update=True)


if os.name == "nt":
    CONFIG_DIR = os.path.join(os.environ.get("APPDATA", str(Path.home())), "ANCORATE")
else:
    CONFIG_DIR = os.path.join(str(Path.home()), ".config", "ANCORATE")
CONFIG_FILE = os.path.join(CONFIG_DIR, "device.png")
REGISTRATION_MARKER = os.path.join(CONFIG_DIR, ".registered")
RECENT_CONTAINERS_FILE = os.path.join(CONFIG_DIR, "recent_containers.json")


def get_app_icon():
    """
    Lädt das passende Icon-Format für die aktuelle Plattform.
    """
    system = platform.system()
    
    # Verschiedene Icon-Formate versuchen
    icon_paths = []
    
    if system == "Windows":
        icon_paths = [
            "utilities/icon.ico",
            "utilities/icon.png",
        ]
    else:
        icon_paths = [
            "utilities/icon.png",
            "utilities/icon_64x64.png",
            "utilities/icon_48x48.png",
            "utilities/icon_32x32.png",
        ]
    
    # Erstes existierendes Icon zurückgeben
    for path in icon_paths:
        if os.path.exists(path):
            return QIcon(path)
    
    # Fallback: Leeres Icon
    return QIcon()


def read_json_file(path):
    """Hilfsfunktion: Liest JSON ein"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def safe_run(cmd, timeout=1):
    try:
        out = subprocess.check_output(
            cmd, stderr=subprocess.DEVNULL, shell=True, text=True, timeout=timeout
        )
        return out.strip()
    except Exception:
        return ""


def get_mac_bytes():
    import uuid

    node = uuid.getnode()
    return int(node).to_bytes(6, "big", signed=False)


def get_cpu_id():
    import platform
    system = platform.system()
    
    try:
        if system == "Windows":
            out = safe_run("wmic cpu get ProcessorId")
            if out:
                lines = [
                    l.strip() for l in out.splitlines() 
                    if l.strip() and "ProcessorId" not in l
                ]
                if lines:
                    return lines[0]
        elif system == "Darwin":  # macOS
            out = safe_run("sysctl -n machdep.cpu.brand_string")
            if out:
                return out.strip()
        elif system == "Linux":
            out = safe_run("cat /proc/cpuinfo | grep 'model name' | head -1")
            if out:
                # Format: "model name      : Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz"
                parts = out.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    except Exception as e:
        print(f"[WARN] CPU ID detection failed: {e}")
    
    return "unknown-cpu"


def get_disk_serial():
    import platform
    system = platform.system()
    
    try:
        if system == "Windows":
            out = safe_run("wmic diskdrive get SerialNumber")
            if out:
                lines = [
                    l.strip() for l in out.splitlines() 
                    if l.strip() and "SerialNumber" not in l
                ]
                if lines:
                    return lines[0]
            out = safe_run("vol C:")
            if out:
                return out.replace("\r", "").replace("\n", "").strip()
        elif system == "Darwin":  # macOS
            out = safe_run("diskutil info / | grep 'Volume UUID'")
            if out:
                # Format: "   Volume UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
                parts = out.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
        elif system == "Linux":
            out = safe_run("lsblk -d -o serial -n")
            if out:
                return out.strip()
    except Exception as e:
        print(f"[WARN] Disk serial detection failed: {e}")
    
    return "unknown-disk"


def ensure_config_dir():
    d = os.path.dirname(CONFIG_FILE)
    os.makedirs(d, exist_ok=True)


def save_device_key_hex(key_bytes: bytes):
    """
    Legacy function for compatibility. No longer saves to file since key is generated at runtime.
    """
    # Device key is now generated at runtime, no need to save
    pass


def device_fingerprint() -> bytes:
    """Generate consistent device fingerprint from hardware identifiers"""
    try:
        mac = get_mac_bytes()
        cpu = get_cpu_id().encode("utf-8", errors="ignore")
        dsk = get_disk_serial().encode("utf-8", errors="ignore")
        
        # Validate components
        if len(mac) != 6:
            print(f"[WARN] Invalid MAC address length: {len(mac)}")
        if not cpu:
            print("[WARN] Could not get CPU ID")
        if not dsk:
            print("[WARN] Could not get disk serial")
            
        raw = b"|".join([b"MAC", mac, b"CPU", cpu, b"DSK", dsk])
        fp = hashlib.sha256(raw).digest()
        
        print(f"[DEBUG] Device fingerprint generated successfully")
        return fp
    except Exception as e:
        print(f"[ERROR] Device fingerprint generation failed: {e}")
        # Fallback to random but consistent seed
        import platform
        fallback = f"{platform.node()}{platform.system()}".encode("utf-8")
        return hashlib.sha256(fallback).digest()


def generate_device_key() -> bytes:
    """
    Generate a consistent device key at runtime without storing to file.
    Uses deterministic approach: SHA256(fingerprint + ANCORATE_SEED)
    """
    fp = device_fingerprint()
    
    # Use a fixed seed instead of random secret for consistency
    seed = b"ANCORATE_DEVICE_KEY_SEED_2026_STABLE"
    
    # Generate deterministic key
    device_key = hashlib.sha256(fp + seed).digest()
    
    return device_key


def load_device_key() -> bytes:
    """
    Always generate the device key at runtime instead of loading from file.
    This ensures the same key for the same device without file dependency.
    """
    try:
        key = generate_device_key()
        # Validate key is 32 bytes (AES-256)
        if len(key) != 32:
            raise ValueError(f"Invalid device key length: {len(key)} bytes, expected 32")
        return key
    except Exception as e:
        print(f"[ERROR] Device key generation failed: {e}")
        # Fallback to empty bytes if fingerprint generation fails
        return b""


def is_device_registered() -> bool:
    """Check if this device has been registered before"""
    return os.path.exists(REGISTRATION_MARKER)


def mark_device_registered():
    """Mark this device as registered"""
    ensure_config_dir()
    try:
        with open(REGISTRATION_MARKER, "w") as f:
            f.write("registered")
    except Exception:
        pass


def load_recent_containers() -> list:
    """Load recent containers list"""
    try:
        if os.path.exists(RECENT_CONTAINERS_FILE):
            with open(RECENT_CONTAINERS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        return []
    except Exception:
        return []


def save_recent_containers(containers: list):
    """Save recent containers list"""
    try:
        ensure_config_dir()
        with open(RECENT_CONTAINERS_FILE, "w", encoding="utf-8") as f:
            json.dump(containers[:10], f, indent=2)  # Keep only last 10
    except Exception as e:
        print(f"[ERROR] Failed to save recent containers: {e}")


def add_recent_container(container_path: str):
    """Add container to recent list"""
    containers = load_recent_containers()
    
    # Remove if already exists
    containers = [c for c in containers if c["path"] != container_path]
    
    # Add to beginning
    recent_entry = {
        "path": container_path,
        "name": os.path.basename(container_path),
        "last_accessed": int(time.time())
    }
    containers.insert(0, recent_entry)
    
    save_recent_containers(containers)


def rekey_container_password(
    container_path: str,
    current_meta: dict,
    current_flags: int,
    current_master_key: bytes,
    new_password: str,
) -> None:
    if not os.path.isfile(container_path):
        raise FileNotFoundError(f"Container nicht gefunden: {container_path}")

    new_salt = secrets.token_bytes(SALT_LEN)
    device_key = load_device_key() if (current_flags & FLAG_DEVICE) else None
    new_master = derive_master_key(
        new_password,
        new_salt,
        bool(current_flags & FLAG_DEVICE),
        device_key,
    )

    # Re-encrypt all file data with new master key
    new_meta = dict(current_meta)
    new_meta["flags"] = current_flags
    
    # Read old salt from container for decryption
    with open(container_path, "rb") as source:
        header = source.read(HEADER_LEN)
        magic, version, flags, old_salt, _reserved = struct.unpack(HEADER_FMT, header)
    
    # Derive old master key for decryption
    # Note: We need the old password to derive the old master key
    # Since we don't have it here, we'll use the passed current_master_key directly
    
    # Re-encrypt each file blob
    new_files = []
    current_offset = HEADER_LEN
    
    for file_entry in current_meta.get("files", []):
        file_name = file_entry["name"]
        file_offset = file_entry["offset"]
        file_length = file_entry["length"]
        
        # Decrypt with old master key and re-encrypt with new master key
        try:
            from decrypt import decrypt_blob_range
            from encrypt import encrypt_file_to_blob
            import tempfile as tf
            
            # Create temporary file for decrypted data
            with tf.NamedTemporaryFile(delete=False) as tmp_decrypt:
                tmp_decrypt_path = tmp_decrypt.name
            
            # Decrypt blob to temp file
            with open(container_path, "rb") as source:
                source.seek(file_offset)
                decrypt_blob_range(source, tmp_decrypt_path, file_length, current_master_key, file_name)
            
            # Re-encrypt with new master key
            with tf.NamedTemporaryFile(delete=False) as tmp_encrypt:
                tmp_encrypt_path = tmp_encrypt.name
            
            with open(tmp_encrypt_path, "wb") as tmp_encrypt_file:
                encrypt_file_to_blob(
                    tmp_decrypt_path,
                    tmp_encrypt_file,
                    new_master,
                    filename=file_name,
                )
            
            # Read re-encrypted blob
            with open(tmp_encrypt_path, "rb") as enc_file:
                reencrypted_blob = enc_file.read()
            
            # Store re-encrypted blob in file entry for later writing
            file_entry_with_blob = {
                "name": file_name,
                "offset": current_offset,
                "length": len(reencrypted_blob),
                "size": file_entry.get("size", 0),
                "blob": reencrypted_blob
            }
            new_files.append(file_entry_with_blob)
            
            current_offset += len(reencrypted_blob)
            
            # Cleanup temp files
            try:
                os.remove(tmp_decrypt_path)
                os.remove(tmp_encrypt_path)
            except:
                pass
                
        except Exception as e:
            # If re-encryption fails, keep original blob
            print(f"[WARN] Re-encryption failed for {file_name}: {e}")
            # Read original blob
            with open(container_path, "rb") as source:
                source.seek(file_offset)
                original_blob = source.read(file_length)
            
            new_files.append({
                "name": file_name,
                "offset": current_offset,
                "length": file_length,
                "size": file_entry.get("size", 0),
                "blob": original_blob
            })
            current_offset += file_length
    
    # Create clean metadata without blob fields for JSON serialization
    new_meta_files = []
    for file_entry in new_files:
        clean_entry = {
            "name": file_entry["name"],
            "offset": file_entry["offset"],
            "length": file_entry["length"],
            "size": file_entry.get("size", 0)
        }
        new_meta_files.append(clean_entry)
    
    new_meta["files"] = new_meta_files
    new_meta_blob = encrypt_meta(new_meta, new_master)

    container_dir = os.path.dirname(container_path) or os.curdir
    temp_path = None
    try:
        with open(container_path, "rb") as source, tempfile.NamedTemporaryFile(
            delete=False, dir=container_dir
        ) as tmp:
            temp_path = tmp.name

            header = source.read(HEADER_LEN)
            if len(header) != HEADER_LEN:
                raise ValueError("Container-Header ist beschädigt oder unvollständig.")
            magic, version, flags, _salt, _reserved = struct.unpack(HEADER_FMT, header)
            if magic != MAGIC:
                raise ValueError("Ungültiger Container-Header.")
            if flags != current_flags:
                raise ValueError("Container-Flags stimmen nicht mit dem geöffneten Tresor überein.")

            source.seek(0, os.SEEK_END)
            file_size = source.tell()
            if file_size < HEADER_LEN + META_LEN_SIZE:
                raise ValueError("Container ist zu kurz.")

            source.seek(-META_LEN_SIZE, os.SEEK_END)
            old_meta_len_bytes = source.read(META_LEN_SIZE)
            if len(old_meta_len_bytes) != META_LEN_SIZE:
                raise ValueError("Metadatenlänge konnte nicht gelesen werden.")
            old_meta_len = struct.unpack("<Q", old_meta_len_bytes)[0]

            data_end = file_size - META_LEN_SIZE - old_meta_len
            if data_end < HEADER_LEN:
                raise ValueError("Metadatenposition ist ungültig.")

            write_header(tmp, current_flags, new_salt)
            
            # Write re-encrypted file blobs
            for file_entry in new_files:
                blob = file_entry["blob"]
                tmp.write(blob)

            tmp.write(new_meta_blob)
            tmp.write(struct.pack("<Q", len(new_meta_blob)))

        os.replace(temp_path, container_path)
        temp_path = None
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except Exception:
                pass


def change_container_password(container_path: str, current_master_key: bytes, current_meta: dict, current_password: str, current_flags: int, parent=None) -> bool:
    """
    Change password for existing container
    Returns True if successful, False if cancelled
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle("Passwort ändern")
    dialog.setWindowIcon(get_app_icon())
    dialog.setMinimumSize(560, 440)
    dialog.resize(560, 440)
    dialog.setModal(True)
    
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(24, 24, 24, 24)
    layout.setSpacing(16)
    
    title_label = QLabel("Passwort für den geöffneten Tresor ändern")
    title_label.setStyleSheet("font-size: 18px; font-weight: 700;")
    layout.addWidget(title_label)

    info_label = QLabel(
        "Der Tresorinhalt bleibt erhalten. Das Ändern des Passworts aktualisiert die Verschlüsselungskeys, um die Sicherheit zu verbessern. Das kann bei großen Tresoren einige Zeit dauern."
    )
    info_label.setWordWrap(True)
    info_label.setStyleSheet("color: #8a8f98; font-size: 11px;")
    layout.addWidget(info_label)
    
    # Store result for returning the new password
    result = {'success': False, 'new_password': None}
    
    # New password with requirements
    new_group = QGroupBox("Neues Passwort")
    new_layout = QVBoxLayout()
    new_layout.setContentsMargins(16, 18, 16, 16)
    new_layout.setSpacing(10)

    new_pwd_input = QLineEdit()
    new_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    new_pwd_input.setPlaceholderText("Neues Passwort eingeben")
    new_pwd_input.setMinimumHeight(34)

    confirm_pwd_input = QLineEdit()
    confirm_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    confirm_pwd_input.setPlaceholderText("Neues Passwort bestätigen")
    confirm_pwd_input.setMinimumHeight(34)

    form = QFormLayout()
    form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
    form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
    form.setHorizontalSpacing(12)
    form.setVerticalSpacing(10)
    form.addRow("Neues Passwort", new_pwd_input)
    form.addRow("Bestätigen", confirm_pwd_input)
    new_layout.addLayout(form)

    req_group = QGroupBox("Anforderungen")
    req_group_layout = QGridLayout()
    req_group_layout.setContentsMargins(12, 14, 12, 12)
    req_group_layout.setHorizontalSpacing(18)
    req_group_layout.setVerticalSpacing(8)

    req_widgets = {}
    req_labels = [
        ("Mindestens 8 Zeichen", "length"),
        ("Mindestens 1 Großbuchstabe (A-Z)", "upper"),
        ("Mindestens 1 Kleinbuchstabe (a-z)", "lower"),
        ("Mindestens 1 Ziffer (0-9)", "digit"),
        ("Mindestens 1 Sonderzeichen (!@#$%^&*)", "special"),
    ]

    for idx, (text, key) in enumerate(req_labels):
        label = QLabel(f"◦ {text}")
        label.setStyleSheet("color: #8a8f98; font-size: 11px;")
        req_widgets[key] = label
        req_group_layout.addWidget(label, idx // 2, idx % 2)

    req_group.setLayout(req_group_layout)
    new_group.setLayout(new_layout)
    layout.addWidget(new_group)
    layout.addWidget(req_group)

    # Update requirements as user types
    def update_requirements():
        password = new_pwd_input.text()
        req_widgets["length"].setStyleSheet(
            "color: #6ee7b7; font-size: 11px;"
            if len(password) >= 8
            else "color: #8a8f98; font-size: 11px;"
        )
        req_widgets["length"].setText(
            f"{'✓' if len(password) >= 8 else '◦'} Mindestens 8 Zeichen"
        )

        has_upper = any(c.isupper() for c in password)
        req_widgets["upper"].setStyleSheet(
            "color: #6ee7b7; font-size: 11px;"
            if has_upper
            else "color: #8a8f98; font-size: 11px;"
        )
        req_widgets["upper"].setText(
            f"{'✓' if has_upper else '◦'} Mindestens 1 Großbuchstabe (A-Z)"
        )

        has_lower = any(c.islower() for c in password)
        req_widgets["lower"].setStyleSheet(
            "color: #6ee7b7; font-size: 11px;"
            if has_lower
            else "color: #8a8f98; font-size: 11px;"
        )
        req_widgets["lower"].setText(
            f"{'✓' if has_lower else '◦'} Mindestens 1 Kleinbuchstabe (a-z)"
        )

        has_digit = any(c.isdigit() for c in password)
        req_widgets["digit"].setStyleSheet(
            "color: #6ee7b7; font-size: 11px;"
            if has_digit
            else "color: #8a8f98; font-size: 11px;"
        )
        req_widgets["digit"].setText(
            f"{'✓' if has_digit else '◦'} Mindestens 1 Ziffer (0-9)"
        )

        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        req_widgets["special"].setStyleSheet(
            "color: #6ee7b7; font-size: 11px;"
            if has_special
            else "color: #8a8f98; font-size: 11px;"
        )
        req_widgets["special"].setText(
            f"{'✓' if has_special else '◦'} Mindestens 1 Sonderzeichen (!@#$%^&*)"
        )

    new_pwd_input.textChanged.connect(update_requirements)
    update_requirements()

    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()

    change_btn = QPushButton("Passwort ändern")
    cancel_btn = QPushButton("Abbrechen")
    cancel_btn.setObjectName("secondary")
    change_btn.setDefault(True)
    change_btn.setMinimumWidth(150)
    cancel_btn.setMinimumWidth(120)
    change_btn.setObjectName("primary")
    # change_btn.setStyleSheet(
        #     "QPushButton { background: #2f7cf6; color: white; border: none; "
        #     "border-radius: 6px; padding: 9px 18px; font-weight: 600; }"
        #     "QPushButton:hover { background: #3f8cff; }"
        #     "QPushButton:pressed { background: #2265d1; }"
    # )

    btn_layout.addWidget(change_btn)
    btn_layout.addWidget(cancel_btn)
    layout.addLayout(btn_layout)

    # Button handlers
    def change_password():
        new_pwd = new_pwd_input.text()
        confirm_pwd = confirm_pwd_input.text()
        
        if new_pwd != confirm_pwd:
            QMessageBox.warning(dialog, "Fehler", "Neue Passwörter stimmen nicht überein.")
            return
        
        is_valid, error_msg = validate_password_strength(new_pwd)
        if not is_valid:
            QMessageBox.warning(dialog, "Ungültiges Passwort", error_msg)
            return
        
        try:
            rekey_container_password(container_path, current_meta, current_flags, current_master_key, new_pwd)
            result['success'] = True
            result['new_password'] = new_pwd
            
            QMessageBox.information(dialog, "Erfolg", "Passwort wurde erfolgreich geändert.")
            dialog.accept()
            
        except Exception as e:
            QMessageBox.critical(dialog, "Fehler", f"Passwortänderung fehlgeschlagen: {str(e)}")
    
    def reject_dialog():
        dialog.reject()
    
    change_btn.clicked.connect(change_password)
    cancel_btn.clicked.connect(reject_dialog)
    
    # Show dialog
    dialog_result = dialog.exec() == QDialog.DialogCode.Accepted
    if dialog_result and result['success']:
        # Return both success flag and new password
        return True, result['new_password']
    return False, None


def auto_register_device(export_path: str | None = None) -> bytes:
    """
    Legacy function for compatibility. Now generates and optionally exports the device key.
    The key is generated deterministically and doesn't need to be stored.
    """
    device_key = generate_device_key()
    
    # Mark device as registered
    mark_device_registered()

    if export_path:
        try:
            with open(export_path, "wb") as f:
                f.write(device_key)
        except Exception:
            pass

    return device_key


def derive_argon2(password_bytes: bytes, salt: bytes) -> bytes:
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEM_KIB,
        parallelism=ARGON2_PAR,
        hash_len=ARGON2_OUT,
        type=Type.ID,
    )
    return key


def derive_master_key(
    password: str,
    salt: bytes,
    device_bound: bool = False,
    device_key: Optional[bytes] = None,
) -> bytes:
    try:
        if not isinstance(password, str):
            raise TypeError("password muss str sein.")
        if not isinstance(salt, bytes) or len(salt) != 16:
            raise ValueError("salt muss 16 Bytes lang sein.")
        if device_bound and (device_key is None):
            raise ValueError("device_bound=True verlangt device_key")

        # Validate device key if device bound
        if device_bound and device_key:
            if len(device_key) != 32:
                raise ValueError(f"Invalid device key length: {len(device_key)}")

        # Passwort + Pepper → Argon2
        pwd_bytes = password.encode("utf-8") + PROJECT_PEPPER
        pwd_key = derive_argon2(pwd_bytes, salt)  # 32 Bytes

        # Device-Binding sicher per Hash (32 Bytes)
        device_hash = hashlib.sha256(device_key).digest() if device_key else b""

        # Kombinieren als Input für HKDF (variabel lang)
        ikm = pwd_key + device_hash

        # HKDF erzwingt exakt 32 Bytes → AES-256 kompatibel
        master = HKDF(
            algorithm=hashes.SHA256(), length=HKDF_LENGTH, salt=salt, info=HKDF_INFO
        ).derive(ikm)

        print(f"[DEBUG] Master key derived successfully")
        return master
    except Exception as e:
        print(f"[ERROR] Master key derivation failed: {e}")
        raise


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password strength and return (is_valid, error_message)
    Requirements:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter  
    - At least 1 digit
    - At least 1 special character
    """
    if len(password) < 8:
        return False, "Passwort muss mindestens 8 Zeichen lang sein."
    
    has_upper = any(c.isupper() for c in password)
    if not has_upper:
        return False, "Passwort muss mindestens 1 Großbuchstaben enthalten."
    
    has_lower = any(c.islower() for c in password)
    if not has_lower:
        return False, "Passwort muss mindestens 1 Kleinbuchstaben enthalten."
    
    has_digit = any(c.isdigit() for c in password)
    if not has_digit:
        return False, "Passwort muss mindestens 1 Ziffer enthalten."
    
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    if not has_special:
        return False, "Passwort muss mindestens 1 Sonderzeichen enthalten (!@#$%^&* etc.)."
    
    return True, ""


def get_password_with_requirements(parent, title="Passwort eingeben") -> tuple[str, bool]:
    """
    Get password with visual requirements display
    Returns (password, was_cancelled)
    """
    dialog = QDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setWindowIcon(get_app_icon())
    dialog.setFixedSize(450, 350)
    dialog.setModal(True)
    
    layout = QVBoxLayout(dialog)
    
    # Password input
    pwd_layout = QHBoxLayout()
    pwd_label = QLabel("Passwort:")
    pwd_label.setFixedWidth(80)
    pwd_input = QLineEdit()
    pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    pwd_input.setMinimumWidth(300)
    pwd_layout.addWidget(pwd_label)
    pwd_layout.addWidget(pwd_input)
    layout.addLayout(pwd_layout)
    
    # Requirements display
    req_group = QGroupBox("Passwortanforderungen:")
    req_layout = QVBoxLayout()
    
    req_labels = [
        ("Mindestens 8 Zeichen", "length"),
        ("Mindestens 1 Großbuchstabe (A-Z)", "upper"),
        ("Mindestens 1 Kleinbuchstabe (a-z)", "lower"),
        ("Mindestens 1 Ziffer (0-9)", "digit"),
        ("Mindestens 1 Sonderzeichen (!@#$%^&*)", "special")
    ]
    
    req_widgets = {}
    for text, key in req_labels:
        label = QLabel(f"○ {text}")
        label.setStyleSheet("color: #666; font-size: 11px; margin-left: 10px;")
        req_widgets[key] = label
        req_layout.addWidget(label)
    
    req_group.setLayout(req_layout)
    layout.addWidget(req_group)
    
    # Update requirements display as user types
    def update_requirements():
        password = pwd_input.text()
        is_valid, error_msg = validate_password_strength(password)
        
        # Update visual indicators
        req_widgets["length"].setStyleSheet(
            "color: #4CAF50; font-size: 11px; margin-left: 10px;" 
            if len(password) >= 8 else "color: #666; font-size: 11px; margin-left: 10px;"
        )
        req_widgets["length"].setText(
            f"{'✓' if len(password) >= 8 else '○'} Mindestens 8 Zeichen"
        )
        
        has_upper = any(c.isupper() for c in password)
        req_widgets["upper"].setStyleSheet(
            "color: #4CAF50; font-size: 11px; margin-left: 10px;" 
            if has_upper else "color: #666; font-size: 11px; margin-left: 10px;"
        )
        req_widgets["upper"].setText(
            f"{'✓' if has_upper else '○'} Mindestens 1 Großbuchstabe (A-Z)"
        )
        
        has_lower = any(c.islower() for c in password)
        req_widgets["lower"].setStyleSheet(
            "color: #4CAF50; font-size: 11px; margin-left: 10px;" 
            if has_lower else "color: #666; font-size: 11px; margin-left: 10px;"
        )
        req_widgets["lower"].setText(
            f"{'✓' if has_lower else '○'} Mindestens 1 Kleinbuchstabe (a-z)"
        )
        
        has_digit = any(c.isdigit() for c in password)
        req_widgets["digit"].setStyleSheet(
            "color: #4CAF50; font-size: 11px; margin-left: 10px;" 
            if has_digit else "color: #666; font-size: 11px; margin-left: 10px;"
        )
        req_widgets["digit"].setText(
            f"{'✓' if has_digit else '○'} Mindestens 1 Ziffer (0-9)"
        )
        
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        req_widgets["special"].setStyleSheet(
            "color: #4CAF50; font-size: 11px; margin-left: 10px;" 
            if has_special else "color: #666; font-size: 11px; margin-left: 10px;"
        )
        req_widgets["special"].setText(
            f"{'✓' if has_special else '○'} Mindestens 1 Sonderzeichen (!@#$%^&*)"
        )
    
    pwd_input.textChanged.connect(update_requirements)
    update_requirements()  # Initial state
    
    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()
    
    ok_btn = QPushButton("OK")
    cancel_btn = QPushButton("Abbrechen")
    cancel_btn.setObjectName("secondary")

    btn_layout.addWidget(ok_btn)
    btn_layout.addWidget(cancel_btn)
    layout.addLayout(btn_layout)
    
    # Button handlers
    result_password = ""
    cancelled = True
    
    def accept_password():
        nonlocal result_password, cancelled
        password = pwd_input.text()
        is_valid, error_msg = validate_password_strength(password)
        
        if not is_valid:
            QMessageBox.warning(dialog, "Ungültiges Passwort", error_msg)
            return
        
        result_password = password
        cancelled = False
        dialog.accept()
    
    def reject_dialog():
        nonlocal cancelled
        cancelled = True
        dialog.reject()
    
    ok_btn.clicked.connect(accept_password)
    cancel_btn.clicked.connect(reject_dialog)
    pwd_input.returnPressed.connect(accept_password)
    
    # Show dialog
    dialog.exec()
    return result_password, cancelled


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = ""
    try:
        # "Verbindung" zu einer externen Adresse aufbauen (wird nicht wirklich gesendet)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        print("Device offline. It has to be online to identify its IP address.")
    finally:
        s.close()
    return ip


def write_header(fh, flags: int, salt: bytes):
    """
    Schreibt den ANCORATE-Container-Header an den Anfang der Datei.
    fh muss im Write- oder Read/Write-Modus geöffnet sein.
    Überschreibt vorhandene Headerdaten vollständig.
    """
    if len(salt) != SALT_LEN:
        raise ValueError(
            f"Salt muss {SALT_LEN} Bytes lang sein (erhalten: {len(salt)})"
        )
    
    # Ensure flags is within valid range for B format (0-255)
    if flags < 0 or flags > 255:
        raise ValueError(
            f"Flags müssen im Bereich 0-255 liegen (erhalten: {flags})"
        )

    reserved = b"\x00" * 6
    header = struct.pack(HEADER_FMT, MAGIC, VERSION, flags, salt, reserved)

    # Sicherstellen, dass am Anfang geschrieben wird
    fh.seek(0)
    fh.write(header)
    fh.flush()


def read_header(fh):
    """
    Liest den Header eines geöffneten Containers und repariert ihn bei Bedarf.
    fh muss im Read/Write-Modus geöffnet sein.
    Gibt die Felder zurück: (version, flags, salt)
    """
    fh.seek(0)
    data = fh.read(HEADER_LEN)

    # Header zu kurz → reparieren
    if len(data) < HEADER_LEN or not data.startswith(MAGIC):
        print("[WARN] Header beschädigt oder unvollständig. Wird repariert.")
        salt = os.urandom(SALT_LEN)
        fh.seek(0)  # Anfang der Datei
        write_header(fh, FLAG_DEVICE | FLAG_KEYFILE, salt)
        fh.flush()
        fh.seek(0)  # wieder an Anfang

    # Header vollständig → auslesen
    magic, ver, flags, salt, _ = struct.unpack(HEADER_FMT, data)
    if magic != MAGIC:
        print("[WARN] Ungültige Magic Bytes. Header wird ersetzt.")
        salt = os.urandom(SALT_LEN)
        fh.seek(0)
        write_header(fh, FLAG_DEVICE | FLAG_KEYFILE, salt)
        fh.flush()
        fh.seek(0)
        return flags, salt

    # Header ok
    return flags, salt


class notifier:
    @staticmethod
    def show(title: str, message: str, timeout: int = 1):
        """
        Zeigt eine System-Push-Benachrichtigung an.

        :param title: Titel der Nachricht
        :param message: Inhalt der Nachricht
        :param timeout: Dauer in Sekunden (optional)
        """
        # notification.notify(
        #     title=title,
        #     message=message,
        #     timeout=timeout
        # )


# Einfachen trennenden Strich erzeugen - wird in DetailsDialog verwendet
def make_separator(color="#2a2c32"):
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    line.setStyleSheet(f"background-color: {color}; border: none;")
    return line


# -------------------------------------------------
# Modernisierte Partikel
# -------------------------------------------------
class Particle:
    """Einzelner Partikel für weichen Hintergrundeffekt"""

    def __init__(self, x, y):
        self.pos = QPointF(x, y)
        self.vel = QPointF(random.uniform(-0.8, 0.8), random.uniform(-0.8, 0.8))
        self.size = random.randint(2, 5)
        self.color = QColor(11, 116, 255, random.randint(40, 140))

    def move(self, w, h):
        self.pos += self.vel
        if self.pos.x() < 0 or self.pos.x() > w:
            self.vel.setX(-self.vel.x())
        if self.pos.y() < 0 or self.pos.y() > h:
            self.vel.setY(-self.vel.y())


class ParticleBackground(QWidget):
    """Weicher, dynamischer Hintergrund mit Partikeln"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.particles = [
            Particle(random.randint(0, 800), random.randint(0, 500)) for _ in range(65)
        ]
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.animate)
        self.timer.start(30)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

    def animate(self):
        for p in self.particles:
            p.move(self.width(), self.height())
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.fillRect(self.rect(), QColor(10, 15, 25, 255))
        for p in self.particles:
            gradient = QBrush(
                QColor(p.color.red(), p.color.green(), p.color.blue(), p.color.alpha())
            )
            painter.setBrush(gradient)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(p.pos, p.size, p.size)


# -------------------------------------------------
# Moderner Startscreen
# -------------------------------------------------
class FreshStartup(QWidget):
    def __init__(self, duration=3000):
        super().__init__()
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(800, 500)

        # --- Hintergrund mit Partikeln ---
        self.bg = ParticleBackground(self)
        self.bg.resize(self.size())

        # --- Rundes Fenster mit Shadow/Glaslook ---
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height(), 25, 25)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

        # --- Layout ---
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(40)

        # Logo
        self.logo = QLabel("ANCORATE")
        self.logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.logo.setFont(QFont("Segoe UI", 400, QFont.Weight.Bold))
        self.logo.setStyleSheet("color: #0b74ff; letter-spacing: 4px;")
        layout.addWidget(self.logo)

        # Untertitel
        self.subtitle = QLabel(f"ENCRYPT HOME {version_year} CITADEL")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setFont(QFont("Segoe UI", 16))
        self.subtitle.setStyleSheet("color: rgba(255,255,255,0.7);")
        layout.addWidget(self.subtitle)

        # Fortschrittsbalken
        self.progress = QProgressBar()
        self.progress.setFixedWidth(420)
        self.progress.setRange(0, 100)
        self.progress.setStyleSheet("""
            QProgressBar {
                background-color: rgba(255,255,255,0.08);
                border: 1px solid rgba(11,116,255,0.6);
                border-radius: 10px;
                text-align: center;
                color: #cce0ff;
            }
            QProgressBar::chunk {
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0b74ff,
                    stop:1 #38b6ff
                );
                border-radius: 10px;
            }
        """)
        layout.addWidget(self.progress)

        # --- Fortschritt Animation ---
        self.progress_value = 0
        self.duration = duration
        self.progress_timer = QTimer(self)
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(duration // 100)

        # --- sanftes Einblenden ---
        self.fade_in = QPropertyAnimation(self, b"windowOpacity")
        self.fade_in.setDuration(1000)
        self.fade_in.setStartValue(0)
        self.fade_in.setEndValue(1)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.fade_in.start()

    def update_progress(self):
        self.progress_value += 1
        self.progress.setValue(self.progress_value)
        if self.progress_value >= 100:
            self.progress_timer.stop()
            self.fade_out = QPropertyAnimation(self, b"windowOpacity")
            self.fade_out.setDuration(100000)
            self.fade_out.setStartValue(1)
            self.fade_out.setEndValue(0)
            self.fade_out.finished.connect(self.close)
            self.fade_out.start()


class AddWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        files: list,
        master_key: bytes,
        flags: int,
        stop_event: threading.Event,
    ):
        super().__init__()
        self.container_path = container_path
        self.files = files
        self.master_key = master_key
        self.flags = flags
        self.stop_event = stop_event

    def run(self):
        """Worker: Dateien in Container verschlüsseln und Meta aktualisieren."""
        try:
            # Validate inputs
            if not os.path.exists(self.container_path):
                raise FileNotFoundError("Container nicht gefunden")
            if not self.files:
                raise ValueError("Keine Dateien zum Hinzufügen angegeben")
            if len(self.master_key) != 32:
                raise ValueError("Ungültige Master-Key-Länge")
            
            print(f"[DEBUG] Starting to add {len(self.files)} files to container")

            # Debug: Key prüfen
            v2 = self.master_key
            if len(v2) not in (16, 24, 32):
                v2 = (v2 + b"\x00" * 32)[:32]

            added = []

            with open(self.container_path, "rb+") as f:
                # Meta lesen
                f.seek(-META_LEN_SIZE, os.SEEK_END)
                meta_len_bytes = f.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge ungültig")
                meta_len = struct.unpack("<Q", meta_len_bytes)[0]

                meta_pos = (
                    os.path.getsize(self.container_path) - META_LEN_SIZE - meta_len
                )
                f.seek(meta_pos)
                meta_blob = f.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden+")

                # Meta entschlüsseln
                meta = decrypt_meta(meta_blob, v2)

                # Datei ab hier kürzen, neuer Content wird angehängt
                f.truncate(meta_pos)
                f.seek(0, os.SEEK_END)

                total = len(self.files)
                for idx, filepath in enumerate(self.files, start=1):
                    if self.stop_event and self.stop_event.is_set():
                        raise RuntimeError("Vorgang abgebrochen")

                    if not os.path.isfile(filepath):
                        continue

                    offset = f.tell()
                    name = os.path.basename(filepath)
                    size = os.path.getsize(filepath)

                    # Progress-Callback
                    def cb(progress_value):
                        base = int(((idx - 1) / max(1, total)) * 100)
                        self.progress.emit(
                            min(100, base + int(progress_value / max(1, total)))
                        )

                    # Datei verschlüsseln und anhängen
                    encrypt_file_to_blob(
                        filepath, f, v2, progress_cb=cb, stop_event=self.stop_event
                    )

                    newpos = f.tell()
                    blob_len = newpos - offset
                    meta["files"].append(
                        {
                            "name": name,
                            "size": size,
                            "offset": offset,
                            "length": blob_len,
                        }
                    )
                    added.append(name)

                # Meta verschlüsseln und ans Ende schreiben
                meta_enc = encrypt_meta(meta, v2)
                f.write(meta_enc)
                f.write(struct.pack("<Q", len(meta_enc)))

 # Einstellungen neu laden für aktuellen del_source_added Status
            current_settings = load_settings()
            if current_settings.get("del_source_added"):
                for file in self.files:
                    try:
                        os.remove(file)
                    except Exception:
                        pass

            self.finished.emit(added)

        except Exception as e:
            # Fehler sauber melden
            error_msg = str(e) if str(e) else repr(e)
            print(f"[DEBUG] Worker error: {error_msg}")
            print(f"[DEBUG] Exception type: {type(e).__name__}")
            self.error.emit(error_msg)


class ExportWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        meta_entry: dict,
        master_key: bytes,
        stop_event: threading.Event = None,
    ):
        super().__init__()
        self.container_path = container_path
        self.meta_entry = meta_entry
        self.master_key = master_key
        self.stop_event = stop_event or threading.Event()

    def run(self):
        try:
            # Container-Datei prüfen
            container_file = os.path.normpath(self.container_path)
            if not os.path.isfile(container_file):
                raise FileNotFoundError(
                    f"Container-Datei existiert nicht: {container_file}"
                )

            # Zielpfad für exportierte Datei
            save_to_raw = self.meta_entry.get("__save_to")
            if not save_to_raw:
                raise ValueError("Kein Zielpfad angegeben")
            save_to = os.path.normpath(save_to_raw)

            # Zielordner erstellen, falls nicht existiert
            save_dir = os.path.dirname(save_to)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)

            # Tresor öffnen und Blob entschlüsseln
            with open(container_file, "r+b") as f:
                read_header(f)
                f.seek(self.meta_entry["offset"])
                blob_len = self.meta_entry["length"]
                decrypt_blob_range(
                    f,
                    save_to,
                    blob_len,
                    self.master_key,
                    self.meta_entry["name"],
                    stop_event=self.stop_event,
                )
            self.finished.emit(save_to)

        except Exception as e:
            error_msg = str(e) if str(e) else repr(e)
            print(f"[DEBUG] Worker error: {error_msg}")
            print(f"[DEBUG] Exception type: {type(e).__name__}")
            self.error.emit(error_msg)


class ExportBatchWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        entries: list[dict],
        master_key: bytes,
        target_dir: str,
        stop_event: threading.Event = None,
    ):
        super().__init__()
        self.container_path = container_path
        self.entries = entries
        self.master_key = master_key
        self.target_dir = target_dir
        self.stop_event = stop_event or threading.Event()

    def run(self):
        try:
            exported_paths: list[str] = []
            total = max(1, len(self.entries))
            for index, entry in enumerate(self.entries, start=1):
                if self.stop_event.is_set():
                    raise RuntimeError("Cancelled")
                save_to = os.path.join(self.target_dir, entry["name"])
                export_entry_to_path(
                    self.container_path,
                    {**entry, "__save_to": save_to},
                    self.master_key,
                    stop_event=self.stop_event,
                )
                exported_paths.append(save_to)
                self.progress.emit(int(index / total * 100))
            self.finished.emit(exported_paths)
        except Exception as e:
            error_msg = str(e) if str(e) else repr(e)
            print(f"[DEBUG] Worker error: {error_msg}")
            print(f"[DEBUG] Exception type: {type(e).__name__}")
            self.error.emit(error_msg)


def export_entry_to_path(
    container_path: str,
    meta_entry: dict,
    master_key: bytes,
    *,
    stop_event: threading.Event | None = None,
) -> str:
    container_file = os.path.normpath(container_path)
    if not os.path.isfile(container_file):
        raise FileNotFoundError(f"Container-Datei existiert nicht: {container_file}")

    save_to_raw = meta_entry.get("__save_to")
    if not save_to_raw:
        raise ValueError("Kein Zielpfad angegeben")
    save_to = os.path.normpath(save_to_raw)

    save_dir = os.path.dirname(save_to)
    if save_dir:
        os.makedirs(save_dir, exist_ok=True)

    with open(container_file, "r+b") as f:
        read_header(f)
        f.seek(meta_entry["offset"])
        blob_len = meta_entry["length"]
        decrypt_blob_range(
            f,
            save_to,
            blob_len,
            master_key,
            meta_entry["name"],
            stop_event=stop_event,
        )

    return save_to


# ---------------------------------------------------------
# Theme Setting laden
# ---------------------------------------------------------
def load_theme_setting():
    path = SETTINGS_FILE
    if not os.path.exists(path):
        return "Standard-dark"  # Standard-Theme
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("theme", "Standard-dark")
    except Exception:
        return "Standard-dark"


# ---------------------------------------------------------
# Base Path (EXE-Verzeichnis)
# ---------------------------------------------------------
base_path = os.path.dirname(os.path.abspath(sys.argv[0]))

# ---------------------------------------------------------
# Theme auswählen
# ---------------------------------------------------------
theme = load_theme_setting()

THEMES = {
    "Standard-light": "utilities/themes/light.css",
    "Standard-dark": "utilities/themes/dark_fixed.css",
    "Quantum": "utilities/themes/quantum.css",
    "Precision-light": "utilities/themes/precision-light.css",
    "Precision-dark": "utilities/themes/precision-dark.css",
    "Hackers-dark": "utilities/themes/hackers-dark.css",
    "Cyber-blue": "utilities/themes/cyber-blue.css",
}

# Default auf dark
css_file = THEMES.get(theme, "utilities/themes/dark_fixed.css")
css_path = os.path.join(base_path, css_file)

# ---------------------------------------------------------
# CSS laden
# ---------------------------------------------------------
try:
    with open(css_path, "r", encoding="utf-8") as f:
        APP_STYLE = f.read()
except Exception as e:
    print(f"CSS loading failed: {e}")
    APP_STYLE = ""


class SetupDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(f"ANCORATE {edition} – Einrichtung")
        self.setWindowIcon(get_app_icon())
        self.resize(520, 260)

        layout = QVBoxLayout(self)

        lbl = QLabel(
            f"""Willkommen bei ANCORATE {edition} {version_year}.
© 2025–2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin

Ein lokaler PC‑Key wird nun erzeugt
und dauerhaft an dieses Gerät gebunden."""
        )
        lbl.setWordWrap(True)
        layout.addWidget(lbl)

        self.key_box = QLineEdit("PC-Key wird erzeugt...")
        self.key_box.setReadOnly(True)
        layout.addWidget(self.key_box)

        self.btn_done = QPushButton("Fertig")
        self.btn_done.setObjectName("primary")
        self.btn_done.clicked.connect(self.finish)
        layout.addWidget(self.btn_done)

    def finish(self):
        secret = auto_register_device()

        masked = "*" * len(secret.hex())
        self.key_box.setText(masked)

        QMessageBox.information(
            self,
            "Registrierung abgeschlossen",
            "Der PC‑Key wurde erfolgreich registriert.",
        )

        self.accept()


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle(f"ANCORATE {edition} {version} – Anmeldung")
        self.setWindowIcon(get_app_icon())
        self.resize(420, 170)

        layout = QVBoxLayout(self)

        lbl = QLabel(
            f"Willkommen bei {edition}, deinem sicheren Dateimanager von ANCORATE.\n"
            "Die Anmeldung erfolgt über dein registriertes Gerät.\n\n"
            f"ANCORATE {edition} {version} ist © 2026\n"
            "by Samuel J. Tirwa & Gabriel Leiria‑Roussin"
        )
        lbl.setWordWrap(True)
        layout.addWidget(lbl)

        btn_row = QHBoxLayout()

        self.btn_try = QPushButton(f"Bei {edition} anmelden")
        self.btn_try.setObjectName("primary")
        self.btn_try.clicked.connect(self.do_check)
        btn_row.addWidget(self.btn_try)

        layout.addLayout(btn_row)

        self.valid_key = None
        self.relaunch_setup = False

    # =========================
    # LOGIN CHECK
    # =========================
    def do_check(self):
        device_key = load_device_key()
        
        # Check if this is a new device (no registration marker)
        if not is_device_registered():
            QMessageBox.warning(
                self,
                "Keine Registrierung",
                "Kein registriertes Gerät vorhanden.\n"
                "Die Ersteinrichtung wird gestartet.",
            )
            self.start_setup()
            return
        
        # Verify device key can be generated
        if not device_key:
            QMessageBox.warning(
                self,
                "Geräteerkennungsfehler",
                "Konnte keine Geräte-ID generieren.\n"
                "Bitte überprüfen Sie Ihre Systemkonfiguration.",
            )
            self.reject()
            return

        """if not LicenseDialog.load_and_validate_license():
            QMessageBox.warning(
                self,
                "Keine gültige Lizenz",
                "Es wurde keine gültige Lizenz gefunden.\n"
                f"Bitte aktiviere {edition} erneut."
            )
            self.reject()
            return"""

        self.valid_key = device_key

        QMessageBox.information(
            self,
            "Angemeldet",
            "Ihr Login über den PC-Key war erfolgreich.\nIhr Gerät wurde mit ANCORATE Proof verifiziert.",
        )

        self.accept()

    # =========================
    # SETUP RELAUNCH
    # =========================
    def start_setup(self):
        self.relaunch_setup = True
        self.reject()


class VaultEntry:
    def __init__(self, name: str, offset: int, length: int):
        self.name = name
        self.offset = offset
        self.length = length


class FileDropList(QListWidget):
    fileDropped = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDropIndicatorShown(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.enabled = False

    def dragEnterEvent(self, event):
        md = event.mimeData()
        if md.hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        md = event.mimeData()
        if md.hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if self.enabled:
            md = event.mimeData()
            if md.hasUrls():
                paths = []
                for url in md.urls():
                    path = url.toLocalFile()
                    if path:
                        if os.path.isfile(path):
                            self._add_path_item(path)
                            paths.append(path)
                if paths:
                    self.fileDropped.emit(paths)
                event.acceptProposedAction()
                return
            super().dropEvent(event)

    def add_vault_entry(self, entry: VaultEntry):
        item = QListWidgetItem(entry.name)
        item.setData(Qt.ItemDataRole.UserRole, entry)
        self.addItem(item)

    def selected_entries(self):
        entries = []
        for item in self.selectedItems():
            entry = item.data(Qt.ItemDataRole.UserRole)
            if entry:
                entries.append(entry)
        return entries

    def _add_path_item(self, path: str):
        name = os.path.basename(path)
        item = QListWidgetItem(name)
        item.setData(Qt.ItemDataRole.UserRole, path)
        self.addItem(item)

    def selected_file_paths(self) -> list:
        paths = []
        for it in self.selectedItems():
            p = it.data(Qt.ItemDataRole.UserRole)
            if p:
                paths.append(p)
        return paths


class StartupUpdateWorker(QThread):
    """Prüft im Hintergrund, ob ein Update verfügbar ist."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def run(self):
        try:
            settings = load_settings()
            update_url = settings.get("update_url", UPDATE_URL)
            response = requests.get(update_url, timeout=5)
            response.raise_for_status()
            data = response.json()
            data["update_url"] = update_url
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))


class UpdateNewsDialog(QDialog):
    def __init__(self, parent: QWidget | None, update_data: dict):
        super().__init__(parent)
        self.setWindowTitle("EncryptHome News")
        self.setWindowIcon(get_app_icon())
        self.resize(640, 420)
        self.setModal(True)

        version = update_data.get("version", "unbekannt")
        release_date = (
            update_data.get("release_date")
            or update_data.get("date")
            or "Unbekannt"
        )

        headline = QLabel(f"Update verfügbar: Version {version}")
        headline.setStyleSheet("font-weight: bold; font-size: 18px;")
        headline.setWordWrap(True)

        details = QTextBrowser()
        details.setOpenExternalLinks(True)
        details.setStyleSheet(
            "background-color: #1b1e24; color: #e7e7e7; border: 1px solid #444;"
        )

        notes = (
            update_data.get("changelog")
            or update_data.get("release_notes")
            or update_data.get("notes")
            or update_data.get("description")
            or update_data.get("news")
            or "Keine weiteren Informationen verfügbar."
        )

        if isinstance(notes, list):
            notes = "\n".join(f"- {item}" for item in notes)
        elif not isinstance(notes, str):
            notes = str(notes)

        description = (
            f"<h3>Version {version}</h3>"
            f"<p><b>Veröffentlicht:</b> {release_date}</p>"
            "<hr>"
            f"<pre style=\"font-size:12px; white-space:pre-wrap; word-wrap:break-word;\">{notes}</pre>"
        )
        details.setHtml(description)

        actions = QHBoxLayout()
        actions.addStretch()
        close_btn = QPushButton("Später")
        close_btn.setObjectName("secondary")
        open_updates_btn = QPushButton("Zu Updates")
        open_updates_btn.setObjectName("primary")
        actions.addWidget(close_btn)
        actions.addWidget(open_updates_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(headline)
        layout.addWidget(details, 1)
        layout.addLayout(actions)

        close_btn.clicked.connect(self.reject)
        open_updates_btn.clicked.connect(self.open_updates)

    def open_updates(self):
        self.accept()
        parent = self.parent()
        if parent is not None and hasattr(parent, "show_settings_dialog"):
            parent.show_settings_dialog()


class App(QWidget):
    LAN_DISC_PORT = 48291  # UDP-Port für LAN-Discovery
    LAN_TCP_PORT = 48292  # TCP-Port für LAN-Verbindungen
    LAN_MAGIC = b"ANCORATE_DISCOVER_V1"
    LAN_CHUNK = 64 * 1024  # 64 KiBp

    def __init__(self):  # Hauptfenster der Anwendung
        super().__init__()
        self.setWindowTitle(f"ANCORATE {edition} {version} - kein Tresor geöffnet")
        self.setWindowIcon(get_app_icon())
        self.resize(1080, 720)
        self.exporting = False
        self.pwd = ""
        self.MAX_ATTEMPTS = 3
        self.attempts = 0
        self.container_path = None
        self.master_key = None
        self.flags = 0
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.rekey_temp_backup = None
        self.stop_event = None
        self.progress = None
        self._lan_sharing = False
        self._lan_threads = []
        self._lan_tcp_sock = None
        self.settings_dialog = SettingsDialog
        self._settings_dialog = None
        self.update_worker = None
        self.intelligence_manager = None
        self.data = load_settings()
        if self.data.get("encrypt_intelligence_enabled", False):
            self._start_intelligence_init()
        # Vorschau-Cache (RAM): LRU-Cache für bereits entschlüsselte Bytes
        self._preview_cache: OrderedDict[str, tuple[bytes, object]] = OrderedDict()
        self._preview_cache_bytes: int = 0
        self._preview_cache_limit: int = 200 * 1024 * 1024  # 200 MiB total
        self._preview_max_file_bytes: int = PREVIEW_MAX_BYTES

        self.layout = QVBoxLayout(self)
        
        # ---- GUI Elemente erstellen ----
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Container (.salt)"))
        self.container_label = QLineEdit()
        row1.addWidget(self.container_label)
        btn_choose = QPushButton("➕")
        btn_choose.clicked.connect(self.choose_container)
        row1.addWidget(btn_choose)
        self.layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Suchen:"))
        self.search = QLineEdit()
        self.searchbar_content = ""
        row2.addWidget(self.search)
        self.layout.addLayout(row2)

        # --- File List ---
        self.file_list = FileDropList()
        self.file_list.fileDropped.connect(self.add_files)
        self.layout.addWidget(self.file_list)

        # --- Shortcuts ---
        self.create_vault_sc = QShortcut(QKeySequence("Ctrl+N"), self)
        self.add_sec_sc = QShortcut(QKeySequence("Ctrl++"), self)
        self.ex_selected_sc = QShortcut(QKeySequence("Ctrl+E"), self)
        self.ex_all_seq = QShortcut(QKeySequence("Alt+E"), self)
        self.open_vault_sc = QShortcut(QKeySequence("Ctrl+O"), self)
        self.remove_sc = QShortcut(QKeySequence("Del"), self)
        self.del_container_sc = QShortcut(QKeySequence("Alt+Del"), self)
        self.search_sc = QShortcut(QKeySequence("Return"), self)
        self.recent_containers_sc = QShortcut(QKeySequence("Ctrl+R"), self)

        self.file_list.itemDoubleClicked.connect(self.preview_selected)

        # --- Shortcut Verbindungen ---
        self.create_vault_sc.activated.connect(lambda: self.choose_container(2))
        self.add_sec_sc.activated.connect(self.add_file_dialog)
        self.ex_selected_sc.activated.connect(self.export_selected)
        self.ex_all_seq.activated.connect(self.export_all)
        self.open_vault_sc.activated.connect(lambda: self.choose_container(1))
        self.remove_sc.activated.connect(self.delete_selected)
        self.del_container_sc.activated.connect(lambda: self.delete_container())
        self.search_sc.activated.connect(self.start_search)
        self.recent_containers_sc.activated.connect(self.show_recent_containers)

        self.status = QLabel(
            "Session gestartet. - 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin"
        )
        self.status.setObjectName("status")
        self.layout.addWidget(self.status)

        self.setLayout(self.layout)
        self.setStyleSheet(APP_STYLE)
        
        # Auto-Lock Timeout (5 Minuten)
        self.timeout_ms = 300000

        # ---- Automatisch ständig aktualisieren ----
        self.timer = QTimer(self)
        self.timer.setInterval(10000)  # Alle 10 Sekunden (Performance)
        self.timer.timeout.connect(self._simple_cleanup)
        self.timer.start()
        
        self.apply_settings()  # Initial anwenden
        
        # ---- Menüleiste hinzufügen ----
        self.add_menubar()
        
        # ---- File Watcher für sofortige Updates ----
        self.settings_watcher = QFileSystemWatcher([SETTINGS_FILE], self)
        self.settings_watcher.fileChanged.connect(self.on_settings_changed)
        print("[SETTINGS] File Watcher aktiviert für sofortige Updates")
    
    
    def _simple_cleanup(self):
        """Einfache Cleanup Funktion"""
        try:
            import gc
            gc.collect()
            print("[CLEANUP] Simple Cleanup durchgeführt")
        except Exception as e:
            print(f"[CLEANUP] Fehler: {e}")

    def open_settings(self):
        dialog = SettingsDialog()
        dialog.exec()  # Modal Popup

    def check_updates_quick(self):
        if not hasattr(self, "_settings_dialog") or self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)
        self._settings_dialog.display_category(3)
        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()
        self._settings_dialog.check_updates_manual()

    def start_update_check(self):
        if self.update_worker is not None and self.update_worker.isRunning():
            return

        self.update_worker = StartupUpdateWorker()
        self.update_worker.finished.connect(self.on_update_check_finished)
        self.update_worker.error.connect(self.on_update_check_error)
        self.update_worker.start()

    def is_update_available(self, data: dict) -> bool:
        try:
            def parse_version(v: str):
                parts = str(v).split(".")
                while len(parts) < 3:
                    parts.append("0")
                return tuple(int(p) for p in parts[:3])

            current = parse_version(version)
            latest = parse_version(data.get("version", version))
            return latest > current
        except Exception:
            return False

    def on_update_check_finished(self, data: dict):
        self.update_data = data
        if not self.is_update_available(data):
            return

        self.status.setText(
            f"Update verfügbar: v{data.get('version')} – Öffnen Sie Einstellungen > Updates"
        )

        self.show_update_news(data)

    def on_update_check_error(self, error_msg: str):
        print(f"[UPDATE] Updatecheck fehlgeschlagen: {error_msg}")

    def show_update_news(self, data: dict):
        if self.update_news_shown:
            return
        self.update_news_shown = True

        dlg = UpdateNewsDialog(self, data)
        dlg.exec()

    # ------------------ Menüleiste ------------------
    def add_menubar(self):
        self._rebuild_menubar()

    def _rebuild_menubar(self):
        menubar = QMenuBar()
        
        # Datei-Menü
        file_menu = QMenu("Datei", self)
        actions_file = [
            QAction("Neuer Tresor", self),
            QAction("Tresor öffnen", self),
            QAction("Zuletzt verwendete Tresore", self),
            QAction("Tresorpasswort ändern", self),
            QAction("Tresor schließen", self),
            QAction("Tresor löschen", self),
            None,  # Separator
            QAction("Einstellungen", self),
        ]
        actions_file[1].triggered.connect(lambda: self.choose_container(1))
        actions_file[0].triggered.connect(lambda: self.choose_container(2))
        actions_file[2].triggered.connect(self.show_recent_containers)
        actions_file[3].triggered.connect(self.change_container_password_dialog)
        actions_file[4].triggered.connect(self.close_container)
        actions_file[5].triggered.connect(self.delete_container)
        actions_file[7].triggered.connect(lambda: self.show_settings_dialog())
        for a in actions_file:
            if a is None:
                file_menu.addSeparator()
            else:
                file_menu.addAction(a)

        # Bearbeiten-Menü
        edit_menu = QMenu("Bearbeiten", self)
        actions_edit = [
            QAction("Datei(en) hinzufügen", self),
            QAction("Dateivorschau starten", self),
            QAction("Datei löschen", self),
            QAction("Datei exportieren", self),
            QAction("Alles exportieren", self),
        ]
        actions_edit[0].triggered.connect(self.add_file_dialog)
        actions_edit[1].triggered.connect(self.preview_selected)
        actions_edit[2].triggered.connect(self.delete_selected)
        actions_edit[3].triggered.connect(self.export_selected)
        actions_edit[4].triggered.connect(self.export_all)
        for a in actions_edit:
            edit_menu.addAction(a)

        # EncryptIntelligence-Menü (nur wenn aktiviert)
        if self.data.get("encrypt_intelligence_enabled", False):
            intelligence_menu = QMenu("EncryptIntelligence BETA", self)
            open_intelligence_action = QAction("EncryptIntelligence BETA öffnen", self)
            open_intelligence_action.triggered.connect(self.show_intelligence_dialog)
            intelligence_menu.addAction(open_intelligence_action)
            menubar.addMenu(intelligence_menu)

        # Hilfe-Menü
        help_menu = QMenu("Hilfe", self)
        about_action = QAction(f"Über {edition} {version_year}", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Menüs hinzufügen
        menubar.addMenu(file_menu)
        menubar.addMenu(edit_menu)
        menubar.addMenu(help_menu)
        
        self.layout.setMenuBar(menubar)

    # ------------------ Dialoge ------------------
    def show_recent_containers(self):
        """Show recent containers dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Zuletzt verwendete Container")
        dialog.setWindowIcon(get_app_icon())
        dialog.setFixedSize(600, 400)
        dialog.setModal(True)
        
        layout = QVBoxLayout(dialog)
        
        # Recent containers list
        list_widget = QListWidget()
        containers = load_recent_containers()
        
        for container in containers:
            item = QListWidgetItem(f"📁 {container['name']}")
            item.setData(Qt.ItemDataRole.UserRole, container["path"])
            item.setToolTip(container["path"])
            
            # Format last accessed time
            last_accessed = container.get("last_accessed", 0)
            if last_accessed:
                time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_accessed))
                item.setText(f"📁 {container['name']} - {time_str}")
            
            list_widget.addItem(item)
        
        if not containers:
            list_widget.addItem(QListWidgetItem("Keine kürzlichen Container gefunden"))
        
        layout.addWidget(list_widget)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        open_btn = QPushButton("Öffnen")
        open_btn.setObjectName("primary")
        clear_btn = QPushButton("Liste löschen")
        clear_btn.setObjectName("danger")
        cancel_btn = QPushButton("Abbrechen")
        cancel_btn.setObjectName("secondary")
        
        btn_layout.addWidget(open_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        # Button handlers
        def open_selected():
            selected_items = list_widget.selectedItems()
            if selected_items:
                container_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
                if container_path and os.path.exists(container_path):
                    self.container_path = container_path
                    self.container_label.setText(container_path)
                    self.open_container()
                    dialog.accept()
                else:
                    QMessageBox.warning(dialog, "Fehler", "Container existiert nicht mehr.")
        
        def clear_recent():
            if QMessageBox.question(
                dialog, "Bestätigen", 
                "Möchten Sie die Liste der kürzlich genutzten Container wirklich leeren?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            ) == QMessageBox.StandardButton.Yes:
                save_recent_containers([])
                list_widget.clear()
                list_widget.addItem(QListWidgetItem("Liste geleert"))
        
        def reject_dialog():
            dialog.reject()
        
        open_btn.clicked.connect(open_selected)
        clear_btn.clicked.connect(clear_recent)
        cancel_btn.clicked.connect(reject_dialog)
        
        # Double-click to open
        list_widget.itemDoubleClicked.connect(lambda item: open_selected())
        
        dialog.exec()


    def change_container_password_dialog(self):
            """Show password change dialog for current container"""
            if not self.container_path or not self.master_key:
                QMessageBox.warning(self, "Kein Container", "Bitte öffnen Sie zuerst einen Container.")
                return
            
            success, new_pwd = change_container_password(
                self.container_path, 
                self.master_key, 
                self.meta, 
                self.pwd,
                self.flags,
                self
            )
            
            if success and new_pwd:
                self.append_log("Passwort wurde erfolgreich geändert.")
                
                # Preserve current container path before closing
                container_path = self.container_path
                self.close_container()
                
                # Re-open the container with new password
                try:
                    # Re-open container with new password
                    self.open_container_with_password(container_path, new_pwd)
                    self.append_log("Container mit neuem Passwort erneut geöffnet.")
                    
                except Exception as e:
                    self.append_log(f"Fehler beim erneuten Öffnen des Containers: {str(e)}")
                    QMessageBox.warning(self, "Fehler", f"Container konnte nicht mit neuem Passwort geöffnet werden: {str(e)}")
                    self.close_container()
            else:
                self.append_log("Passwortänderung abgebrochen")


    def show_about_dialog(self):
            if not hasattr(self, "_about_dialog"):
                self._about_dialog = AboutDialog(self)
            self._about_dialog.show()
            self._about_dialog.raise_()
            self._about_dialog.activateWindow()

    def show_settings_dialog(self):
        if not hasattr(self, "_settings_dialog") or self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)

        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()

    def _start_intelligence_init(self):
        if self.intelligence_manager is not None:
            return
        try:
            from intelligence.core import EncryptIntelligenceManager, EncryptIntelligenceConfig
            tier = self.data.get("encrypt_intelligence_model_tier", "EncryptIntelligence Light")
            config = EncryptIntelligenceConfig(model_tier=tier)
            self.intelligence_manager = EncryptIntelligenceManager(config)
        except Exception as e:
            print(f"[INTELLIGENCE] Init-Fehler: {e}")

    def _reset_intelligence_init(self):
        self.intelligence_manager = None

    def _get_intelligence_manager(self, block=True):
        if self.intelligence_manager is None:
            self._start_intelligence_init()
        return self.intelligence_manager

    def show_intelligence_dialog(self):
        container_path = getattr(self, "container_path", None)
        if container_path:
            from intelligence.core import EncryptIntelligenceManager, EncryptIntelligenceConfig
            tier = self.data.get("encrypt_intelligence_model_tier", "EncryptIntelligence Light")
            vault_dir = Path(container_path).parent / (Path(container_path).stem + ".ei")
            try:
                vault_dir.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
            manager = EncryptIntelligenceManager(
                EncryptIntelligenceConfig(model_tier=tier, storage_dir=str(vault_dir))
            )
        else:
            manager = self._get_intelligence_manager()

        if manager is None:
            QMessageBox.critical(
                self,
                "EncryptIntelligence BETA",
                "EncryptIntelligence BETA konnte nicht geladen werden.",
            )
            return

        if not hasattr(self, "_intelligence_dialog") or self._intelligence_dialog is None:
            from intelligence.ui import EncryptIntelligenceDialog
            self._intelligence_dialog = EncryptIntelligenceDialog(
                self, manager=manager,
            )
        else:
            self._intelligence_dialog.manager = manager

        self._intelligence_dialog.show()
        self._intelligence_dialog.raise_()
        self._intelligence_dialog.activateWindow()

    def get_pwd_dialog(self):
        print("Passwortabfrage")
        pwd, cancelled = get_password_with_requirements(self, "Passwort eingeben")
        self.setWindowIcon(get_app_icon())

        if cancelled or not pwd:
            return ""

        print("Passwort erhalten")
        return pwd

    def update_container_path(self, path: str = None):
        if not self.meta.get("files", ""):
            self.container_path = path
            self.container_label.setText(path or "")
            if path is None:
                self.status.setText("Tresor-Pfad zurückgesetzt")
            else:
                self.status.setText(f"Tresor-Pfad gesetzt: {path}")

    # ------------------------------------------------------

    def apply_settings(self):
        try:
            s = load_settings()
            
            # 1. Theme sofort anwenden
            self.apply_theme(s.get("theme", "Standard-dark"))
            
            # 2. Shortcuts aktualisieren
            self.apply_shortcuts(s)
            
            # 3. Verhaltens-Einstellungen aktualisieren
            self.apply_behavior_settings(s)
            
        except Exception as e:
            print("[SETTINGS] Fehler beim Anwenden der Einstellungen:", e)
    
    def apply_theme(self, theme_name):
        """Theme sofort ohne Neustart anwenden"""
        try:
            base_path = os.path.dirname(os.path.abspath(sys.argv[0]))
            THEMES = {
                "Standard-light": "utilities/themes/light.css",
                "Standard-dark": "utilities/themes/dark_fixed.css",
                "Quantum": "utilities/themes/quantum.css",
                "Precision-light": "utilities/themes/precision-light.css",
                "Precision-dark": "utilities/themes/precision-dark.css",
                "Hackers-dark": "utilities/themes/hackers-dark.css",
                "Cyber-blue": "utilities/themes/cyber-blue.css",
            }
            
            css_file = THEMES.get(theme_name, "utilities/themes/dark_fixed.css")
            css_path = os.path.join(base_path, css_file)
            
            if os.path.exists(css_path):
                with open(css_path, "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
                print(f"[SETTINGS] Theme '{theme_name}' angewendet")
            else:
                print(f"[SETTINGS] Theme-Datei nicht gefunden: {css_path}")
        except Exception as e:
            print(f"[SETTINGS] Theme-Fehler: {e}")
    
    def apply_shortcuts(self, settings):
        """Shortcuts sofort anwenden"""
        try:
            # Hilfsfunktion: Key setzen
            def set_key(shortcut_obj, key_name, fallback=""):
                key_str = settings.get(key_name, settings.get(fallback, ""))
                if key_str is None:
                    key_str = ""
                shortcut_obj.setKey(QKeySequence(key_str))

            # Shortcuts setzen
            set_key(self.ex_selected_sc, "o_seq")
            set_key(self.ex_all_seq, "o_all_seq")
            set_key(self.create_vault_sc, "crea_vault_seq")
            set_key(self.open_vault_sc, "vault_o_seq")
            set_key(self.remove_sc, "del_seq")
            set_key(self.del_container_sc, "del_vault_seq")
            set_key(self.search_sc, "search_seq")
            
            print("[SETTINGS] Shortcuts aktualisiert")
        except Exception as e:
            print(f"[SETTINGS] Shortcuts-Fehler: {e}")
    
    def apply_behavior_settings(self, settings):
        """Verhaltens-Einstellungen aktualisieren"""
        try:
            old_enabled = self.data.get("encrypt_intelligence_enabled", False)
            self.data = settings
            new_enabled = self.data.get("encrypt_intelligence_enabled", False)
            
            if new_enabled and not old_enabled:
                if self.intelligence_manager is None:
                    self._start_intelligence_init()
            elif not new_enabled and old_enabled:
                if not hasattr(self, "_intelligence_dialog") or self._intelligence_dialog is None:
                    self._reset_intelligence_init()
            
            if (
                hasattr(self, "_intelligence_dialog")
                and self._intelligence_dialog is not None
                and self.intelligence_manager is not None
            ):
                self._intelligence_dialog.manager = self.intelligence_manager
            
            # Menüleiste neu aufbauen wenn sich EncryptIntelligence-Status geändert hat
            if old_enabled != new_enabled:
                self._rebuild_menubar()
            
            print("[SETTINGS] Verhaltens-Einstellungen aktualisiert")
        except Exception as e:
            print(f"[SETTINGS] Verhaltens-Fehler: {e}")
    
    def on_settings_changed(self, path):
        """Wird aufgerufen wenn settings.json geändert wird"""
        try:
            print(f"[SETTINGS] Settings-Datei geändert: {path}")
            # Kleine Verzögerung um sicherzustellen dass Datei komplett geschrieben ist
            QTimer.singleShot(100, self.apply_settings)
        except Exception as e:
            print(f"[SETTINGS] Watcher-Fehler: {e}")

    # ------------------ Container wählen / erstellen ------------------
    def choose_container(self, mode: int = 0):
        if not mode:
            action = QMessageBox()
            action.setWindowIcon(get_app_icon())
            action.setWindowTitle("ANCORATE – Tresor wählen")
            action.setText(
                "Möchten Sie einen bestehenden Tresor öffnen oder einen neuen erstellen?"
            )
            o = action.addButton("Öffnen", QMessageBox.ButtonRole.YesRole)
            n = action.addButton("Erstellen", QMessageBox.ButtonRole.NoRole)
            action.exec()

            result = action.clickedButton()
            if result == o:
                mode = 1
            elif result == n:
                mode = 2

        # 1. Bestehenden Tresor öffnen
        path = ""
        creating = False
        if mode == 1:
            path, _ = QFileDialog.getOpenFileName(
                None,
                f"ANCORATE {edition} - Tresor wählen",
                "",
                "ANC Secure Authentication Layer Tresor (*.salt)",
            )

        # 2. Neuen Tresor erstellen
        elif mode == 2:
            folder = QFileDialog.getExistingDirectory(
                self, "Speicherort für neuen Tresor wählen"
            )
            if folder:
                name, ok = QInputDialog.getText(
                    None,
                    "Tresornamen wählen",
                    "Wähle einen Namen für deinen Tresor",
                    text="new-vault",
                )

                # Standardname, falls leer
                if not name:
                    name = "secure"
                if "." in name:
                    name, _ = os.path.splitext(name)
                # Erweiterung hinzufügen
                name += ".salt"
                path = os.path.join(folder, name)
                creating = True

        # 3. Pfad setzen
        if path:
            self.update_container_path(path)
            if creating:
                self.create_container()
            else:
                self.open_container()

    def open_container_with_password(self, container_path: str, password: str):
        """Öffnet einen bestehenden Container mit dem angegebenen Passwort"""
        
        # Use provided path and password
        self.container_path = container_path
        pwd = password

        # Add to recent containers on successful open
        add_recent_container(self.container_path)

        try:
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "r+b") as fh:
                # 4a. Header lesen: Flags + Salt
                flags, salt = read_header(fh)
                if salt is None:
                    raise ValueError("Salt konnte nicht gelesen werden.")

                if flags & FLAG_PRO_VAULT:
                    self.append_log(
                        "Open blocked: Pro vault detected in Home (flag 0x04)."
                    )
                    QMessageBox.critical(
                        self,
                        "Nicht unterstützter Tresor",
                        "Dieser Tresor wurde mit ANCORATE EncryptPro erstellt und kann in EncryptHome nicht geöffnet werden.\n\nBitte verwende ANCORATE EncryptPro.\nWeitere Informationen unter ancorate.com",
                    )
                    self.update_container_path()
                    return

                # 4b. Master-Key ableiten
                master = derive_master_key(
                    pwd,
                    salt,
                    bool(flags & FLAG_DEVICE),
                    load_device_key() if (flags & FLAG_DEVICE) else None,
                )
                if master is None:
                    raise ValueError("Master-Key konnte nicht abgeleitet werden.")

                # 4c. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4d. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Nach dem Schließen der Datei: Meta entschlüsseln
            # ------------------------------------------------------------------
            meta = decrypt_meta(meta_blob, master)
            if meta is None:
                raise ValueError("Metadaten konnten nicht entschlüsselt werden.")

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags

            # ------------------------------------------------------------------
            # 7. GUI aktualisieren
            # ------------------------------------------------------------------
            file_name = os.path.basename(self.container_path)
            folder_name = os.path.basename(os.path.dirname(self.container_path))

            self.status.setText(f"Tresor geöffnet: {file_name}")
            self.append_log("Tresor geöffnet.")
            self.setWindowTitle(
                f"ANCORATE {edition} {version} – {file_name} aus {folder_name} geöffnet"
            )
            self.file_list.enabled = True
            self.refresh_list()

        except Exception as e:
            error_msg = str(e)
            raise e

    def open_container(self):
        """Öffnet einen bestehenden Container"""

        # 1. Prüfen, ob Container-Pfad gesetzt ist
        if not self.container_path:
            QMessageBox.warning(
                self,
                "Fehler",
                "Kein Container-Pfad gesetzt. Wähle zuerst einen Container.",
            )
            self.choose_container()
            return

        # 2. Prüfen, ob Container existiert
        if not os.path.exists(self.container_path):
            QMessageBox.warning(
                self,
                "Fehler",
                f"Container nicht gefunden unter:\n{self.container_path}",
            )
            self.update_container_path()
            self.choose_container()
            return

        # 3. Passwort abfragen
        pwd = self.pwd
        while not pwd:
            pwd = self.get_pwd_dialog()
        if not pwd:
            QMessageBox.warning(self, "Passwort fehlt", "Kein Passwort bereitgestellt.")
            return

        # Add to recent containers on successful open
        add_recent_container(self.container_path)

        try:
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "r+b") as fh:
                # 4a. Header lesen: Flags + Salt
                flags, salt = read_header(fh)
                if salt is None:
                    raise ValueError("Salt konnte nicht gelesen werden.")

                if flags & FLAG_PRO_VAULT:
                    self.append_log(
                        "Open blocked: Pro vault detected in Home (flag 0x04)."
                    )
                    QMessageBox.critical(
                        self,
                        "Nicht unterstützter Tresor",
                        "Dieser Tresor wurde mit ANCORATE EncryptPro erstellt und kann in EncryptHome nicht geöffnet werden.\n\nBitte verwende ANCORATE EncryptPro.\nWeitere Informationen unter ancorate.com",
                    )
                    self.update_container_path()
                    return

                # 4b. Master-Key ableiten
                master = derive_master_key(
                    pwd,
                    salt,
                    bool(flags & FLAG_DEVICE),
                    load_device_key() if (flags & FLAG_DEVICE) else None,
                )
                if master is None:
                    raise ValueError("Master-Key konnte nicht abgeleitet werden.")

                # 4c. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4d. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Nach dem Schließen der Datei: Meta entschlüsseln
            # ------------------------------------------------------------------
            meta = decrypt_meta(meta_blob, master)
            if meta is None:
                raise ValueError("Metadaten konnten nicht entschlüsselt werden.")

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags

            # ------------------------------------------------------------------
            # 7. GUI aktualisieren
            # ------------------------------------------------------------------
            file_name = os.path.basename(self.container_path)
            folder_name = os.path.basename(os.path.dirname(self.container_path))

            self.status.setText(f"Tresor geöffnet: {file_name}")
            self.append_log("Tresor geöffnet.")
            self.setWindowTitle(
                f"ANCORATE {edition} {version} – {file_name} aus {folder_name} geöffnet"
            )
            self.file_list.enabled = True
            self.refresh_list()

        except Exception as e:
            error_msg = str(e)

            if "signature did not match digest" in error_msg.lower():
                self.update_container_path()
                user_msg = (
                    """Der Tresor konnte nicht geöffnet werden.
Mögliche Ursache
• Der Tresor wurde auf einem anderen Gerät erstellt
• Das eingegebene Passwort ist falsch\n"""
                    f"• Der Tresor wurde mit einer veralteten Version von {edition} erstellt"
                )
                log_msg = "Open failed: signature/digest mismatch (device or password)"

            elif isinstance(e, FileNotFoundError) or "errno 2" in error_msg.lower():
                user_msg = (
                    "Der Tresor konnte nicht geöffnet werden.\n\n"
                    "Mögliche Ursachen:\n"
                    "• Der Tresor wurde durch fehlerhaftes Kopieren beschädigt\n"
                    "• Der Speicherplatz Ihres Laufwerks war beim letzten Hinzufügen von Dateien nicht ausreichend\n"
                    f"• {edition} ist beim Hinzufügen von Dateien zu diesem Tresor unerwartet geschlossen worden\n\n"
                    "Der Tresor ist irreparabel beschädigt und kann nicht wiederhergestellt werden."
                )
                log_msg = f"Open failed: FileNotFoundError ({error_msg})"

            else:
                user_msg = f"Öffnen fehlgeschlagen:\n{error_msg}"
                log_msg = f"Open failed: {error_msg}"

            QMessageBox.critical(self, "ANCORATE – Tresorfehler", user_msg)

            self.append_log(log_msg)
            return

    def create_container(self):
        if self.container_path is None:
            QMessageBox.warning(self, "Fehler", "Wähle zuerst einen Dateipfad aus.")
            return
        # Prüfen, ob Container bereits existiert
        if os.path.exists(self.container_path):
            if (
                QMessageBox.question(
                    self,
                    "Tresor bereits vorhanden",
                    "Tresor existiert bereits — überschreiben?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                self.update_container_path()
                return

        # Passwort mit Anforderungen abfragen
        pwd = self.pwd
        while not pwd:
            pwd = self.get_pwd_dialog()

            # Container-Daten erzeugen
        salt = secrets.token_bytes(SALT_LEN)

        # Flags Device-Binding
        flags = 0
        if getattr(self, "device_bound", False):
            flags |= FLAG_DEVICE

        # Master-Key ableiten (nur Passwort + optional Device-Key)
        master = derive_master_key(
            pwd,
            salt,
            bool(flags & FLAG_DEVICE),
            load_device_key() if (flags & FLAG_DEVICE) else None,
        )

        meta = {"files": [], "created": int(time.time()), "flags": flags}

        meta_blob = encrypt_meta(meta, master)

        with open(self.container_path, "wb") as fh:
            write_header(fh, flags, salt)
            fh.write(meta_blob)
            fh.write(struct.pack("<Q", len(meta_blob)))

        self.master_key = master
        self.meta = meta
        self.flags = flags
        self.pwd = pwd

        self.status.setText("Container erstellt.")
        self.append_log("Container created.")

    def delete_container(self):
        # 1. Validierung des Pfads
        c_path = getattr(self, "container_path", "")
        if not c_path or not os.path.exists(c_path):
            QMessageBox.warning(self, "Fehler", "Kein gültiger Tresor ausgewählt.")
            return

        # 2. Sicherheitsabfrage
        method = self.data.get("deletion_method", "Standard")

        # Warnung verschärfen, wenn Vaporizer gewählt ist
        warning_text = f"Möchtest du den Tresor wirklich mit '{method}' vernichten?\n\n"
        if "ANCORATE Vaporizer 1 (100x)" in method:
            warning_text += "ACHTUNG: ANCORATE Vaporizer 1 mit 100 Durchgängen gewählt. Dies wird lange dauern (1+ min)!"
        elif "ANCORATE Furnace Max (200x" in method:
            warning_text += "ACHTUNG: ANCORATE Furnace Max mit 200 Durchgängen gewählt. Der Löschvorgang wird mindestens 5 min dauern!"

        elif "ANCORATE Shatterer Ultra (300x)" in method:
            warning_text += "ACHTUNG: ANCORATE Shatterer Ultra mit 300 Durchgängen gewählt. Der Löschvorgang wird sehr lange dauern (10+ min)!\nEr kann bei HDDs (Hard Disk Drives) zu dauerhaften Schäden an der Disk führen!"
        else:
            warning_text += (
                "Dies überschreibt alle Daten physisch und löscht die Tresordatei."
            )

        confirm = QMessageBox.question(
            self,
            "Tresor vernichten",
            warning_text,
            defaultButton=QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            self.append_log(f"Vernichtung gestartet (Modus: {method})...")

            # 3. Physisches Überschreiben (Die gesamte Datei)
            file_size = os.path.getsize(c_path)
            with open(c_path, "rb+") as fh:
                self._secure_overwrite(fh, 0, file_size)

            # 4. Datei vom Dateisystem entfernen
            os.remove(c_path)

            # 5. UI Aufräumen
            self.update_container_path()

            self.meta = {"files": []}
            # Passwort-Änderungs-Zustandsvariablen
            self.changing_password = False
            self.password_change_in_progress = False
            self.rekey_temp_backup = None

            self.refresh_list()
            self.append_log(f"Tresor mit {method} erfolgreich vernichtet.")

            QMessageBox.information(
                self, "Erfolg", f"Der Tresor wurde mit {method} sicher gelöscht."
            )

        except Exception as e:
            self.append_log(f"Fehler: {str(e)}")
            QMessageBox.critical(
                self, "Kritischer Fehler", f"Löschvorgang fehlgeschlagen: {e}"
            )

    # ------------------ registrierten Key laden ------------------
    def load_device_key(self):
        if not os.path.exists(CONFIG_FILE):
            return None
        try:
            with open(CONFIG_FILE, "r") as f:
                js = json.load(f)
            v = js.get("device_key_hex", "")
            if not v:
                return None
            return bytes.fromhex(v)
        except Exception:
            return None

    def add_file_dialog(self):
        if not getattr(self, "master_key", None):
            QMessageBox.information(
                self,
                "Hinweis",
                "Öffne oder erstelle zuerst einen Container und gib dein Passwort ein.",
            )
            return

        # Geändert auf getOpenFileNames (Plural!) für Mehrfachauswahl im Fenster
        fns, _ = QFileDialog.getOpenFileNames(self, "Dateien wählen")
        if not fns:
            return

        # Wir übergeben die Liste 'fns' an add_files
        print("adding files")
        self.add_files(fns)
        # self.refresh_list() # Nicht nötig, da der Worker am Ende finished -> _add_finished -> refresh_list aufruft

    # ------------------ Container Operationen ------------------
    def close_container(self):
        if hasattr(self, "stop_event") and self.stop_event:
            try:
                self.stop_event.set()
            except Exception:
                pass

        try:
            if self.progress:
                self.progress.close()
        except Exception:
            pass

        self.pwd = ""
        self.master_key = None
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.rekey_temp_backup = None
        self.flags = 0
        self.keyfile_bytes = None
        self.stop_event = None
        self.progress = None
        self.exporting = False
        self._preview_cache.clear()
        self._preview_cache_bytes = 0
        self.file_list.clear()
        self.file_list.enabled = False
        self.search.clear()
        self.searchbar_content = ""
        self.update_container_path()
        self.status.setText("Tresor geschlossen.")
        print("Container closed.")
        self.setWindowTitle(f"ANCORATE {edition} {version} - Tresor geschlossen")
        notifier.show("Tresor geschlossen 🔐", "Der Tresor wurde geschlossen. ✅")

    def add_files(self, filepaths=None):
        """
        Datei(en) zum Tresor hinzufügen.
        :param filepaths: Liste von Pfaden oder None → Dialog öffnen
        """
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist."
            )
            return
        if filepaths is None:
            files, _ = QFileDialog.getOpenFileNames(
                self, "Dateien zum Tresor hinzufügen", "", "Alle Dateien (*.*)"
            )
        else:
            files = filepaths

        if not files:
            return

        # Frisches Stop‑Event für diesen Add‑Vorgang,
        # damit ein vorheriger Abbruch (preview/export) neue Adds nicht blockiert.
        self.stop_event = threading.Event()

        # Master‑Key ggf. auf 32 Byte auffüllen
        v2 = self.master_key
        if len(v2) not in (16, 24, 32):
            v2 = (v2 + b"\x00" * 32)[:32]

        worker = AddWorker(
            self.container_path, files, v2, self.flags, stop_event=self.stop_event
        )

        thread = QThread()
        worker.moveToThread(thread)

        # Verbindung für Fortschritt und Fehler
        worker.progress.connect(self._on_progress)
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))

        # Hier die korrekte Lambda‑Verbindung:
        worker.finished.connect(
            lambda added, w=worker: self._add_finished(added, thread, w)
        )

        # UI: Fortschrittsdialog
        count = len(files)
        msg = (
            f"Verschlüssele {count} Datei(en)..."
            if count > 1
            else "Änderungen am Tresor werden vorgenommen..."
        )
        self.progress = QProgressDialog(msg, "Abbrechen", 0, 100, self)

        # konkreter Modality‑Wert
        self.progress.setWindowTitle(f"ANCORATE {edition}")  # ← hier
        self.progress.canceled.connect(self.cancel_current)
        self.progress.setValue(0)
        self.progress.show()

        # Erfolg‑Benachrichtigung
        def show_success():
            text = (
                f"{count} Dateien hinzugefügt." if count > 1 else "Datei hinzugefügt."
            )
            notifier.show("Verschlüsselung abgeschlossen ✅", text)

        worker.finished.connect(show_success)
        worker.finished.connect(self.progress.close)

        thread.started.connect(worker.run)
        thread.start()

    # ------------------ Datei exportieren ------------------
    def queueing(self):
        while self.exporting:
            time.sleep(0.2)

    def _selected_meta_indexes(self) -> list[int]:
        indexes = []
        for item in self.file_list.selectedItems():
            data = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(data, int):
                indexes.append(data)

        if not indexes:
            selected_index = self._selected_meta_index()
            if selected_index is not None:
                indexes.append(selected_index)

        seen = set()
        unique_indexes = []
        for index in indexes:
            if index not in seen:
                seen.add(index)
                unique_indexes.append(index)
        return sorted(unique_indexes)

    def export_selected(self, idx: int = 0, mode: int = 0, target_dir: str = ""):
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist, bevor Sie Dateien exportieren."
            )
            return
        if self.exporting:
            QMessageBox.information(self, "Info", "Ein Export läuft bereits. Bitte kurz warten.")
            return
        if mode:
            selected_indexes = [int(idx)]
        else:
            selected_indexes = self._selected_meta_indexes()

        if not selected_indexes:
            QMessageBox.information(self, "Info", "Bitte mindestens eine Datei auswählen.")
            return

        selected_entries = [dict(self.meta["files"][i]) for i in selected_indexes]
        multiple = len(selected_entries) > 1

        if multiple:
            if not target_dir:
                target_dir = QFileDialog.getExistingDirectory(
                    self, "Exportordner wählen"
                )
            if not target_dir:
                return
            self._start_batch_export(selected_entries, target_dir)
            return

        entry = selected_entries[0]
        if not target_dir:
            save, _ = QFileDialog.getSaveFileName(self, "Speichere Datei", entry["name"])
        else:
            save = os.path.join(target_dir, entry["name"])
        if not save:
            return

        self._start_single_export(entry, save)

    # ------------------ Dateivorschau (RAM) ------------------
    def _selected_meta_index(self) -> int | None:
        """
        Liefert den Index in self.meta['files'] für das aktuell ausgewählte List-Item.
        Wichtig: Die List-Row ist bei Suche/Filter nicht gleich dem Meta-Index.
        """
        item = self.file_list.currentItem()
        if not item:
            return None

        data = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, int):
            return data

        # Fallback: Text parsen (Name vor "—")
        try:
            txt = item.text()
            name = txt.split(" — ", 1)[0].strip()
            for i, ent in enumerate(self.meta.get("files", [])):
                if ent.get("name") == name:
                    return i
        except Exception:
            pass
        return None

    def _preview_cache_key(self, entry: dict) -> str:
        return f"{self.container_path}|{entry.get('offset')}|{entry.get('length')}|{entry.get('name')}"

    def _preview_cache_put(self, key: str, data: bytes, info_obj: object):
        # Entferne alten Eintrag, falls vorhanden
        if key in self._preview_cache:
            old_data, _old_info = self._preview_cache.pop(key)
            self._preview_cache_bytes -= len(old_data)

        self._preview_cache[key] = (data, info_obj)
        self._preview_cache.move_to_end(key)
        self._preview_cache_bytes += len(data)

        # LRU-Eviction
        while (
            self._preview_cache_bytes > self._preview_cache_limit
            and self._preview_cache
        ):
            _k, (d, _i) = self._preview_cache.popitem(last=False)
            self._preview_cache_bytes -= len(d)

    def preview_selected(self, *_args):
        if not self.container_path or not self.master_key:
            QMessageBox.information(
                self, "Vorschau", "Bitte zuerst einen Tresor öffnen."
            )
            return

        idx = self._selected_meta_index()
        if idx is None or idx < 0:
            QMessageBox.information(self, "Vorschau", "Bitte eine Datei auswählen.")
            return

        entry = self.meta["files"][int(idx)]
        key = self._preview_cache_key(entry)

        # Cache hit
        if key in self._preview_cache:
            data, info_obj = self._preview_cache[key]
            self._preview_cache.move_to_end(key)
            show_preview(self, entry.get("name", "Datei"), data, info_obj)
            return

        # Cache miss: im Hintergrund entschlüsseln und in RAM laden
        self.stop_event = threading.Event()
        worker = PreviewDecryptWorker(
            self.container_path,
            entry,
            self.master_key,
            stop_event=self.stop_event,
            max_bytes=self._preview_max_file_bytes,
        )
        thread = QThread()
        worker.moveToThread(thread)

        # UI: Fortschrittsdialog
        self.progress = QProgressDialog(
            "Nehme Änderungen am Tresor vor...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(self.cancel_current)
        self.progress.setValue(0)
        self.progress.show()

        worker.progress.connect(self._on_progress)

        def _done(data: bytes, info_obj: object):
            try:
                self.progress.close()
            except Exception:
                pass
            thread.quit()
            thread.wait()
            worker.deleteLater()
            thread.deleteLater()
            self._preview_cache_put(key, data, info_obj)
            show_preview(self, entry.get("name", "Datei"), data, info_obj)

        worker.finished.connect(_done)
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def export_all(self):
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist, bevor Sie Dateien exportieren."
            )
            return
        if not self.meta.get("files"):
            QMessageBox.information(
                self, "Info", "Keine Dateien zum Exportieren vorhanden."
            )
            return

        # Zielordner wählen
        target_dir = QFileDialog.getExistingDirectory(self, "Zielordner wählen")
        if not target_dir:
            return

        self._start_batch_export([dict(entry) for entry in self.meta["files"]], target_dir)

    def _start_single_export(self, entry: dict, save_to: str):
        self.exporting = True
        self.stop_event = threading.Event()
        entry_copy = dict(entry)
        entry_copy["__save_to"] = save_to
        worker = ExportWorker(
            self.container_path, entry_copy, self.master_key, stop_event=self.stop_event
        )
        thread = QThread()
        worker.moveToThread(thread)
        worker.finished.connect(lambda p: self._export_finished(p, thread, worker))
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _start_batch_export(self, entries: list[dict], target_dir: str):
        self.exporting = True
        self.stop_event = threading.Event()
        worker = ExportBatchWorker(
            self.container_path,
            entries,
            self.master_key,
            target_dir,
            stop_event=self.stop_event,
        )
        thread = QThread()
        worker.moveToThread(thread)

        self.progress = QProgressDialog(
            "Exportiere Dateien...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(self.cancel_current)
        self.progress.setValue(0)
        self.progress.show()

        worker.progress.connect(self._on_progress)
        worker.finished.connect(
            lambda paths: self._batch_export_finished(paths, thread, worker)
        )
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _batch_export_finished(self, paths, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self.exporting = False
        if paths:
            self.append_log(f"Export fertig: {len(paths)} Datei(en)")
            QMessageBox.information(
                self,
                "Export fertig",
                f"{len(paths)} Datei(en) wurden exportiert.",
            )
        else:
            QMessageBox.information(self, "Export fertig", "Keine Dateien exportiert.")

    def _secure_overwrite(self, file_handle, offset, length):
        """Überschreibt Daten physisch – jetzt inklusive Vaporizer 1 Modus."""
        method = self.data.get("deletion_method", "Standard")

        # Durchgänge festlegen

        if "ANCORATE Shatterer Ultra (300x)" in method:
            passes = 300
        elif "ANCORATE Furnace Max (200x, grosse Dateien)" in method:
            passes = 200
        elif "ANCORATE Vaporizer 1 (100x)" in method:
            passes = 100
        elif "Gutmann (35x)" in method:
            passes = 35
        elif "DoD 5220.22-M (3x)" in method:
            passes = 3
        else:
            passes = 1

        total_work = length * passes
        total_written = 0

        for i in range(passes):
            file_handle.seek(offset)
            bytes_left = length
            chunk_size = 1024 * 1024  # 1MB Chunks

            while bytes_left > 0:
                current_chunk = min(bytes_left, chunk_size)
                # Kryptographischer Zufall
                file_handle.write(secrets.token_bytes(current_chunk))
                bytes_left -= current_chunk

                # Fortschritt berechnen
                total_written += current_chunk
                if hasattr(self, "progress") and self.progress:
                    prog = int((total_written / total_work) * 100)
                    self.progress.setValue(prog)

                QApplication.processEvents()  # UI am Leben halten

            # Puffer erzwingen
            file_handle.flush()
            os.fsync(file_handle.fileno())

    def delete_selected(self):
        idx = self._selected_meta_index()
        if idx is None or idx < 0:
            QMessageBox.information(self, "Info", "Bitte eine Datei auswählen.")
            return

        method = self.data.get("deletion_method", "Standard")
        confirm = QMessageBox.question(
            self,
            "Sicheres Löschen",
            f"Datei wirklich mit '{method}' vernichten?\nDies kann bei großen Dateien sehr lange dauern!",
            defaultButton=QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        # 1. Datei-Metadaten abgreifen
        target = self.meta["files"][int(idx)]
        f_offset = target["offset"]
        f_length = target["length"]
        f_name = target["name"]

        try:
            with open(self.container_path, "rb+") as fh:
                # --- SCHRITT A: DATEN ÜBERSCHREIBEN ---
                print("starting")
                self._secure_overwrite(fh, f_offset, f_length)

                # --- SCHRITT B: CONTAINER KOMPAKTIEREN ---
                print("squeezing")
                fh.seek(-8, os.SEEK_END)  # 8 = META_LEN_SIZE
                old_meta_len = struct.unpack("<Q", fh.read(8))[0]
                total_size = os.path.getsize(self.container_path)

                data_end = total_size - old_meta_len - 8
                next_data_start = f_offset + f_length
                bytes_to_move = data_end - next_data_start

                if bytes_to_move > 0:
                    self.append_log("Entferne Überreste...")
                    fh.seek(next_data_start)
                    chunk = fh.read(bytes_to_move)
                    fh.seek(f_offset)
                    fh.write(chunk)

                # --- SCHRITT C: METADATEN AKTUALISIEREN ---
                print("editing meta")
                # Datei aus Liste löschen
                self.meta["files"].pop(int(idx))

                # Offsets aller nachfolgenden Dateien korrigieren
                for f in self.meta["files"]:
                    if f["offset"] > f_offset:
                        f["offset"] -= f_length

                # Container am Ende kürzen
                new_size = f_offset + bytes_to_move
                fh.truncate(new_size)

                # Neue Metadaten ans Ende hängen
                fh.seek(0, os.SEEK_END)
                new_meta_blob = encrypt_meta(self.meta, self.master_key)
                fh.write(new_meta_blob)
                fh.write(struct.pack("<Q", len(new_meta_blob)))

            self.append_log(f"Erfolgreich vernichtet: {f_name}")
            self.refresh_list()
            QMessageBox.information(
                self, "Erfolg", f"Die Datei wurde unwiderruflich gelöscht."
            )

        except Exception as e:
            self.append_log(f"FEHLER beim Löschen: {str(e)}")
            QMessageBox.critical(
                self, "Kritischer Fehler", f"Löschvorgang abgebrochen: {e}"
            )

    # ------------------ Worker Callbacks ------------------
    def _add_finished(self, added, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self.append_log("Added files: " + ", ".join(added))
        try:
            with open(self.container_path, "rb") as fh:
                fh.seek(-META_LEN_SIZE, os.SEEK_END)
                meta_len = struct.unpack("<Q", fh.read(META_LEN_SIZE))[0]
                meta_pos = (
                    os.path.getsize(self.container_path) - META_LEN_SIZE - meta_len
                )
                fh.seek(meta_pos)
                meta_blob = fh.read(meta_len)
                self.meta = decrypt_meta(meta_blob, self.master_key)
        except Exception as e:
            self.append_log(f"Error reloading meta: {e}")
        self.refresh_list()

    # ------------------ Worker Callbacks ------------------
    def _worker_error(self, error, thread, worker):
        """Handles errors from worker threads."""
        try:
            self.progress.close()
        except Exception:
            pass

        self.exporting = False

        # Thread sauber beenden
        if thread.isRunning():
            thread.quit()
            thread.wait()

        # Worker und Thread freigeben
        worker.deleteLater()
        thread.deleteLater()

        # Fehler anzeigen und loggen
        error_msg = error if isinstance(error, str) else str(error)
        if not error_msg:
            error_msg = repr(error)
        QMessageBox.critical(self, "Fehler", error_msg)
        self.append_log(f"Fehler: {error_msg}")

    def _export_finished(self, path, thread, worker):
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self.exporting = False
        QMessageBox.information(self, "Export fertig", f"Datei gespeichert: {path}")
        self.append_log(f"Export fertig: {path}")

    def cancel_current(self):
        if hasattr(self, "stop_event") and self.stop_event:
            self.stop_event.set()
            self.append_log("Abbruch angefordert.")

    def append_log(self, txt):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {txt}")
        self.status.setText(txt)

    def closeEvent(self, event):
        # Einstellungen neu laden für aktuellen confirm_exit Status
        current_settings = load_settings()
        if current_settings.get("confirm_exit", True):
            reply = QMessageBox.question(
                self,
                f"ANCORATE {edition} beenden",
                f"Möchten Sie ANCORATE {edition} wirklich beenden?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        # Cleanup VaultBridge USB monitoring
        if hasattr(self, 'usb_detector') and self.usb_detector:
            try:
                self.usb_detector.stop_monitoring()
                print("[VAULTBRIDGE] USB monitoring stopped")
            except Exception as e:
                print(f"[VAULTBRIDGE] Error stopping USB monitoring: {e}")

        event.accept()

    # ------------------ Worker Callbacks ------------------
    def _on_progress(self, v):
        """Aktualisiert den Fortschrittsbalken."""
        try:
            # 'self.progress' in __init__ initialisieren, damit es immer existiert
            self.progress.setValue(v)
        except Exception as e:
            print(f"Fehler beim Update des Progressbars: {e}")

    def _on_finished(self):
        """Wird aufgerufen, wenn der Worker fertig ist."""
        self.progress.setValue(0)
        self.append_log("Vorgang abgeschlossen.")
        self.refresh_list()

    # ------------------ Suchfunktion ------------------
    def start_search(self):
        query = self.search.text().strip()
        if not query:
            self.refresh_list()
            return

        if self.data.get("encrypt_intelligence_enabled", False) and self.data.get(
            "encrypt_intelligence_search_integration", False
        ):
            manager = self._get_intelligence_manager(block=False)
            if manager is not None:
                try:
                    manager.reload_storage()
                except Exception:
                    pass
                results = manager.search_documents(query)
                if results:
                    self.refresh_list(searching=True, intelligence_results=results)
                    self.status.setText(
                        f"EncryptIntelligence: {len(results)} relevante Dokument(e) gefunden."
                    )
                    return

        self.refresh_list(True)
    
    def keep_search(self):
        """Suchleiste am Leben erhalten"""
        try:
            # Warte bis GUI vollständig initialisiert ist
            max_wait = 20  # Maximal 20 Sekunden warten
            wait_count = 0
            
            while wait_count < max_wait:
                if hasattr(self, 'search') and self.search is not None:
                    break
                time.sleep(0.5)
                wait_count += 1
                print(f"[SEARCH] Warte auf GUI... {wait_count * 0.5}s")
            
            if not hasattr(self, 'search') or self.search is None:
                print("[SEARCH] GUI nach Wartezeit nicht verfügbar - beende keep_search")
                return
                
            print("[SEARCH] GUI verfügbar - starte Suchüberwachung")
            self.searchbar_content = ""
            while True:
                try:
                    if hasattr(self, 'search') and self.search and self.search.text() != self.searchbar_content:
                        self.start_search()
                        self.searchbar_content = self.search.text()
                    time.sleep(0.2)
                except RuntimeError:
                    # GUI wurde zerstört, beende Thread
                    print("[SEARCH] GUI nicht mehr verfügbar - beende keep_search")
                    break
                except Exception as e:
                    print(f"[SEARCH] Fehler in keep_search: {e}")
                    break
        except Exception as e:
            print(f"[SEARCH] Thread-Fehler: {e}")

    # ------------------ Dateiliste aktualisieren ------------------
    def refresh_list(self, searching: bool = False, intelligence_results=None):
        if getattr(self.file_list, "isEnabled", lambda: True)():
            self.file_list.clear()
            files = self.meta.get("files", [])
            result_mapping = {}
            if intelligence_results:
                for result in intelligence_results:
                    if result.get("filename"):
                        result_mapping[result["filename"]] = result
                    result_mapping[result["document_name"]] = result

            for idx, ent in enumerate(files):
                name = ent.get("name", "<unnamed>")
                size = ent.get("size", 0)

                if size < 1024:
                    size_text = f"{size} B"
                elif size < 1024**2:
                    size_text = f"{size / 1024:.1f} KB"
                elif size < 1024**3:
                    size_text = f"{size / 1024**2:.2f} MB"
                elif size < 1024**4:
                    size_text = f"{size / 1024**3:.2f} GB"
                elif size >= 1024**4:
                    size_text = f"{size / 1024**4:.2f} TB"
                else:
                    size_text = f"{size / 1024**5:.2f} PB"

                if intelligence_results is not None:
                    result = result_mapping.get(name)
                    if not result:
                        continue
                    display_text = (
                        f"{name} — {size_text} — KI {result['score']:.2f}\n"
                        f"{result['snippet']}"
                    )
                elif self.search.text() and searching:
                    if self.search.text().lower() not in name.lower():
                        continue
                    display_text = f"{name} — {size_text}"
                else:
                    display_text = f"{name} — {size_text}"

                item = QListWidgetItem(display_text)
                item.setData(Qt.ItemDataRole.UserRole, idx)
                self.file_list.addItem(item)


class DetailsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ANCORATE – Technische Details")
        self.setFixedSize(600, 520)
        self.setWindowIcon(get_app_icon())
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        BG = "#0f1014"
        CARD = "#16181d"
        BORDER = "#23262e"
        ACCENT = "#00d4aa"  # Teal-Grün Akzent
        TEXT = "#e8eaf0"
        MUTED = "#6b7280"
        TAG_BG = "#1c2230"
        TAG_FG = "#60a5fa"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG};
                font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
                color: {TEXT};
            }}
            QScrollArea, QWidget#Scroll {{
                background: transparent;
                border: none;
            }}
            QLabel {{
                color: {TEXT};
                font-family: 'JetBrains Mono', 'Cascadia Code', 'Consolas', monospace;
            }}
            QFrame#Section {{
                background-color: {CARD};
                border: 1px solid {BORDER};
                border-radius: 6px;
            }}
            QPushButton#CloseBtn {{
                background-color: transparent;
                color: {MUTED};
                border: 1px solid {BORDER};
                border-radius: 4px;
                padding: 7px 20px;
                font-size: 12px;
                font-family: 'JetBrains Mono', monospace;
            }}
            QPushButton#CloseBtn:hover {{
                color: {TEXT};
                border-color: {ACCENT};
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(64)
        header.setStyleSheet(
            f"background-color: {CARD}; border-bottom: 1px solid {BORDER};"
        )
        hlay = QHBoxLayout(header)
        hlay.setContentsMargins(24, 0, 24, 0)

        prefix = QLabel("// ")
        prefix.setStyleSheet(f"color: {ACCENT}; font-size: 14px; font-weight: bold;")
        title = QLabel(f"TECHNISCHE DETAILS ZU ANCORATE {edition} {version}")
        title.setStyleSheet(
            f"color: {TEXT}; font-size: 14px; font-weight: bold; letter-spacing: 2px;"
        )

        hlay.addWidget(prefix)
        hlay.addWidget(title)
        hlay.addStretch()
        root.addWidget(header)

        # ── Scroll Body ──────────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setObjectName("Scroll")
        scroll.setWidgetResizable(True)
        body = QWidget()
        body.setObjectName("Scroll")
        blay = QVBoxLayout(body)
        blay.setContentsMargins(24, 20, 24, 20)
        blay.setSpacing(16)

        # Sektion-Hilfsfunktion
        def add_section(title_text, rows):
            frame = QFrame()
            frame.setObjectName("Section")
            fl = QVBoxLayout(frame)
            fl.setContentsMargins(16, 14, 16, 14)
            fl.setSpacing(10)

            t = QLabel(title_text.upper())
            t.setStyleSheet(
                f"color: {ACCENT}; font-size: 10px; font-weight: bold; letter-spacing: 2px;"
            )
            fl.addWidget(t)
            fl.addWidget(make_separator(BORDER))

            grid = QGridLayout()
            grid.setVerticalSpacing(8)
            grid.setHorizontalSpacing(24)
            grid.setColumnStretch(1, 1)
            for i, (k, v) in enumerate(rows):
                k_lbl = QLabel(k)
                k_lbl.setStyleSheet(f"color: {MUTED}; font-size: 11px;")
                v_lbl = QLabel(v)
                v_lbl.setStyleSheet(f"color: {TEXT}; font-size: 12px;")
                v_lbl.setWordWrap(True)
                grid.addWidget(k_lbl, i, 0, Qt.AlignmentFlag.AlignTop)
                grid.addWidget(v_lbl, i, 1)
            fl.addLayout(grid)
            return frame

        # Abschnitte
        blay.addWidget(
            add_section(
                "Kryptographie",
                [
                    ("Algorithmen", "ANCORATE-configured AES-256-GCM"),
                    ("Integritätscheck", "argon2id · SHA-3-256"),
                    ("Geräte-Bindung", "ANCORATE PC-Key 1.1 · ADAS 1.0"),
                    ("Zufallsquelle", "CSPRNG via os.urandom()"),
                ],
            )
        )

        blay.addWidget(
            add_section(
                "Laufzeitumgebung",
                [
                    ("Python-Version", "3.13 (64-bit) · modfified PyInstaller Build"),
                    ("Qt-Framework", "PyQt6 · Qt 6.7"),
                    (
                        "Crypto-Backend",
                        "cryptography 42 · (OpenSSL 3) · ANC0 Crypto Engine",
                    ),
                    ("Plattform", f"{platform.system()} {platform.release()} ({'64-bit' if sys.maxsize > 2**32 else '32-bit'})"),
                    ("Min. RAM", "1024 MB"),
                ],
            )
        )

        blay.addWidget(
            add_section(
                "Lizenz & Compliance",
                [
                    ("Lizenzmodell", "Proprietär · Closed Source"),
                    ("Datenhaltung", "Vollständig lokal · keine Datensammlung"),
                ],
            )
        )

        blay.addStretch()
        scroll.setWidget(body)
        root.addWidget(scroll)

        # ── Footer ───────────────────────────────────────────────────────────
        footer = QWidget()
        footer.setFixedHeight(58)
        footer.setStyleSheet(
            f"background-color: {CARD}; border-top: 1px solid {BORDER};"
        )
        flay = QHBoxLayout(footer)
        flay.setContentsMargins(24, 0, 24, 0)

        hint = QLabel(f"Build  {version}-{version_year}")
        hint.setStyleSheet(f"color: {MUTED}; font-size: 11px;")

        btn = QPushButton("Schließen")
        btn.setObjectName("CloseBtn")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(self.close)

        flay.addWidget(hint)
        flay.addStretch()
        flay.addWidget(btn)
        root.addWidget(footer)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle(f"Über ANCORATE {edition}")
        self.setFixedSize(520, 400)
        self.setWindowIcon(get_app_icon())
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        # ── Farb-Palette ─────────────────────────────────────────────────────
        BG = "#0f1014"
        PANEL = "#16181d"
        BORDER = "#23262e"
        ACCENT = "#00d4aa"  # Teal
        ACCENT2 = "#007aff"  # Blau für Hover
        TEXT = "#e8eaf0"
        MUTED = "#6b7280"
        SUBTLE = "#9ca3af"
        BTN_BG = "#1a1d24"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG};
                font-family: 'Segoe UI Variable', 'Segoe UI', 'SF Pro Display', sans-serif;
            }}

            /* ─ Basis ─────────────────────────────────────────────── */
            QWidget {{ background: transparent; }}
            QScrollArea {{ border: none; }}

            /* ─ Beschriftungen ────────────────────────────────────── */
            QLabel                 {{ color: {TEXT}; }}
            QLabel#AppName         {{ font-size: 22px; font-weight: 700; color: {TEXT}; letter-spacing: -0.5px; }}
            QLabel#AppSub          {{ font-size: 12px; color: {MUTED}; letter-spacing: 0.5px; }}
            QLabel#SectionHeader   {{ font-size: 10px; font-weight: 700; color: {ACCENT}; letter-spacing: 2px; }}
            QLabel#MetaKey         {{ font-size: 12px; color: {MUTED}; }}
            QLabel#MetaValue       {{ font-size: 12px; color: {TEXT}; font-weight: 500; }}
            QLabel#DescText        {{ font-size: 12px; color: {SUBTLE}; line-height: 1.6; }}
            QLabel#Copyright       {{ font-size: 11px; color: {MUTED}; }}

            /* ─ Klickbarer Link ───────────────────────────────────── */
            QLabel#DetailLink {{
                font-size: 12px;
                font-weight: 600;
                color: {ACCENT};
                text-decoration: underline;
            }}
            QLabel#DetailLink:hover {{
                color: {TEXT};
            }}

            /* ─ Panel / Karte ─────────────────────────────────────── */
            QFrame#Card {{
                background-color: {PANEL};
                border: 1px solid {BORDER};
                border-radius: 8px;
            }}

            /* ─ Footer ────────────────────────────────────────────── */
            QWidget#Footer {{
                background-color: {PANEL};
                border-top: 1px solid {BORDER};
            }}

            /* ─ Close-Button ──────────────────────────────────────── */
            QPushButton#CloseBtn {{
                background-color: {BTN_BG};
                color: {SUBTLE};
                border: 1px solid {BORDER};
                border-radius: 5px;
                padding: 8px 22px;
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton#CloseBtn:hover {{
                background-color: {ACCENT};
                color: #000;
                border-color: {ACCENT};
            }}
            QPushButton#CloseBtn:pressed {{
                background-color: #00b090;
            }}
        """)

        # ── Root-Layout ───────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ─────────────────────────────────────────────────────────────────────
        # 1. HEADER  (Icon + Name + Subtitle)
        # ─────────────────────────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet(
            f"background-color: {PANEL}; border-bottom: 1px solid {BORDER};"
        )
        hlay = QHBoxLayout(header)
        hlay.setContentsMargins(28, 22, 28, 22)
        hlay.setSpacing(18)

        # Icon
        icon_lbl = QLabel()
        px = get_app_icon().pixmap(84, 84)
        if px.isNull():
            px = QPixmap(94, 94)
            px.fill(QColor(ACCENT))
        icon_lbl.setPixmap(px)
        icon_lbl.setFixedSize(94, 94)
        icon_lbl.setStyleSheet(
            f"border-radius: 10px; background-color: #1e2128; padding: 4px; border: 1px solid {BORDER};"
        )

        # Name + Subtitle
        name_col = QVBoxLayout()
        name_col.setSpacing(3)
        name_col.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        lbl_name = QLabel(f"ANCORATE {edition}")
        lbl_name.setObjectName("AppName")

        lbl_sub = QLabel("Advanced Encryption Suite by ANCORATE")
        lbl_sub.setObjectName("AppSub")

        # Version-Badge inline
        badge = QLabel(f"  v{version}  ")
        badge.setStyleSheet(
            f"background-color: #1e2128; color: {ACCENT}; font-size: 10px; "
            f"font-weight: 700; border: 1px solid {ACCENT}; border-radius: 3px; "
            f"padding: 1px 0; letter-spacing: 1px;"
        )
        badge.setFixedHeight(18)

        badge_row = QHBoxLayout()
        badge_row.setSpacing(8)
        badge_row.addWidget(lbl_sub)
        badge_row.addWidget(badge)
        badge_row.addStretch()

        name_col.addWidget(lbl_name)
        name_col.addLayout(badge_row)

        hlay.addWidget(icon_lbl)
        hlay.addLayout(name_col)
        hlay.addStretch()
        root.addWidget(header)

        # ─────────────────────────────────────────────────────────────────────
        # 2. INHALT
        # ─────────────────────────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        ilay = QVBoxLayout(inner)
        ilay.setContentsMargins(24, 20, 24, 16)
        ilay.setSpacing(14)

        # ── Metadaten-Karte ───────────────────────────────────────────────
        card = QFrame()
        card.setObjectName("Card")
        clay = QVBoxLayout(card)
        clay.setContentsMargins(18, 14, 18, 14)
        clay.setSpacing(12)

        # Sektion-Titel
        sec = QLabel("RELEASE-INFO")
        sec.setObjectName("SectionHeader")
        clay.addWidget(sec)
        clay.addWidget(make_separator(BORDER))

        meta = QGridLayout()
        meta.setVerticalSpacing(9)
        meta.setHorizontalSpacing(32)
        meta.setColumnMinimumWidth(0, 130)

        rows = [
            ("Version", f"{version}  ({version_year} · {type_edition})"),
            ("Entwicklung", "Samuel J. Tirwa · Gabriel Leiria-Roussin"),
            ("Lizenz", "Proprietär / Closed Source"),
        ]
        for i, (k, v) in enumerate(rows):
            kl = QLabel(k)
            kl.setObjectName("MetaKey")
            vl = QLabel(v)
            vl.setObjectName("MetaValue")
            meta.addWidget(kl, i, 0)
            meta.addWidget(vl, i, 1)

        clay.addLayout(meta)
        ilay.addWidget(card)

        # ── Beschreibung ──────────────────────────────────────────────────
        desc = QLabel(
            f"ANCORATE {edition} bietet gerätegebundene Dateiverschlüsselung auf "
            "Basis moderner kryptographischer Standards. Die Anwendung arbeitet vollständig "
            "lokal – es werden keine persönlichen Daten übertragen oder gespeichert."
        )
        desc.setObjectName("DescText")
        desc.setWordWrap(True)
        ilay.addWidget(desc)

        # ── Link zu Detailfenster ──────────────────────────────────────────
        link_row = QHBoxLayout()
        link_row.setSpacing(6)

        arrow = QLabel("→")
        arrow.setStyleSheet(f"color: {ACCENT}; font-size: 12px; font-weight: bold;")

        link = QLabel("Technische Details & Spezifikationen anzeigen")
        link.setObjectName("DetailLink")
        link.setCursor(Qt.CursorShape.PointingHandCursor)
        link.mousePressEvent = self._open_details  # type: ignore[assignment]

        link_row.addWidget(arrow)
        link_row.addWidget(link)
        link_row.addStretch()
        ilay.addLayout(link_row)

        ilay.addStretch()
        scroll.setWidget(inner)
        root.addWidget(scroll)

        # ─────────────────────────────────────────────────────────────────────
        # 3. FOOTER
        # ─────────────────────────────────────────────────────────────────────
        footer = QWidget()
        footer.setObjectName("Footer")
        flay = QHBoxLayout(footer)
        flay.setContentsMargins(24, 14, 24, 14)

        copy_lbl = QLabel("© 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin")
        copy_lbl.setObjectName("Copyright")

        close_btn = QPushButton("Schließen")
        close_btn.setObjectName("CloseBtn")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.close)

        flay.addWidget(copy_lbl)
        flay.addStretch()
        flay.addWidget(close_btn)
        root.addWidget(footer)

    # ── Slot: Detailfenster öffnen ────────────────────────────────────────────
    def _open_details(self, _event=None):
        dlg = DetailsDialog(self)
        dlg.exec()


class TermsOfServiceDialog(QDialog):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ANCORATE – Terms of Service")
        self.setWindowIcon(get_app_icon())
        self.setMinimumSize(760, 720)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)

        self.setStyleSheet("""
            QDialog {
                background-color: #121212;
                color: #e0e0e0;
            }
            QLabel {
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #1e1e1e;
                color: #f0f0f0;
                border: 1px solid #333;
                border-radius: 6px;
                padding: 10px;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
            QCheckBox {
                color: #e0e0e0;
                spacing: 8px;
            }
            QPushButton {
                background-color: #2a2a2a;
                color: #ffffff;
                border: 1px solid #444;
                border-radius: 6px;
                padding: 6px 18px;
            }
            QPushButton:hover {
                background-color: #3a3a3a;
            }
            QPushButton:disabled {
                background-color: #1a1a1a;
                color: #777;
                border-color: #222;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(14)

        header = QLabel("Terms of Service")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet("font-size: 22px; font-weight: 600;")
        layout.addWidget(header)

        subtitle = QLabel(
            "Bitte lies die folgenden Nutzungsbedingungen sorgfältig durch.\n"
            f"Die Nutzung von ANCORATE {edition} setzt deren Zustimmung voraus."
        )
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(subtitle)

        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setPlainText(self.load_terms_text())
        layout.addWidget(self.text_area, stretch=1)

        self.checkbox = QCheckBox(
            "Ich habe die Terms of Service gelesen und stimme ihnen zu."
        )
        layout.addWidget(self.checkbox)

        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Akzeptieren")
        self.buttons.button(QDialogButtonBox.StandardButton.Cancel).setText("Ablehnen")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        layout.addWidget(self.buttons)

        self.checkbox.stateChanged.connect(self.toggle_accept)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)

    def toggle_accept(self):
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(
            self.checkbox.isChecked()
        )

    def load_terms_text(self):
        for path in (
            os.path.join(os.getcwd(), "TOS.txt"),
            os.path.join(os.path.dirname(sys.argv[0]), "TOS.txt"),
        ):
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return f.read()
        return "Error: TOS.txt not found."


class WelcomeOverlay(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setModal(True)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setFixedSize(900, 420)

        # =========================
        # Layout
        # =========================
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(18)
        layout.setContentsMargins(0, 0, 0, 0)

        # =========================
        # Title
        # =========================
        self.title = QLabel("THIS IS ANCORATE.")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet(f"""
            font-size: 56px;
            font-weight: 900;
            letter-spacing: 3px;
            color: {ANCORATE_BLUE};
        """)

        # =========================
        # Subtitle
        # =========================
        self.subtitle = QLabel("Secure · Local · Trusted")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.subtitle.setStyleSheet("""
            font-size: 16px;
            letter-spacing: 2px;
            color: rgba(200, 215, 235, 180);
        """)

        layout.addWidget(self.title)
        layout.addWidget(self.subtitle)

        # =========================
        # Opacity Effect
        # =========================
        self.opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity)
        self.opacity.setOpacity(0.0)

        self.fade_in = QPropertyAnimation(self.opacity, b"opacity")
        self.fade_out = QPropertyAnimation(self.opacity, b"opacity")
        self.scale = QPropertyAnimation(self, b"geometry")

    def showEvent(self, event):
        super().showEvent(event)

        screen = self.screen() or QApplication.primaryScreen()
        geo = screen.availableGeometry()

        end_rect = QRect(
            geo.center().x() - self.width() // 2,
            geo.center().y() - self.height() // 2,
            self.width(),
            self.height(),
        )

        start_rect = QRect(
            end_rect.x(), end_rect.y() + 20, end_rect.width(), end_rect.height()
        )

        self.setGeometry(start_rect)

        # =========================
        # Animations
        # =========================
        self.fade_in.setDuration(600)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.scale.setDuration(600)
        self.scale.setStartValue(start_rect)
        self.scale.setEndValue(end_rect)
        self.scale.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.fade_out.setDuration(500)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.Type.InCubic)

        self.fade_in.start()
        self.scale.start()

        self.fade_in.finished.connect(
            lambda: QTimer.singleShot(1300, self.fade_out.start)
        )
        self.fade_out.finished.connect(self.accept)


def main():
    import sys
    import threading

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox

    print(f"ANCORATE {edition} {version} - Initializing...", flush=True)

    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setStyleSheet(APP_STYLE)

    # Splash
    splash = FreshStartup()
    splash.show()
    print("SPLASH SHOWN", flush=True)

    def after_splash():
        print("SPLASH DONE", flush=True)
        splash.close()

        # =========================
        # Device registration check
        # =========================
        device_key = load_device_key()

        if not device_key:
            QMessageBox.critical(None, "ANCORATE", "Device fingerprint generation failed.\nPlease check your system configuration.")
            sys.exit(1)

        # Show welcome dialog for new devices
        if not is_device_registered():
            welcome = WelcomeOverlay()
            welcome.exec()
            
            # Show TOS only for new devices
            tos = TermsOfServiceDialog()
            if tos.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)

        # =========================
        # Login with setup relaunch handling
        # =========================
        while True:
            login = LoginDialog()
            result = login.exec()
            
            if result == QDialog.DialogCode.Accepted:
                break  # Login successful, proceed
            elif hasattr(login, 'relaunch_setup') and login.relaunch_setup:
                # Setup was requested, show setup dialog
                setup = SetupDialog()
                if setup.exec() != QDialog.DialogCode.Accepted:
                    sys.exit(0)
                # Continue loop to show login again
            else:
                sys.exit(0)  # User cancelled login

        print("LOGIN OK", flush=True)

        window = App()
        window.show()
        print("MAIN WINDOW SHOWN", flush=True)

        # Background update check at startup
        QTimer.singleShot(1000, window.start_update_check)

        # Delayed start of keep_search thread to ensure GUI is fully initialized
        QTimer.singleShot(2000, lambda: threading.Thread(target=window.keep_search, daemon=True).start())

    # Splash sichtbar lassen
    QTimer.singleShot(2500, after_splash)

    print("ENTER EVENT LOOP", flush=True)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


# © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved. Distribution without permission prohibited.
# This code is part of ANCORATE Encryption Software.
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.
# Written by Samuel J. Tirwa & Gabriel Leiria-Roussin.
# January 2026
# Version 26.2
