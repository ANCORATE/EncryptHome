#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; siehe main.py fuer Einstiegspunkt)
#

import os
import json
import struct
import time
import hashlib
import subprocess
import secrets
import tempfile
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *
from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Interne Module
from decrypt import *
from encrypt import *

# Utilities
from utilities.settings import *
from utilities.theme_engine import build_stylesheet
from utilities import get_app_icon

# ============================================================
# Globale Konstanten + Standalone-Helfer (aus main.py)
# ============================================================

MAGIC = b"ANC0"  # Magic-Header für ANCORATE .salt Container
VERSION = 0x09  # Aktuelle Containerversion
FLAG_DEVICE = 0x01  # Container ist an Gerät gebunden
FLAG_KEYFILE = 0x02  # Container verwendet Keyfile
FLAG_RESERVED_0x04 = 0x04  # Reserviertes Flag (derzeit nicht verwendet)
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


if os.name == "nt":
    CONFIG_DIR = os.path.join(os.environ.get("APPDATA", str(Path.home())), "ANCORATE")
else:
    CONFIG_DIR = os.path.join(str(Path.home()), ".config", "ANCORATE")

try:
    os.makedirs(CONFIG_DIR, exist_ok=True)
except OSError:
    pass

CONFIG_FILE = os.path.join(CONFIG_DIR, "device.png")
REGISTRATION_MARKER = os.path.join(CONFIG_DIR, ".registered")
RECENT_CONTAINERS_FILE = os.path.join(CONFIG_DIR, "recent_containers.json")

# Magic-Präfix für verschlüsselte Zuletzt-Liste (device-key-gebunden)
_RECENT_MAGIC = b"ANC_REC\x01"

ANCORATE_BLUE = "#1e88e5"
ANCORATE_BLUE_SOFT = "#90caf9"
BACKGROUND_DARK = "#0b0f14"

from .version import edition, type_edition, version, version_year  # noqa: F401


def safe_run(cmd, timeout=1):
    try:
        if isinstance(cmd, str):
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, shell=True, text=True, timeout=timeout
            )
        else:
            out = subprocess.check_output(
                cmd, stderr=subprocess.DEVNULL, text=True, timeout=timeout
            )
        return out.strip()
    except Exception:
        return ""


def run_powershell(script, timeout=3):
    """Führt ein PowerShell-Skript aus und gibt die Ausgabe zurück (Windows)."""
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
        )
        return out.strip()
    except Exception:
        return ""


def get_mac_bytes():
    import uuid

    node = uuid.getnode()
    return int(node).to_bytes(6, "big", signed=False)


def get_cpu_id(timeout=3):
    import platform
    system = platform.system()
    
    try:
        if system == "Windows":
            # PowerShell First (robust on current Windows, wmic is deprecated)
            out = run_powershell(
                "(Get-CimInstance Win32_Processor).ProcessorId", timeout=timeout
            )
            if out:
                return out
            out = safe_run("wmic cpu get ProcessorId", timeout=timeout)
            if out:
                lines = [
                    l.strip() for l in out.splitlines() 
                    if l.strip() and "ProcessorId" not in l
                ]
                if lines:
                    return lines[0]
        elif system == "Darwin":  # macOS
            out = safe_run("sysctl -n machdep.cpu.brand_string", timeout=timeout)
            if out:
                return out.strip()
        elif system == "Linux":
            out = safe_run("cat /proc/cpuinfo | grep 'model name' | head -1", timeout=timeout)
            if out:
                # Format: "model name      : Intel(R) Core(TM) i7-8700K CPU @ 3.70GHz"
                parts = out.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
    except Exception as e:
        print(f"[WARN] CPU ID detection failed: {e}")
    
    return "unknown-cpu"


def get_disk_serial(timeout=3):
    import platform
    system = platform.system()
    
    try:
        if system == "Windows":
            # PowerShell First (robust on current Windows, wmic is deprecated)
            out = run_powershell(
                "(Get-CimInstance Win32_DiskDrive | Select-Object -First 1).SerialNumber.Trim()",
                timeout=timeout,
            )
            if out:
                return out.splitlines()[0].strip()
            out = safe_run("wmic diskdrive get SerialNumber", timeout=timeout)
            if out:
                lines = [
                    l.strip() for l in out.splitlines() 
                    if l.strip() and "SerialNumber" not in l
                ]
                if lines:
                    return lines[0]
            out = safe_run("vol C:", timeout=timeout)
            if out:
                return out.replace("\r", "").replace("\n", "").strip()
        elif system == "Darwin":  # macOS
            out = safe_run("diskutil info / | grep 'Volume UUID'", timeout=timeout)
            if out:
                # Format: "   Volume UUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
                parts = out.split(":")
                if len(parts) > 1:
                    return parts[1].strip()
        elif system == "Linux":
            out = safe_run("lsblk -d -o serial -n", timeout=timeout)
            if out:
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                if lines:
                    return lines[0]
    except Exception as e:
        print(f"[WARN] Disk serial detection failed: {e}")
    
    return "unknown-disk"


def ensure_config_dir():
    d = os.path.dirname(CONFIG_FILE)
    os.makedirs(d, exist_ok=True)


def _secure_delete_file(path: str, passes: int = 3):
    """Überschreibt eine Datei mehrfach mit Zufallsdaten und löscht sie dann.

    Verhindert, dass entschlüsselte Klartextdaten aus Temp-Dateien nach dem
    Löschen auf der Platte wiederhergestellt werden können. Scheitert das
    Überschreiben, wird zumindest die Löschung versucht.
    """
    if not path or not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        if size > 0:
            with open(path, "r+b") as fh:
                chunk = 1024 * 1024
                for _ in range(passes):
                    fh.seek(0)
                    remaining = size
                    while remaining > 0:
                        n = min(chunk, remaining)
                        fh.write(secrets.token_bytes(n))
                        remaining -= n
                    fh.flush()
                    os.fsync(fh.fileno())
    except Exception:
        pass
    try:
        os.remove(path)
    except Exception:
        pass


_DEVICE_KEY_SEED = b"ANCORATE_DEVICE_KEY_SEED_2026_STABLE"


def _machine_guid() -> str:
    """Deterministische, installierungsspezifische Windows-Maschinenkennung."""
    import platform
    if platform.system() != "Windows":
        return ""
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            return str(guid).strip()
    except Exception as e:
        print(f"[WARN] MachineGuid could not be read: {e}")
        return ""


def device_fingerprint() -> bytes:
    """
    Deterministischer Geräte-Fingerabdruck.

    Bevorzugt die Windows-MachineGuid (fest pro Installation, ohne
    Subprozesse und damit ohne Timeout-Races). Fallback: MAC-Adresse,
    sonst Knotenname + Betriebssystem.
    """
    try:
        guid = _machine_guid()
        if guid:
            raw = b"GUID|" + guid.encode("utf-8", errors="ignore")
        else:
            mac = get_mac_bytes()
            if len(mac) == 6:
                raw = b"MAC|" + mac
            else:
                import platform
                raw = f"{platform.node()}|{platform.system()}".encode(
                    "utf-8", errors="ignore"
                )
        return hashlib.sha256(raw).digest()
    except Exception as e:
        print(f"[ERROR] Device fingerprint generation failed: {e}")
        import platform
        fallback = f"{platform.node()}{platform.system()}".encode("utf-8")
        return hashlib.sha256(fallback).digest()


def _legacy_device_fingerprint(cpu_id: str, disk_serial: str) -> bytes:
    """
    Rekonstruiert das frühere, zeitabhängige Fingerprint-Schema
    (MAC + CPU + Disk) aus konkreten Werten. Nur für die Migration
    bereits erstellter Tresore/Schlüssel.
    """
    mac = get_mac_bytes()
    raw = b"|".join(
        [
            b"MAC",
            mac,
            b"CPU",
            str(cpu_id).encode("utf-8", errors="ignore"),
            b"DSK",
            str(disk_serial).encode("utf-8", errors="ignore"),
        ]
    )
    return hashlib.sha256(raw).digest()


def legacy_device_key_variants() -> list:
    """
    Deterministische Schlüsselkandidaten der früheren Ableitung.

    Die alte Ableitung hing von subprozessbasierten Abfragen mit Timeout ab,
    die zwischen 'unknown-cpu'/'unknown-disk' und den echten Hardwarewerten
    wechselten. Diese Varianten decken alle plausiblen Kombinationen ab,
    sodass bereits erstellte gerätegebundene Tresore erneut geöffnet werden
    können. Bewusst frei von Subprozess-Races (Kandidatensatz ist aus den
    aktuellen, stabilen Hardwarewerten + festen Platzhalten reproduzierbar).
    """
    try:
        cpu = get_cpu_id(timeout=12)
        dsk = get_disk_serial(timeout=12)
    except Exception:
        cpu, dsk = "unknown-cpu", "unknown-disk"

    variants = []
    for c in sorted({cpu, "unknown-cpu"}):
        for d in sorted({dsk, "unknown-disk"}):
            fp = _legacy_device_fingerprint(c, d)
            key = hashlib.sha256(fp + _DEVICE_KEY_SEED).digest()
            if key not in variants:
                variants.append(key)
    return variants


def generate_device_key() -> bytes:
    """
    Generate a consistent device key at runtime without storing to file.
    Uses deterministic approach: SHA256(fingerprint + ANCORATE_SEED)
    """
    fp = device_fingerprint()

    # Use a fixed seed instead of random secret for consistency
    seed = _DEVICE_KEY_SEED

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


def determine_master_key(pwd, salt, flags, meta_blob):
    """
    Bestimmt den Master-Key für einen Tresor.

    - Nicht gerätegebunden: Ableitung nur aus dem Passwort.
    - Gerätegebunden: zuerst der stabile Geräteschlüssel (ohne Subprozesse);
      scheitert dessen Entschlüsselung (z.B. Tresor aus einer älteren Version
      mit zeitabhängiger Ableitung), werden die deterministischen
      Legacy-Kandidaten probiert.

    Returns Master-Key (bytes) oder None.
    """
    try:
        if not (flags & FLAG_DEVICE):
            return derive_master_key(pwd, salt, False)

        # 1) Stabiler Schlüssel - fast, ohne Subprozesse.
        try:
            stable = load_device_key()
            if stable:
                master = derive_master_key(pwd, salt, True, stable)
                if master is not None:
                    try:
                        decrypt_meta(meta_blob, master)  # Validierung
                        return master
                    except Exception:
                        pass
        except Exception:
            pass

        # 2) Legacy-Kandidaten - nur falls der stabile Schlüssel scheitert.
        for variant in legacy_device_key_variants():
            master = derive_master_key(pwd, salt, True, variant)
            if master is None:
                continue
            try:
                decrypt_meta(meta_blob, master)  # Validierung der Ableitung
                return master
            except Exception:
                continue
        return None
    except Exception as e:
        print(f"[ERROR] Master key determination failed: {e}")
        return None


def is_device_registered() -> bool:
    """Check if this device has been registered before"""
    return os.path.exists(REGISTRATION_MARKER)


def mark_device_registered():
    """Mark this device as registered"""
    ensure_config_dir()
    with open(REGISTRATION_MARKER, "w", encoding="utf-8") as f:
        f.write("registered")


def _recent_containers_key():
    """Stabiler, gerätegebundener Schlüssel für die Zuletzt-Liste (domain-separiert)."""
    try:
        dev = generate_device_key()
        if not dev:
            return None
        from base import derive_subkey
        return derive_subkey(dev, b"ANCORATE_RECENT_V1", "ancorate-recent-v1")
    except Exception:
        return None


def load_recent_containers() -> list:
    """Load recent containers list (encrypted on disk, plaintext legacy fallback)."""
    try:
        if os.path.exists(RECENT_CONTAINERS_FILE):
            with open(RECENT_CONTAINERS_FILE, "rb") as f:
                raw = f.read()
            if raw.startswith(_RECENT_MAGIC):
                blob = raw[len(_RECENT_MAGIC):]
                key = _recent_containers_key()
                if key:
                    try:
                        from decrypt import decrypt_meta
                        return decrypt_meta(blob, key)
                    except Exception:
                        return []
                return []
            # Legacy: unverschlüsseltes JSON aus früheren Versionen
            return json.loads(raw.decode("utf-8"))
        return []
    except Exception:
        return []


def save_recent_containers(containers: list):
    """Save recent containers list (encrypted with the device-derived key)."""
    try:
        ensure_config_dir()
        key = _recent_containers_key()
        if not key:
            with open(RECENT_CONTAINERS_FILE, "w", encoding="utf-8") as f:
                json.dump(containers[:10], f, indent=2)
            return
        from encrypt import encrypt_meta
        blob = encrypt_meta(containers[:10], key)
        tmp_fd, tmp = tempfile.mkstemp(
            dir=os.path.dirname(RECENT_CONTAINERS_FILE),
            prefix=".recent-", suffix=".tmp",
        )
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(_RECENT_MAGIC)
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, RECENT_CONTAINERS_FILE)
        except Exception:
            try:
                os.remove(tmp)
            except OSError:
                pass
            raise
    except Exception as e:
        print(f"[ERROR] Failed to save recent containers: {e}")


def add_recent_container(container_path: str):
    """Add container to recent list"""
    try:
        containers = load_recent_containers()
        if not isinstance(containers, list):
            containers = []

        # Remove if already exists
        containers = [c for c in containers if not isinstance(c, dict) or c.get("path") != container_path]

        # Add to beginning
        recent_entry = {
            "path": container_path,
            "name": os.path.basename(container_path),
            "last_accessed": int(time.time())
        }
        containers.insert(0, recent_entry)

        save_recent_containers(containers)
    except Exception as e:
        print(f"[ERROR] Failed to add recent container: {e}")


def remove_recent_container(container_path: str):
    """Remove a single entry from the recent list (e.g. after destruction)."""
    try:
        if not container_path:
            return
        target = os.path.normcase(os.path.abspath(container_path))
        containers = load_recent_containers()
        if not isinstance(containers, list):
            return

        kept = []
        removed = False
        for entry in containers:
            path = entry.get("path") if isinstance(entry, dict) else None
            if isinstance(path, str) and os.path.normcase(
                os.path.abspath(path)
            ) == target:
                removed = True
                continue
            kept.append(entry)

        if removed:
            save_recent_containers(kept)
    except Exception as e:
        print(f"[ERROR] Failed to remove recent container: {e}")

def rekey_container_password(
    container_path: str,
    current_meta: dict,
    current_flags: int,
    current_master_key: bytes,
    new_password: str,
) -> None:
    if not os.path.isfile(container_path):
        raise FileNotFoundError(f"Container nicht gefunden: {container_path}")

    from decrypt import decrypt_blob_range
    from encrypt import encrypt_file_to_blob
    import tempfile as tf

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
    
    # Parse the current header before beginning the re-encryption work.
    with open(container_path, "rb") as source:
        header = source.read(HEADER_LEN)
        _magic, _version, _flags, _old_salt, _reserved = struct.unpack(
            HEADER_FMT, header
        )
    
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
        
        # Decrypt with old master key and re-encrypt with new master key.
        # Wichtig: Falls eine Datei nicht neu verschlüsselt werden kann, wird der
        # komplette Vorgang abgebrochen (Exception), BEVOR irgendetwas geschrieben
        # wird. Andernfalls würde der neue Header/Meta einen neuen Key verwenden,
        # während der Alt-Blob mit dem alten Key verschlüsselt bliebe und die
        # Datei dauerhaft unlesbar würde.
        tmp_decrypt_path = None
        tmp_encrypt_path = None
        try:
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
                "offset": current_offset,
                "length": len(reencrypted_blob),
                "blob": reencrypted_blob,
            }
            for k, v in file_entry.items():
                if k not in ("offset", "length", "blob"):
                    file_entry_with_blob[k] = v
            new_files.append(file_entry_with_blob)

            current_offset += len(reencrypted_blob)

        except Exception as e:
            raise RuntimeError(
                f"Passwortwechsel fehlgeschlagen bei '{file_name}': {e}. "
                "Der Tresor bleibt unverändert."
            ) from e
        finally:
            # Temporäre Dateien sicher (überschreibend) aufräumen, damit
            # keine entschlüsselten Klartextdaten auf der Platte zurückbleiben.
            if tmp_decrypt_path:
                _secure_delete_file(tmp_decrypt_path)
            if tmp_encrypt_path:
                _secure_delete_file(tmp_encrypt_path)
    
    # Create clean metadata without blob fields for JSON serialization
    new_meta_files = []
    for file_entry in new_files:
        clean_entry = dict(file_entry)
        clean_entry.pop("blob", None)
        new_meta_files.append(clean_entry)
    
    new_meta["files"] = new_meta_files
    new_meta["modified"] = int(time.time())
    new_meta.setdefault("format", f"ANCORATE-SALT-{VERSION}")
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

    return master


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
    Liest den Header eines geöffneten Containers.

    fh muss im Read/Write-Modus geöffnet sein.
    Gibt die Felder zurück: (flags, salt)

    WICHTIG: Diese Funktion verändert die Datei NICHT. Eine Header-Reparatur
    würde das Salt ändern und den Tresor dauerhaft unlesbar machen, weil die
    Metadaten mit dem ursprünglichen Salt verschlüsselt wurden.
    """
    fh.seek(0)
    data = fh.read(HEADER_LEN)

    if len(data) < HEADER_LEN or not data.startswith(MAGIC):
        raise ValueError("Container-Header ist beschädigt oder unvollständig.")

    magic, ver, flags, salt, _ = struct.unpack(HEADER_FMT, data)
    if magic != MAGIC:
        raise ValueError("Ungültige Magic Bytes im Container-Header.")

    # Header ok
    return flags, salt


class notifier:
    _tray_icon = None

    @staticmethod
    def _get_tray():
        if notifier._tray_icon is None:
            try:
                tray = QSystemTrayIcon(get_app_icon())
                tray.setVisible(False)
                notifier._tray_icon = tray
            except Exception:
                return None
        return notifier._tray_icon

    @staticmethod
    def show(title: str, message: str, timeout: int = 1):
        """
        Zeigt eine System-Push-Benachrichtigung an.
        Falls kein System-Tray verfügbar ist, wird die Meldung ausgegeben.
        """
        try:
            tray = notifier._get_tray()
            if tray is not None:
                tray.showMessage(title, message, QSystemTrayIcon.MessageIcon.Information, timeout * 1000)
            else:
                print(f"[NOTIFY] {title}: {message}")
        except Exception:
            print(f"[NOTIFY] {title}: {message}")


# Einfachen trennenden Strich erzeugen - wird in DetailsDialog verwendet
def make_separator(color=None):
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setFixedHeight(1)
    line.setObjectName("HSep")
    if color:
        line.setStyleSheet(f"background-color: {color}; border: none;")
    return line

DEFAULT_THEME = "Standard-dark"

def build_app_style():
    """Qt-Stylesheet fuer das aktuelle Theme + Akzentfarbe + Dichte."""
    try:
        s = load_settings()
    except Exception:
        s = {}
    return build_stylesheet(
        s.get("theme", DEFAULT_THEME),
        str(s.get("ui_accent", "") or ""),
        str(s.get("ui_density", "Mittel") or "Mittel"),
    )

# ---------------------------------------------------------
# CSS laden (Theme + Akzentfarbe + Dichte)
# ---------------------------------------------------------
try:
    APP_STYLE = build_app_style()
except Exception as e:
    print(f"CSS loading failed: {e}")
    APP_STYLE = ""
