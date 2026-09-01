#!/usr/bin/env python3
# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; Ausgangspunkt bleibt main.py)
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#

import os
import sys
import json
import struct
import time
import hashlib
import subprocess
import socket
import platform
import requests
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

from app.core import *
# ============================================================
# Worker-Threads + Export-Helfer (aus main.py)
# ============================================================

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

                try:
                    total = len(self.files)
                    added_paths = []
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
                        try:
                            mtime = int(os.path.getmtime(filepath))
                        except Exception:
                            mtime = None
                        entry = {
                            "name": name,
                            "size": size,
                            "offset": offset,
                            "length": blob_len,
                        }
                        if mtime:
                            entry["mtime"] = mtime
                        meta["files"].append(entry)
                        added.append(name)
                        added_paths.append(filepath)

                    # Meta verschlüsseln und ans Ende schreiben
                    meta_enc = encrypt_meta(meta, v2)
                    f.write(meta_enc)
                    f.write(struct.pack("<Q", len(meta_enc)))

                except Exception:
                    # Wen etwas schief läuft (z.B. Abbruch, Fehler), die alten
                    # Metadaten wiederherstellen, damit der Tresor lesbar bleibt.
                    try:
                        f.truncate(meta_pos)
                        f.seek(0, os.SEEK_END)
                        f.write(meta_blob)
                        f.write(meta_len_bytes)
                        f.flush()
                        os.fsync(f.fileno())
                    except Exception:
                        pass
                    raise

 # Einstellungen neu laden für aktuellen del_source_added Status
            current_settings = load_settings()
            if current_settings.get("del_source_added"):
                # Nur die tatsächlich erfolgreich verschlüsselten Quelldateien löschen.
                for file in added_paths:
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


class StartupUpdateWorker(QThread):
    """Prüft im Hintergrund, ob ein Update verfügbar ist."""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def run(self):
        try:
            from utilities.updater import validate_latest_json

            settings = load_settings()
            update_url = settings.get("update_url", UPDATE_URL)
            response = requests.get(update_url, timeout=5)
            if response.status_code != 200:
                raise ConnectionError(f"HTTP {response.status_code}")
            data = validate_latest_json(response.json())
            data["update_url"] = update_url
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))
