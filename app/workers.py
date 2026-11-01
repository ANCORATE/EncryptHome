#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; Ausgangspunkt bleibt main.py)
#

import os
import struct
import time
import secrets
import tempfile
import threading
from typing import Optional

import requests
from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *

# Interne Module
from decrypt import *
from encrypt import *

# Utilities
from utilities.container_ops import (
    atomic_container_update,
    file_sha256,
    new_file_entry,
    replace_entry_in_container,
    replace_container_with_backup,
    save_container_metadata,
    touch_container_meta,
)
from utilities.settings import *

from app.core import *
# ============================================================
# Worker-Threads + Export-Helfer (aus main.py)
# ============================================================

def _deletion_passes(method: str) -> int:
    """Anzahl der Überschreib-Durchgänge gemäß ausgewählter Löschmethode."""
    if "Shatterer Ultra" in method:
        return 300
    if "Furnace Max" in method:
        return 200
    if "Vaporizer 1" in method:
        return 100
    if "Gutmann (35x)" in method:
        return 35
    if "DoD 5220.22-M (3x)" in method:
        return 3
    return 1


def _secure_delete_plaintext(path: str, method: str):
    """Überschreibt eine Klartext-Quelldatei gemäß Methode und löscht sie.

    Verhindert, dass der Klartext der Originaldatei nach der Verschlüsselung
    (Option 'del_source_added') auf der Platte wiederhergestellt werden kann.
    Scheitert das Überschreiben, wird zumindest die Löschung versucht.
    """
    passes = _deletion_passes(method)
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


class DeleteWorker(QObject):
    progress = pyqtSignal(int)
    committing = pyqtSignal()
    finished = pyqtSignal(str, object, str)
    error = pyqtSignal(str)

    def __init__(self, container_path, meta, entry_index, master_key, method, stop_event):
        super().__init__()
        self.container_path = container_path
        self.meta = meta
        self.entry_index = int(entry_index)
        self.master_key = master_key
        self.method = method
        self.stop_event = stop_event

    def _secure_overwrite(self, file_handle, offset, length):
        passes = _deletion_passes(self.method)
        total_work = max(1, length * passes)
        total_written = 0
        chunk_size = 1024 * 1024

        for _ in range(passes):
            if self.stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")
            file_handle.seek(offset)
            bytes_left = length
            while bytes_left > 0:
                if self.stop_event.is_set():
                    raise RuntimeError("Vorgang abgebrochen")
                current_chunk = min(bytes_left, chunk_size)
                file_handle.write(secrets.token_bytes(current_chunk))
                bytes_left -= current_chunk
                total_written += current_chunk
                self.progress.emit(50 + min(50, int(total_written / total_work * 50)))
            file_handle.flush()
            os.fsync(file_handle.fileno())

    def run(self):
        temp_path = None
        original = None
        backup_path = None
        try:
            target = self.meta["files"][self.entry_index]
            offset = int(target["offset"])
            length = int(target["length"])
            name = target["name"]
            container_dir = os.path.dirname(os.path.abspath(self.container_path)) or os.curdir

            original = open(self.container_path, "rb+")
            original.seek(0, os.SEEK_END)
            source_size = original.tell()
            if source_size < HEADER_LEN + META_LEN_SIZE:
                raise ValueError("Container ist zu kurz.")
            original.seek(-META_LEN_SIZE, os.SEEK_END)
            meta_len_data = original.read(META_LEN_SIZE)
            if len(meta_len_data) != META_LEN_SIZE:
                raise ValueError("Metadatenlänge konnte nicht gelesen werden.")
            meta_len = struct.unpack("<Q", meta_len_data)[0]
            data_end = source_size - META_LEN_SIZE - meta_len
            if offset < HEADER_LEN or length < 0 or offset + length > data_end:
                raise ValueError("Dateieintrag liegt außerhalb des Tresors.")

            with tempfile.NamedTemporaryFile(delete=False, dir=container_dir) as temp:
                temp_path = temp.name
                destination = temp
                original.seek(0)
                header = original.read(HEADER_LEN)
                if len(header) != HEADER_LEN:
                    raise IOError("Container-Header unvollständig.")
                destination.write(header)

                bytes_to_copy = data_end - HEADER_LEN - length
                bytes_copied = 0
                for start, remaining in (
                    (HEADER_LEN, offset - HEADER_LEN),
                    (offset + length, data_end - (offset + length)),
                ):
                    original.seek(start)
                    while remaining > 0:
                        if self.stop_event.is_set():
                            raise RuntimeError("Vorgang abgebrochen")
                        chunk = original.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise IOError("Unerwartetes Dateiende im Tresor.")
                        destination.write(chunk)
                        remaining -= len(chunk)
                        bytes_copied += len(chunk)
                        if bytes_to_copy:
                            self.progress.emit(min(50, int(bytes_copied / bytes_to_copy * 50)))

                new_meta = {**self.meta, "files": [dict(item) for item in self.meta["files"]]}
                new_meta["files"].pop(self.entry_index)
                for item in new_meta["files"]:
                    if item["offset"] > offset:
                        item["offset"] -= length

                new_meta_blob = encrypt_meta(new_meta, self.master_key)
                destination.write(new_meta_blob)
                destination.write(struct.pack("<Q", len(new_meta_blob)))
                destination.flush()
                os.fsync(destination.fileno())

            if self.stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")
            self.committing.emit()
            if os.name == "nt":
                original.close()
                original = None
                backup_path = (
                    self.container_path + ".anc-delete-" + secrets.token_hex(8)
                )
                replace_container_with_backup(
                    temp_path, self.container_path, backup_path
                )
            else:
                os.replace(temp_path, self.container_path)
            temp_path = None

            overwrite_error = ""
            try:
                if backup_path is not None:
                    with open(backup_path, "rb+") as old_container:
                        self._secure_overwrite(old_container, offset, length)
                else:
                    self._secure_overwrite(original, offset, length)
            except Exception as error:
                overwrite_error = str(error)
            finally:
                if backup_path is not None:
                    try:
                        os.remove(backup_path)
                    except OSError as error:
                        cleanup_error = f"Alte Tresorkopie konnte nicht entfernt werden: {error}"
                        overwrite_error = (
                            f"{overwrite_error}; {cleanup_error}"
                            if overwrite_error
                            else cleanup_error
                        )
            self.finished.emit(name, new_meta, overwrite_error)
        except Exception as error:
            self.error.emit(str(error) or repr(error))
        finally:
            if original is not None:
                original.close()
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            if backup_path and os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except OSError:
                    pass



class DeleteContainerWorker(QObject):
    """Sicheres Vernichten eines gesamten Tresors im Hintergrund."""

    progress = pyqtSignal(int)
    finished = pyqtSignal(str, str)
    error = pyqtSignal(str)

    def __init__(self, container_path, method, stop_event):
        super().__init__()
        self.container_path = container_path
        self.method = method
        self.stop_event = stop_event

    def _secure_overwrite_data(self, file_handle, offset, length):
        passes = _deletion_passes(self.method)
        chunk_size = 1024 * 1024
        # Fortschritt pro abgeschlossenem Pass: Bei 300 Durchgaengen und einem
        # Byte-basierten Anteil bleibt der Balken ueber Tausende Chunks bei 0 %
        # stehen und wirkt wie ein Haenger.
        for pass_index in range(passes):
            if self.stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")
            file_handle.seek(offset)
            bytes_left = length
            while bytes_left > 0:
                if self.stop_event.is_set():
                    raise RuntimeError("Vorgang abgebrochen")
                current_chunk = min(bytes_left, chunk_size)
                file_handle.write(secrets.token_bytes(current_chunk))
                bytes_left -= current_chunk
            file_handle.flush()
            os.fsync(file_handle.fileno())
            # Letzter Pass auf 99 % begrenzt, das Entfernen der Datei ist der
            # letzte Schritt und wird separat gemeldet.
            self.progress.emit(
                max(0, min(99, int((pass_index + 1) / passes * 99)))
            )

    def run(self):
        c_path = self.container_path
        try:
            if not c_path or not os.path.exists(c_path):
                raise ValueError("Tresor nicht gefunden.")
            if self.stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")

            file_size = os.path.getsize(c_path)
            if file_size > HEADER_LEN:
                with open(c_path, "rb+") as fh:
                    data_offset = HEADER_LEN
                    data_length = file_size - data_offset
                    if data_length > 0:
                        self._secure_overwrite_data(fh, data_offset, data_length)

            if self.stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")

            os.remove(c_path)
            self.finished.emit(c_path, self.method)
        except Exception as error:
            self.error.emit(str(error) or repr(error))



class AddWorker(QObject):
    progress = pyqtSignal(int)
    stage = pyqtSignal(str)
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        files: list,
        master_key: bytes,
        flags: int,
        stop_event: threading.Event,
        folder: str = "",
    ):
        super().__init__()
        self.container_path = container_path
        self.files = files
        self.master_key = master_key
        self.flags = flags
        self.stop_event = stop_event
        self.folder = folder or ""

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
            added_paths = []

            self.stage.emit("Kopiere vorhandene Tresordaten sicher...")

            def copy_progress(progress_value):
                self.progress.emit(min(20, int(progress_value / 5)))

            with atomic_container_update(
                self.container_path,
                v2,
                progress_cb=copy_progress,
                stop_event=self.stop_event,
            ) as (f, meta):
                # Container-Ebene der Metadaten aktualisieren
                meta = touch_container_meta(
                    meta, flags=self.flags, app_version=f"{edition} {version}"
                )

                # Zielordner (inkl. Elternpfade) in der Meta festhalten
                if self.folder:
                    folders = set(meta.get("folders") or [])
                    parts = self.folder.split("/")
                    p = ""
                    for part in parts:
                        p = f"{p}/{part}" if p else part
                        folders.add(p)
                total = len(self.files)
                for idx, filepath in enumerate(self.files, start=1):
                    if self.stop_event and self.stop_event.is_set():
                        raise RuntimeError("Vorgang abgebrochen")

                    if not os.path.isfile(filepath):
                        continue

                    offset = f.tell()
                    name = os.path.basename(filepath)
                    if self.folder:
                        name = f"{self.folder}/{name}"
                    size = os.path.getsize(filepath)

                    def cb(progress_value):
                        fraction = ((idx - 1) + progress_value / 100) / max(
                            1, total
                        )
                        self.progress.emit(min(90, 20 + int(fraction * 70)))

                    encrypt_file_to_blob(
                        filepath,
                        f,
                        v2,
                        filename=name,
                        progress_cb=cb,
                        stop_event=self.stop_event,
                    )

                    newpos = f.tell()
                    blob_len = newpos - offset
                    self.stage.emit(f"Prüfe Datei {idx} von {total}...")
                    try:
                        f_stat = os.stat(filepath)
                        f_mtime = int(f_stat.st_mtime)
                        f_created = int(f_stat.st_ctime)
                    except OSError:
                        f_mtime = None
                        f_created = None
                    entry = new_file_entry(
                        name,
                        size,
                        offset,
                        blob_len,
                        mtime=f_mtime,
                        created=f_created,
                        added=int(time.time()),
                        sha256=file_sha256(filepath),
                    )
                    meta["files"].append(entry)
                    added.append(name)
                    added_paths.append(filepath)

                self.stage.emit("Schreibe Tresor sicher...")
                meta_enc = encrypt_meta(meta, v2)
                f.write(meta_enc)
                f.write(struct.pack("<Q", len(meta_enc)))

            # Einstellungen neu laden für aktuellen del_source_added Status
            current_settings = load_settings()
            if current_settings.get("del_source_added"):
                self.stage.emit("Lösche Quelldateien sicher...")
                # Nur die tatsächlich erfolgreich verschlüsselten Quelldateien
                # mit der konfigurierten Löschmethode sicher vernichten.
                method = current_settings.get("deletion_method", "Standard")
                for file in added_paths:
                    _secure_delete_plaintext(file, method)

            self.progress.emit(100)
            self.finished.emit(added)

        except Exception as e:
            # Fehler sauber melden
            error_msg = str(e) if str(e) else repr(e)
            print(f"[DEBUG] Worker error: {error_msg}")
            print(f"[DEBUG] Exception type: {type(e).__name__}")
            self.error.emit(error_msg)


class MetadataSaveWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        meta: dict,
        master_key: bytes,
        flags: int,
        stop_event: threading.Event,
    ):
        super().__init__()
        self.container_path = container_path
        self.meta = meta
        self.master_key = master_key
        self.flags = flags
        self.stop_event = stop_event

    def run(self):
        try:
            new_meta = touch_container_meta(
                self.meta, flags=self.flags, app_version=f"{edition} {version}"
            )
            save_container_metadata(
                self.container_path,
                new_meta,
                self.master_key,
                stop_event=self.stop_event,
            )
            self.progress.emit(100)
            self.finished.emit(new_meta)
        except Exception as error:
            self.error.emit(str(error) or repr(error))


class ExportWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        meta_entry: dict,
        master_key: bytes,
        stop_event: Optional[threading.Event] = None,
    ):
        super().__init__()
        self.container_path = container_path
        self.meta_entry = meta_entry
        self.master_key = master_key
        self.stop_event = stop_event or threading.Event()

    def run(self):
        try:
            save_to = export_entry_to_path(
                self.container_path,
                self.meta_entry,
                self.master_key,
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
        stop_event: Optional[threading.Event] = None,
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


class RewriteEntryWorker(QObject):
    """Ersetzt den Inhalt eines Datei-Eintrags im Container durch eine
    entschlüsselte, extern bearbeitete Datei (In-Tresor-Bearbeitung)."""

    progress = pyqtSignal(int)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        meta: dict,
        entry_index: int,
        new_data_path: str,
        master_key: bytes,
        flags: int,
        stop_event: Optional[threading.Event] = None,
    ):
        super().__init__()
        self.container_path = container_path
        self.meta = meta
        self.entry_index = int(entry_index)
        self.new_data_path = new_data_path
        self.master_key = master_key
        self.flags = flags
        self.stop_event = stop_event or threading.Event()

    def run(self):
        try:
            new_meta = replace_entry_in_container(
                self.container_path,
                self.meta,
                self.entry_index,
                self.new_data_path,
                self.master_key,
                self.flags,
                progress_cb=self.progress.emit,
                stop_event=self.stop_event,
                app_version=f"{edition} {version}",
            )
            self.finished.emit(new_meta)
        except Exception as e:
            error_msg = str(e) if str(e) else repr(e)
            print(f"[DEBUG] Rewrite worker error: {error_msg}")
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
