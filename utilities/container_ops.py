#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - reine Container-Operationen
#
# Enthält container-lokale Hilfen (NICHT verschlüsselt):
#   - SHA-256 eines Klartextes berechnen
#   - Metadaten-Einträge für Dateien bauen
#   - Eine Datei in einem Container ersetzen (Atomarer Rebuild)
#
# Wichtig: Die Funktionen hier sind von Qt unabhängig. Sie werden über den
# GUI-Thread (z.B. app.main_window) und Worker-Threads (app.workers) genutzt.

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import os
import stat
import struct
import tempfile
import time
from ctypes import wintypes

from app.core import (
    HEADER_FMT,
    HEADER_LEN,
    MAGIC,
    META_LEN_SIZE,
    VERSION,
    encrypt_meta,
    write_header,
)
from decrypt import decrypt_meta
from encrypt import encrypt_file_to_blob

DEFAULT_FORMAT = f"ANCORATE-SALT-{VERSION}"
_ANY_FILE_STATE = object()
_META_JOURNAL_MAGIC = b"ANC_META_TXN\x01"


def _metadata_journal_path(container_path: str) -> str:
    return container_path + ".anc-meta-recovery"


def _read_container_metadata(container_path: str, master_key: bytes):
    with open(container_path, "rb") as source:
        source_size = os.fstat(source.fileno()).st_size
        if source_size < HEADER_LEN + META_LEN_SIZE:
            raise ValueError("Container ist zu kurz.")
        header = source.read(HEADER_LEN)
        if len(header) != HEADER_LEN or not header.startswith(MAGIC):
            raise ValueError("Container-Header ist beschädigt oder unvollständig.")
        source.seek(-META_LEN_SIZE, os.SEEK_END)
        length_data = source.read(META_LEN_SIZE)
        if len(length_data) != META_LEN_SIZE:
            raise ValueError("Metadatenlänge konnte nicht gelesen werden.")
        meta_length = struct.unpack("<Q", length_data)[0]
        if meta_length < 12 + 16 + 32 + 1 or meta_length > (
            source_size - HEADER_LEN - META_LEN_SIZE
        ):
            raise ValueError("Metadatenlänge ist ungültig.")
        meta_pos = source_size - META_LEN_SIZE - meta_length
        source.seek(meta_pos)
        meta_blob = source.read(meta_length)
        if len(meta_blob) != meta_length:
            raise ValueError("Metadaten konnten nicht vollständig gelesen werden.")
        meta = decrypt_meta(meta_blob, master_key)
        return source_size, meta_pos, meta_blob, meta


def save_container_metadata(
    container_path: str,
    new_meta: dict,
    master_key: bytes,
    *,
    stop_event=None,
) -> None:
    """Replace encrypted metadata in place, journaling only the old metadata.

    File blobs are never copied. The encrypted metadata backup is enough to
    restore the original container tail if writing is interrupted.
    """
    journal_path = _metadata_journal_path(container_path)
    if os.path.exists(journal_path):
        recover_container_metadata(container_path)
        if os.path.exists(journal_path):
            raise RuntimeError("Eine Tresor-Wiederherstellung steht noch aus.")

    original_size, meta_pos, old_meta_blob, _old_meta = _read_container_metadata(
        container_path, master_key
    )
    new_meta_blob = encrypt_meta(new_meta, master_key)

    journal_fd, temporary_journal = tempfile.mkstemp(
        prefix=".anc-meta-", suffix=".tmp",
        dir=os.path.dirname(os.path.abspath(container_path)) or os.curdir,
    )
    try:
        with os.fdopen(journal_fd, "wb") as journal:
            journal.write(_META_JOURNAL_MAGIC)
            journal.write(b"\x00")
            journal.write(struct.pack("<QQ", original_size, len(old_meta_blob)))
            journal.write(old_meta_blob)
            journal.flush()
            os.fsync(journal.fileno())
        os.replace(temporary_journal, journal_path)

        try:
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")
            with open(container_path, "rb+") as destination:
                destination.truncate(meta_pos)
                destination.seek(meta_pos)
                destination.write(new_meta_blob)
                destination.write(struct.pack("<Q", len(new_meta_blob)))
                destination.flush()
                os.fsync(destination.fileno())
        except Exception:
            recover_container_metadata(container_path)
            raise

        with open(journal_path, "rb+") as journal:
            journal.seek(len(_META_JOURNAL_MAGIC))
            journal.write(b"\x01")
            journal.flush()
            os.fsync(journal.fileno())
        try:
            os.remove(journal_path)
        except OSError:
            # The committed marker makes cleanup safe to retry on next open/save.
            pass
    finally:
        if os.path.exists(temporary_journal):
            os.remove(temporary_journal)


def recover_container_metadata(container_path: str) -> bool:
    """Restore the saved encrypted metadata tail after an interrupted update."""
    journal_path = _metadata_journal_path(container_path)
    if not os.path.exists(journal_path):
        return False

    with open(journal_path, "rb") as journal:
        if journal.read(len(_META_JOURNAL_MAGIC)) != _META_JOURNAL_MAGIC:
            raise ValueError("Tresor-Wiederherstellungsjournal ist ungültig.")
        state = journal.read(1)
        if state not in (b"\x00", b"\x01"):
            raise ValueError("Tresor-Wiederherstellungsjournal hat ungültigen Status.")
        if state == b"\x01":
            old_meta_blob = None
            original_size = 0
            meta_length = 0
        else:
            lengths = journal.read(16)
            if len(lengths) != 16:
                raise ValueError("Tresor-Wiederherstellungsjournal ist unvollständig.")
            original_size, meta_length = struct.unpack("<QQ", lengths)
            if (
                original_size < HEADER_LEN + META_LEN_SIZE
                or meta_length < 12 + 16 + 32 + 1
                or meta_length > original_size - HEADER_LEN - META_LEN_SIZE
            ):
                raise ValueError("Tresor-Wiederherstellungsjournal hat ungültige Längen.")
            old_meta_blob = journal.read(meta_length)
            if len(old_meta_blob) != meta_length or journal.read(1):
                raise ValueError("Tresor-Wiederherstellungsjournal ist beschädigt.")

    if old_meta_blob is None:
        try:
            os.remove(journal_path)
        except OSError:
            pass
        return False

    meta_pos = original_size - META_LEN_SIZE - meta_length
    with open(container_path, "rb+") as destination:
        if os.fstat(destination.fileno()).st_size < meta_pos:
            raise ValueError("Tresor-Daten vor den Metadaten sind unvollständig.")
        destination.truncate(meta_pos)
        destination.seek(meta_pos)
        destination.write(old_meta_blob)
        destination.write(struct.pack("<Q", meta_length))
        destination.truncate(original_size)
        destination.flush()
        os.fsync(destination.fileno())
    os.remove(journal_path)
    return True


def _stat_signature(file_stat):
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
    )


def replace_container_with_backup(
    temp_path: str, container_path: str, backup_path: str | None = None
):
    """Atomically replace a container and optionally retain the old file."""
    if os.name != "nt":
        os.replace(temp_path, container_path)
        return None

    if backup_path is None:
        os.replace(temp_path, container_path)
        return None

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    replace_file = kernel32.ReplaceFileW
    replace_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPVOID,
    )
    replace_file.restype = wintypes.BOOL
    if not replace_file(container_path, temp_path, backup_path, 0, None, None):
        raise ctypes.WinError(ctypes.get_last_error())
    return backup_path


def _replace_container_file(temp_path: str, container_path: str, target_exists: bool):
    if os.name != "nt" or not target_exists:
        os.replace(temp_path, container_path)
        return
    replace_container_with_backup(temp_path, container_path)


@contextmanager
def atomic_container_write(
    container_path: str, expected_stat=_ANY_FILE_STATE
):
    """Build a replacement beside the vault and swap it in only when complete."""
    container_dir = os.path.dirname(os.path.abspath(container_path)) or os.curdir
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=container_dir) as temp:
            temp_path = temp.name
            yield temp
            temp.flush()
            os.fsync(temp.fileno())

        try:
            current_stat = os.stat(container_path)
        except FileNotFoundError:
            current_stat = None

        if expected_stat is not _ANY_FILE_STATE:
            changed = (
                current_stat is not None
                if expected_stat is None
                else current_stat is None
                or _stat_signature(current_stat) != _stat_signature(expected_stat)
            )
            if changed:
                raise RuntimeError(
                    "Der Tresor wurde während der Änderung außerhalb der App verändert."
                )

        if current_stat is not None:
            os.chmod(temp_path, stat.S_IMODE(current_stat.st_mode))
        _replace_container_file(
            temp_path, container_path, target_exists=current_stat is not None
        )
        temp_path = None
    finally:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                pass


@contextmanager
def atomic_container_update(
    container_path: str,
    master_key: bytes,
    *,
    progress_cb=None,
    stop_event=None,
):
    """Yield a copy of the blob area for a safe metadata/blob update.

    The existing encrypted metadata is authenticated before any replacement is
    prepared. On error or cancellation, the original vault remains untouched.
    """
    with open(container_path, "rb") as source:
        original_stat = os.fstat(source.fileno())
        source_size = original_stat.st_size
        if source_size < HEADER_LEN + META_LEN_SIZE:
            raise ValueError("Container ist zu kurz.")

        header = source.read(HEADER_LEN)
        if len(header) != HEADER_LEN or not header.startswith(MAGIC):
            raise ValueError("Container-Header ist beschädigt oder unvollständig.")

        source.seek(-META_LEN_SIZE, os.SEEK_END)
        length_data = source.read(META_LEN_SIZE)
        if len(length_data) != META_LEN_SIZE:
            raise ValueError("Metadatenlänge konnte nicht gelesen werden.")
        meta_length = struct.unpack("<Q", length_data)[0]
        if meta_length < 12 + 16 + 32 + 1 or meta_length > (
            source_size - HEADER_LEN - META_LEN_SIZE
        ):
            raise ValueError("Metadatenlänge ist ungültig.")

        meta_pos = source_size - META_LEN_SIZE - meta_length
        source.seek(meta_pos)
        old_meta_blob = source.read(meta_length)
        if len(old_meta_blob) != meta_length:
            raise ValueError("Metadaten konnten nicht vollständig gelesen werden.")
        old_meta = decrypt_meta(old_meta_blob, master_key)

    with atomic_container_write(container_path, original_stat) as destination:
        with open(container_path, "rb") as source:
            if _stat_signature(os.fstat(source.fileno())) != _stat_signature(
                original_stat
            ):
                raise RuntimeError(
                    "Der Tresor wurde während der Änderung außerhalb der App verändert."
                )

            remaining = meta_pos
            copied = 0
            while remaining:
                if stop_event is not None and stop_event.is_set():
                    raise RuntimeError("Vorgang abgebrochen")
                chunk = source.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise IOError("Unerwartetes Dateiende im Tresor.")
                destination.write(chunk)
                remaining -= len(chunk)
                copied += len(chunk)
                if progress_cb is not None and meta_pos:
                    progress_cb(int(copied * 100 / meta_pos))

            if progress_cb is not None and meta_pos == 0:
                progress_cb(100)
            if stop_event is not None and stop_event.is_set():
                raise RuntimeError("Vorgang abgebrochen")

        yield destination, old_meta


def file_sha256(path: str, chunk_size: int = 128 * 1024) -> str:
    """Berechnet den SHA-256-Hash eines Klartextes (hex)."""
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def new_file_entry(
    name: str,
    size: int,
    offset: int,
    length: int,
    *,
    mtime: int | None = None,
    created: int | None = None,
    added: int | None = None,
    edited: int | None = None,
    sha256: str | None = None,
) -> dict:
    """Baut einen Metadaten-Eintrag für eine Datei im Tresor."""
    entry = {
        "name": name,
        "size": size,
        "offset": offset,
        "length": length,
    }
    if mtime is not None:
        entry["mtime"] = int(mtime)
    if created is not None:
        entry["created"] = int(created)
    if added is not None:
        entry["added"] = int(added)
    if edited is not None:
        entry["edited"] = int(edited)
    if sha256:
        entry["sha256"] = sha256
    return entry


def touch_container_meta(meta: dict, *, flags: int | None = None, app_version: str | None = None) -> dict:
    """Aktualisiert die Container-Ebene der Metadaten (modified, app_version)."""
    updated = dict(meta)
    updated["modified"] = int(time.time())
    if flags is not None:
        updated["flags"] = flags
    if app_version:
        updated["app_version"] = app_version
    updated.setdefault("format", DEFAULT_FORMAT)
    return updated


def replace_entry_in_container(
    container_path: str,
    meta: dict,
    entry_index: int,
    new_data_path: str,
    master_key: bytes,
    flags: int,
    *,
    progress_cb=None,
    stop_event=None,
    app_version: str | None = None,
) -> dict:
    """Ersetzt einen Datei-Eintrag im Container durch den Inhalt von new_data_path.

    Der Container wird atomar neu aufgebaut:
      Header + alle Blobs (der ersetzte wird durch den neuen ersetzt) + Meta + Länge.
    Beim Abbruch oder Fehler bleibt der ursprüngliche Container unverändert.

    :return: Neue Metadaten (dict) mit aktualisierten Offsets/Längen.
    """
    if not os.path.isfile(container_path):
        raise FileNotFoundError(
            f"Container nicht gefunden: {container_path}"
        )
    if not os.path.isfile(new_data_path):
        raise FileNotFoundError(
            f"Neue Quelldatei nicht gefunden: {new_data_path}"
        )

    entries = list(meta.get("files", []))
    if entry_index < 0 or entry_index >= len(entries):
        raise IndexError("entry_index liegt außerhalb der Dateiliste.")

    # Aktuellen Salt aus dem Container lesen (Master-Key bleibt gleich).
    with open(container_path, "rb") as source:
        header = source.read(HEADER_LEN)
        if len(header) != HEADER_LEN:
            raise ValueError("Container-Header ist beschädigt oder unvollständig.")
        magic, _version, _flags, salt, _reserved = struct.unpack(HEADER_FMT, header)
        if magic != MAGIC:
            raise ValueError("Ungültiger Container-Header.")

    old_entry = dict(entries[entry_index])
    new_name = old_entry.get("name", "<unnamed>")
    now = int(time.time())

    temp_container = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, dir=os.path.dirname(os.path.abspath(container_path)) or os.curdir
        ) as tmp:
            temp_container = tmp.name
            write_header(tmp, flags, salt)

            new_entries: list[dict] = []
            total = len(entries)

            with open(container_path, "rb") as source:
                for i, entry in enumerate(entries):
                    if stop_event and stop_event.is_set():
                        raise RuntimeError("Vorgang abgebrochen")

                    if i == entry_index:
                        # Ersetzte Datei: neuen Inhalt verschlüsseln und anhängen.
                        entry_offset = tmp.tell()
                        encrypt_file_to_blob(
                            new_data_path,
                            tmp,
                            master_key,
                            filename=new_name,
                            stop_event=stop_event,
                        )
                        entry_length = tmp.tell() - entry_offset

                        new_size = os.path.getsize(new_data_path)
                        try:
                            new_mtime = int(os.path.getmtime(new_data_path))
                        except OSError:
                            new_mtime = None
                        try:
                            new_created = int(os.path.getctime(new_data_path))
                        except OSError:
                            new_created = None

                        new_entry = new_file_entry(
                            new_name,
                            new_size,
                            entry_offset,
                            entry_length,
                            mtime=new_mtime,
                            created=new_created,
                            added=old_entry.get("added") or now,
                            edited=now,
                            sha256=file_sha256(new_data_path),
                        )
                        # Unbekannte Zusatzfelder des alten Eintrags erhalten.
                        for k, v in old_entry.items():
                            if k not in new_entry and k not in ("offset", "length"):
                                new_entry[k] = v
                        new_entries.append(new_entry)
                    else:
                        # Unveränderter Blob: Byte-weise kopieren.
                        old_offset = int(entry.get("offset", 0))
                        blob_len = int(entry.get("length", 0))
                        source.seek(old_offset)

                        new_offset = tmp.tell()
                        remaining = blob_len
                        copy_chunk = 1024 * 1024
                        while remaining > 0:
                            if stop_event and stop_event.is_set():
                                raise RuntimeError("Vorgang abgebrochen")
                            chunk = source.read(min(copy_chunk, remaining))
                            if not chunk:
                                raise IOError(
                                    "Unerwartetes EOF beim Kopieren eines Blobs."
                                )
                            tmp.write(chunk)
                            remaining -= len(chunk)

                        new_entry = dict(entry)
                        new_entry["offset"] = new_offset
                        new_entries.append(new_entry)

                    if progress_cb:
                        progress_cb(min(90, int((i + 1) / max(1, total) * 90)))

            new_meta = touch_container_meta(
                meta, flags=flags, app_version=app_version
            )
            new_meta["files"] = new_entries

            meta_blob = encrypt_meta(new_meta, master_key)
            tmp.write(meta_blob)
            tmp.write(struct.pack("<Q", len(meta_blob)))
            tmp.flush()
            os.fsync(tmp.fileno())

        os.replace(temp_container, container_path)
        temp_container = None
    finally:
        if temp_container:
            try:
                os.remove(temp_container)
            except OSError:
                pass

    if progress_cb:
        progress_cb(100)

    return new_meta