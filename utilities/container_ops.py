#!/usr/bin/env python3
# ANCORATE EncryptHome - reine Container-Operationen
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#
# Enthält container-lokale Hilfen (NICHT verschlüsselt):
#   - SHA-256 eines Klartextes berechnen
#   - Metadaten-Einträge für Dateien bauen
#   - Eine Datei in einem Container ersetzen (Atomarer Rebuild)
#
# Wichtig: Die Funktionen hier sind von Qt unabhängig. Sie werden über den
# GUI-Thread (z.B. app.main_window) und Worker-Threads (app.workers) genutzt.

from __future__ import annotations

import os
import struct
import tempfile
import time

from app.core import (
    HEADER_FMT,
    HEADER_LEN,
    MAGIC,
    META_LEN_SIZE,
    VERSION,
    encrypt_meta,
    write_header,
)
from encrypt import encrypt_file_to_blob

DEFAULT_FORMAT = f"ANCORATE-SALT-{VERSION}"


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