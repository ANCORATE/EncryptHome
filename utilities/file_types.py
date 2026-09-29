#!/usr/bin/env python3
# ANCORATE EncryptHome - Dateityp-Erkennung
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#
# Ermittelt den tatsächlichen Dateityp:
#   1. bevorzugt über die Magic-Bytes des Inhalts (falls Daten vorliegen),
#   2. sonst über die vollständige Endungskette des Namens (auch zusammengesetzt,
#      z. B. ".tar.gz").
# Dadurch wird nicht blind das verwendet, was hinter dem letzten Punkt steht.
#
# Das Modul ist bewusst frei von Qt- und Projekt-Abhängigkeiten.

from __future__ import annotations

import os
from pathlib import PurePosixPath

# Kategorie-Kennungen für die Vorschau/Anzeige
KIND_TEXT = "text"
KIND_IMAGE = "image"
KIND_PDF = "pdf"
KIND_VIDEO = "video"
KIND_BINARY = "binary"

# typ_key -> (Anzeigename, Kategorie)
TYPE_INFO = {
    "png": ("PNG-Bild", KIND_IMAGE),
    "jpeg": ("JPEG-Bild", KIND_IMAGE),
    "gif": ("GIF-Bild", KIND_IMAGE),
    "bmp": ("BMP-Bild", KIND_IMAGE),
    "webp": ("WebP-Bild", KIND_IMAGE),
    "tiff": ("TIFF-Bild", KIND_IMAGE),
    "svg": ("SVG-Grafik", KIND_IMAGE),
    "pdf": ("PDF-Dokument", KIND_PDF),
    "mp4": ("MP4-Video", KIND_VIDEO),
    "mov": ("QuickTime-Video", KIND_VIDEO),
    "mkv": ("Matroska-Video", KIND_VIDEO),
    "webm": ("WebM-Video", KIND_VIDEO),
    "avi": ("AVI-Video", KIND_VIDEO),
    "flv": ("Flash-Video", KIND_VIDEO),
    "wmv": ("Windows-Media-Video", KIND_VIDEO),
    "mpeg": ("MPEG-Video", KIND_VIDEO),
    "mp3": ("MP3-Audio", KIND_BINARY),
    "wav": ("WAV-Audio", KIND_BINARY),
    "ogg": ("Ogg-Audio", KIND_BINARY),
    "flac": ("FLAC-Audio", KIND_BINARY),
    "zip": ("ZIP-Archiv", KIND_BINARY),
    "gzip": ("GZip-Archiv", KIND_BINARY),
    "bzip2": ("BZip2-Archiv", KIND_BINARY),
    "xz": ("XZ-Archiv", KIND_BINARY),
    "7z": ("7-Zip-Archiv", KIND_BINARY),
    "rar": ("RAR-Archiv", KIND_BINARY),
    "tar": ("TAR-Archiv", KIND_BINARY),
    "text": ("Textdatei", KIND_TEXT),
    "json": ("JSON-Datei", KIND_TEXT),
    "xml": ("XML-Datei", KIND_TEXT),
    "csv": ("CSV-Tabelle", KIND_TEXT),
    "html": ("HTML-Datei", KIND_TEXT),
    "yaml": ("YAML-Datei", KIND_TEXT),
    "binary": ("Binärdatei", KIND_BINARY),
}

# Endungs-Kette -> typ_key (längste passende Kette gewinnt)
_EXT_TYPES = {
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "jpe": "jpeg", "jfif": "jpeg",
    "gif": "gif", "bmp": "bmp", "webp": "webp", "tif": "tiff", "tiff": "tiff",
    "svg": "svg", "pdf": "pdf",
    "mp4": "mp4", "m4v": "mp4", "mov": "mov", "qt": "mov", "mkv": "mkv",
    "webm": "webm", "avi": "avi", "flv": "flv", "wmv": "wmv",
    "mpg": "mpeg", "mpeg": "mpeg", "3gp": "mp4", "3g2": "mp4",
    "mp3": "mp3", "wav": "wav", "ogg": "ogg", "oga": "ogg", "flac": "flac",
    "zip": "zip", "gz": "gzip", "bz2": "bzip2", "xz": "xz", "7z": "7z",
    "rar": "rar", "tar": "tar",
    "txt": "text", "log": "text", "md": "text", "markdown": "text",
    "rst": "text", "ini": "text", "cfg": "text", "conf": "text",
    "py": "text", "java": "text", "c": "text", "h": "text", "cpp": "text",
    "js": "text", "ts": "text", "sh": "text", "bat": "text", "ps1": "text",
    "json": "json", "xml": "xml", "csv": "csv", "tsv": "csv",
    "html": "html", "htm": "html", "yaml": "yaml", "yml": "yaml",
}

# Magic-Bytes am Dateianfang: (Signatur, typ_key)
_MAGIC_PREFIX = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"BM", "bmp"),
    (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"OggS", "ogg"),
    (b"FLV\x01", "flv"),
    (b"\x1a\x45\xdf\xa3", "mkv"),
    (b"ID3", "mp3"),
    (b"\xff\xfb", "mp3"),
    (b"fLaC", "flac"),
    (b"II*\x00", "tiff"),
    (b"MM\x00*", "tiff"),
)


def _looks_like_text(sample: bytes) -> bool:
    """Plausibilitätsprüfung: überwiegend druckbare Zeichen und kein NUL."""
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    allowed = {0x09, 0x0A, 0x0D, 0x0C}
    printable = sum(
        1 for b in sample if 0x20 <= b <= 0x7E or b in allowed or b >= 0x80
    )
    return printable / len(sample) >= 0.90


def sniff_magic(data: bytes) -> str | None:
    """Ermittelt den Typ anhand der ersten Bytes; None, wenn unbekannt."""
    if not data:
        return None
    for signature, key in _MAGIC_PREFIX:
        if data.startswith(signature):
            return key
    # RIFF-basierte Container (WEBP / AVI / WAV) unterscheiden sich ab Byte 8
    if data.startswith(b"RIFF") and len(data) >= 12:
        form = data[8:12]
        if form == b"WEBP":
            return "webp"
        if form == b"AVI ":
            return "avi"
        if form == b"WAVE":
            return "wav"
    # ISO-BMFF (MP4/QuickTime): "ftyp" an Offset 4
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        return "mov" if brand in (b"qt  ", b"moov") else "mp4"
    if _looks_like_text(data[:4096]):
        return "text"
    return None


def _extension_type(filename: str) -> str | None:
    """Typ aus der vollständigen Endungskette (auch zusammengesetzt)."""
    name = os.path.basename(filename).lower()
    suffixes = [s.lstrip(".") for s in PurePosixPath(name).suffixes]
    if not suffixes:
        return None
    # zusammengesetzte Endungen zuerst prüfen (z. B. tar.gz -> tar/gzip)
    joined = ".".join(suffixes)
    if joined.endswith("tar.gz") or joined.endswith("tgz"):
        return "gzip"
    for suffix in reversed(suffixes):
        key = _EXT_TYPES.get(suffix)
        if key:
            return key
    return None


def detect_type_key(filename: str, data: bytes | None = None) -> str | None:
    """Bevorzugt Inhaltserkennung, faellt auf die Endung zurueck."""
    if data:
        key = sniff_magic(data)
        if key:
            return key
    return _extension_type(filename)


def type_label(filename: str, data: bytes | None = None) -> str:
    """Menschenlesbarer Typname, z. B. 'PNG-Bild' oder 'Unbekannt'."""
    key = detect_type_key(filename, data)
    if key and key in TYPE_INFO:
        return TYPE_INFO[key][0]
    return "Unbekannt"


def guess_kind(filename: str, data: bytes | None = None) -> str:
    """Kategorie fuer die Vorschau: text/image/pdf/video/binary."""
    key = detect_type_key(filename, data)
    if key and key in TYPE_INFO:
        return TYPE_INFO[key][1]
    return KIND_BINARY
