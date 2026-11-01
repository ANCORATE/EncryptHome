#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - Dateityp-Erkennung
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
    "word": ("Word-Dokument", KIND_BINARY),
    "spreadsheet": ("Tabellendokument", KIND_BINARY),
    "presentation": ("Präsentation", KIND_BINARY),
    "opendocument_text": ("OpenDocument-Text", KIND_BINARY),
    "opendocument_sheet": ("OpenDocument-Tabelle", KIND_BINARY),
    "opendocument_presentation": ("OpenDocument-Präsentation", KIND_BINARY),
    "rich_text": ("Rich-Text-Dokument", KIND_BINARY),
    "ebook": ("E-Book", KIND_BINARY),
    "postscript": ("PostScript-Dokument", KIND_BINARY),
    "photoshop": ("Photoshop-Datei", KIND_IMAGE),
    "illustrator": ("Illustrator-Datei", KIND_IMAGE),
    "icon": ("Symbolgrafik", KIND_IMAGE),
    "heif": ("HEIF-Bild", KIND_IMAGE),
    "avif": ("AVIF-Bild", KIND_IMAGE),
    "jp2": ("JPEG-2000-Bild", KIND_IMAGE),
    "raw_image": ("RAW-Kamerabild", KIND_IMAGE),
    "audio": ("Audiodatei", KIND_BINARY),
    "aac": ("AAC-Audio", KIND_BINARY),
    "midi": ("MIDI-Datei", KIND_BINARY),
    "video": ("Videodatei", KIND_VIDEO),
    "mpeg4_video": ("MPEG-4-Video", KIND_VIDEO),
    "3d_model": ("3D-Modell", KIND_BINARY),
    "font": ("Schriftdatei", KIND_BINARY),
    "archive": ("Archivdatei", KIND_BINARY),
    "zstd": ("Zstandard-Archiv", KIND_BINARY),
    "cab": ("CAB-Archiv", KIND_BINARY),
    "disk_image": ("Datenträgerabbild", KIND_BINARY),
    "database": ("Datenbankdatei", KIND_BINARY),
    "sql": ("SQL-Datei", KIND_TEXT),
    "ebook_markup": ("E-Book-Quelldatei", KIND_TEXT),
    "email": ("E-Mail-Datei", KIND_TEXT),
    "calendar": ("Kalenderdatei", KIND_TEXT),
    "contact": ("Kontaktdatei", KIND_TEXT),
    "subtitle": ("Untertiteldatei", KIND_TEXT),
    "web_source": ("Web-Quelldatei", KIND_TEXT),
    "source_code": ("Quelldatei", KIND_TEXT),
    "config": ("Konfigurationsdatei", KIND_TEXT),
    "data": ("Datenaustauschdatei", KIND_TEXT),
    "columnar_data": ("Binäres Datenaustauschformat", KIND_BINARY),
    "font_source": ("Schrift-Quelldatei", KIND_TEXT),
    "cad": ("CAD-Datei", KIND_BINARY),
    "game_data": ("Spieldatei", KIND_BINARY),
    "backup": ("Sicherungsdatei", KIND_BINARY),
    "extended_image": ("Erweitertes Bildformat", KIND_IMAGE),
    "vector_image": ("Vektorgrafik", KIND_IMAGE),
    "cad_model": ("CAD-Modell", KIND_BINARY),
    "gis_data": ("Geodaten-Datei", KIND_BINARY),
    "scientific_data": ("Wissenschaftliche Datendatei", KIND_BINARY),
    "mail_archive": ("E-Mail-Archiv", KIND_BINARY),
    "design_project": ("Kreativprojektdatei", KIND_BINARY),
    "diagram": ("Diagrammdatei", KIND_BINARY),
    "certificate": ("Zertifikatsdatei", KIND_BINARY),
    "executable": ("Programmdatei", KIND_BINARY),
    "binary": ("Binärdatei", KIND_BINARY),
}

# Endungs-Kette -> typ_key (längste passende Kette gewinnt)
_EXT_TYPES = {
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "jpe": "jpeg", "jfif": "jpeg",
    "gif": "gif", "bmp": "bmp", "webp": "webp", "tif": "tiff", "tiff": "tiff",
    "svg": "svg", "pdf": "pdf",
    "mp4": "mp4", "mov": "mov", "qt": "mov", "mkv": "mkv",
    "webm": "webm", "avi": "avi", "flv": "flv", "wmv": "wmv",
    "mpg": "mpeg", "mpeg": "mpeg", "3gp": "mp4", "3g2": "mp4",
    "mp3": "mp3", "wav": "wav", "ogg": "ogg", "oga": "ogg", "flac": "flac",
    "zip": "zip", "gz": "gzip", "bz2": "bzip2", "xz": "xz", "7z": "7z",
    "rar": "rar", "tar": "tar",
    "txt": "text", "log": "text", "md": "text", "markdown": "text",
    "rst": "text", "ini": "text", "cfg": "text", "conf": "text",
    "py": "text", "java": "text", "c": "text", "h": "text", "cpp": "text",
    "js": "web_source", "ts": "source_code", "sh": "text", "bat": "text", "ps1": "text",
    "json": "json", "xml": "xml", "csv": "csv", "tsv": "csv",
    "html": "html", "htm": "html", "yaml": "yaml", "yml": "yaml",
    "doc": "word", "docx": "word", "docm": "word", "dot": "word",
    "dotx": "word", "dotm": "word", "odt": "opendocument_text",
    "ott": "opendocument_text", "rtf": "rich_text", "wps": "word",
    "wpd": "word", "pages": "word",
    "xls": "spreadsheet", "xlsx": "spreadsheet", "xlsm": "spreadsheet",
    "xlsb": "spreadsheet", "xlt": "spreadsheet", "xltx": "spreadsheet",
    "xltm": "spreadsheet", "ods": "opendocument_sheet", "ots": "opendocument_sheet",
    "numbers": "spreadsheet", "dif": "spreadsheet", "slk": "spreadsheet",
    "ppt": "presentation", "pptx": "presentation", "pptm": "presentation",
    "pps": "presentation", "ppsx": "presentation", "ppsm": "presentation",
    "pot": "presentation", "potx": "presentation", "potm": "presentation",
    "odp": "opendocument_presentation", "otp": "opendocument_presentation",
    "key": "presentation",
    "epub": "ebook", "mobi": "ebook", "azw": "ebook", "azw3": "ebook",
    "kfx": "ebook", "fb2": "ebook", "djvu": "ebook", "djv": "ebook",
    "ps": "postscript", "eps": "postscript", "ai": "illustrator",
    "psd": "photoshop", "psb": "photoshop", "ico": "icon", "cur": "icon",
    "icns": "icon", "heic": "heif", "heif": "heif", "avif": "avif",
    "jxl": "extended_image", "apng": "extended_image", "tga": "extended_image",
    "targa": "extended_image", "dds": "extended_image", "exr": "extended_image",
    "hdr": "extended_image", "pcx": "extended_image", "jxr": "extended_image",
    "wdp": "extended_image", "jng": "extended_image",
    "wmf": "vector_image", "emf": "vector_image", "cdr": "vector_image",
    "jp2": "jp2", "j2k": "jp2", "jpf": "jp2", "jpx": "jp2", "jpm": "jp2",
    "raw": "raw_image", "cr2": "raw_image", "cr3": "raw_image", "nef": "raw_image",
    "arw": "raw_image", "dng": "raw_image", "orf": "raw_image", "rw2": "raw_image",
    "pef": "raw_image", "srw": "raw_image", "raf": "raw_image",
    "mp2": "audio", "m4a": "audio", "m4b": "audio", "wma": "audio",
    "aif": "audio", "aiff": "audio", "aifc": "audio", "ape": "audio",
    "wv": "audio", "opus": "audio", "amr": "audio", "ac3": "audio",
    "dts": "audio", "au": "audio", "mid": "midi", "midi": "midi",
    "kar": "midi", "aac": "aac", "caf": "audio", "mka": "audio",
    "m4p": "audio", "mpa": "audio", "ra": "audio", "ram": "audio",
    "snd": "audio", "voc": "audio", "tta": "audio", "w64": "audio",
    "vob": "video", "ogv": "video", "ogm": "video",
    "mts": "video", "m2ts": "video", "m2t": "video", "m1v": "video",
    "m2v": "video", "mpe": "video", "mxf": "video", "mjpeg": "video",
    "mjpg": "video", "ivf": "video", "m4v": "mpeg4_video",
    "f4v": "mpeg4_video", "mpeg4": "mpeg4_video", "divx": "video",
    "rm": "video", "rmvb": "video", "asf": "video", "3gpp": "video",
    "3gp2": "video", "yuv": "video",
    "obj": "3d_model", "stl": "3d_model", "gltf": "3d_model", "glb": "3d_model",
    "fbx": "3d_model", "blend": "3d_model", "dae": "3d_model", "3ds": "3d_model",
    "ply": "3d_model", "3mf": "3d_model", "step": "3d_model", "stp": "3d_model",
    "iges": "3d_model", "igs": "3d_model", "usd": "3d_model", "usdz": "3d_model",
    "ttf": "font", "otf": "font", "woff": "font", "woff2": "font",
    "eot": "font", "fon": "font", "fnt": "font",
    "zst": "zstd", "zstd": "zstd", "cab": "cab", "arj": "archive",
    "lzh": "archive", "lha": "archive", "ace": "archive", "alz": "archive",
    "z": "archive", "lz": "archive", "lzma": "archive", "br": "archive",
    "cabx": "cab", "lz4": "archive", "lzo": "archive", "lzop": "archive",
    "snappy": "archive", "zpaq": "archive",
    "iso": "disk_image", "dmg": "disk_image", "vhd": "disk_image",
    "vhdx": "disk_image", "vmdk": "disk_image", "ova": "disk_image", "ovf": "disk_image",
    "img": "disk_image", "wim": "disk_image", "esd": "disk_image", "nrg": "disk_image",
    "sqlite": "database", "sqlite3": "database", "db": "database", "db3": "database",
    "mdb": "database", "accdb": "database", "accde": "database", "accdr": "database",
    "dbf": "database", "mdf": "database", "ldf": "database", "ibd": "database",
    "bson": "database", "realm": "database", "bak": "backup", "dump": "backup",
    "bkp": "backup", "backup": "backup", "old": "backup", "orig": "backup",
    "snapshot": "backup",
    "sql": "sql", "ddl": "sql", "dml": "sql",
    "opf": "ebook_markup", "ncx": "ebook_markup",
    "eml": "email", "mbox": "email", "msg": "email", "oft": "email",
    "pst": "mail_archive", "ost": "mail_archive",
    "ics": "calendar", "ical": "calendar", "ifb": "calendar", "vcf": "contact",
    "vcard": "contact", "srt": "subtitle", "sub": "subtitle", "ass": "subtitle",
    "ssa": "subtitle", "vtt": "subtitle", "sbv": "subtitle", "smi": "subtitle",
    "css": "web_source", "scss": "web_source", "sass": "web_source", "less": "web_source",
    "vue": "web_source", "svelte": "web_source", "jsx": "web_source", "tsx": "web_source",
    "php": "web_source", "asp": "web_source", "aspx": "web_source", "jsp": "web_source",
    "htaccess": "config", "toml": "config", "properties": "config", "env": "config",
    "config": "config", "jsonl": "data", "ndjson": "data", "geojson": "data",
    "parquet": "columnar_data", "avro": "columnar_data",
    "orc": "columnar_data", "feather": "columnar_data", "arrow": "columnar_data",
    "json5": "json", "jsonc": "json",
    "shp": "gis_data", "shx": "gis_data", "prj": "gis_data", "gpx": "gis_data",
    "kml": "gis_data", "kmz": "gis_data", "gpkg": "gis_data", "qgs": "gis_data",
    "qgz": "gis_data", "las": "gis_data", "laz": "gis_data", "dem": "gis_data",
    "fits": "scientific_data", "fit": "scientific_data", "fts": "scientific_data",
    "mat": "scientific_data", "npy": "scientific_data", "npz": "scientific_data",
    "pkl": "scientific_data", "pickle": "scientific_data", "rds": "scientific_data",
    "rdata": "scientific_data", "safetensors": "scientific_data", "onnx": "scientific_data",
    "pt": "scientific_data", "pth": "scientific_data", "keras": "scientific_data",
    "h5": "scientific_data", "hdf5": "scientific_data",
    "dwg": "cad_model", "dxf": "cad_model", "dgn": "cad_model", "ifc": "cad_model",
    "rvt": "cad_model", "rfa": "cad_model", "skp": "cad_model", "3dm": "cad_model",
    "sldprt": "cad_model", "sldasm": "cad_model", "slddrw": "cad_model",
    "ipt": "cad_model", "iam": "cad_model", "f3d": "cad_model", "catpart": "cad_model",
    "catproduct": "cad_model",
    "indd": "design_project", "idml": "design_project", "aep": "design_project",
    "aepx": "design_project", "prproj": "design_project", "drp": "design_project",
    "veg": "design_project", "fig": "design_project", "sketch": "design_project",
    "afdesign": "design_project", "afphoto": "design_project", "afpub": "design_project",
    "xcf": "design_project", "kra": "design_project", "ora": "design_project",
    "vsd": "diagram", "vsdx": "diagram", "drawio": "diagram", "xmind": "diagram",
    "mmap": "diagram", "graphml": "diagram", "puml": "diagram",
    "pfx": "certificate", "p12": "certificate", "p7b": "certificate", "p7c": "certificate",
    "p7s": "certificate", "der": "certificate",
    "exe": "executable", "dll": "executable", "sys": "executable", "so": "executable",
    "dylib": "executable", "elf": "executable", "com": "executable", "bin": "executable",
    "xmls": "xml", "xhtml": "html", "xht": "html", "xsl": "xml", "xslt": "xml",
    "xsd": "xml", "dtd": "xml", "rss": "xml", "atom": "xml",
    "r": "source_code", "rmd": "source_code", "go": "source_code", "rs": "source_code",
    "kt": "source_code", "kts": "source_code", "swift": "source_code", "m": "source_code",
    "mm": "source_code", "scala": "source_code", "sc": "source_code", "pl": "source_code",
    "pm": "source_code", "rb": "source_code", "php3": "source_code", "php4": "source_code",
    "php5": "source_code", "phtml": "source_code", "lua": "source_code", "dart": "source_code",
    "ex": "source_code", "exs": "source_code", "erl": "source_code", "hrl": "source_code",
    "hs": "source_code", "lhs": "source_code", "elm": "source_code", "clj": "source_code",
    "cljs": "source_code", "cljc": "source_code", "edn": "source_code", "fs": "source_code",
    "fsx": "source_code", "vb": "source_code", "vbs": "source_code", "bas": "source_code",
    "asm": "source_code", "s": "source_code", "sqlx": "sql", "ipynb": "data",
    "tex": "text", "latex": "text", "bib": "text", "adoc": "text", "asciidoc": "text",
    "org": "text", "wiki": "text", "texi": "text", "man": "text",
    "patch": "text", "diff": "text", "lock": "text", "makefile": "source_code",
    "cmake": "source_code", "gradle": "source_code", "groovy": "source_code",
    "dockerfile": "source_code", "tf": "source_code", "hcl": "source_code",
    "proto": "source_code", "graphql": "source_code", "gql": "source_code",
    "wasm": "game_data", "swf": "game_data", "pak": "game_data", "wad": "game_data",
    "sav": "game_data", "rom": "game_data", "nes": "game_data", "gba": "game_data",
    "class": "source_code", "pyi": "source_code", "pyo": "source_code", "pyc": "source_code",
    "mjs": "web_source", "cjs": "web_source", "cxx": "source_code", "cc": "source_code",
    "hpp": "source_code", "hxx": "source_code", "inl": "source_code", "cu": "source_code",
    "cuh": "source_code", "plsql": "sql", "psql": "sql",
    "xps": "postscript", "oxps": "postscript", "abw": "word",
    "jar": "archive", "war": "archive", "ear": "archive",
    "deb": "archive", "rpm": "archive", "apk": "archive", "aab": "archive",
    "msi": "archive", "msp": "archive", "appx": "archive", "msix": "archive",
    "pkg": "archive", "whl": "archive", "gem": "archive", "crx": "archive",
    "xpi": "archive", "torrent": "data", "pem": "text", "crt": "text",
    "cer": "text", "csr": "text", "pub": "text", "asc": "text", "sig": "binary",
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
