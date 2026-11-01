# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""Custom SVG icons for file types shown in the vault views."""

import os

from PyQt6.QtCore import QByteArray, QRectF, Qt
from PyQt6.QtGui import QIcon, QPainter, QPixmap

from .file_types import detect_type_key

try:
    from PyQt6.QtSvg import QSvgRenderer
except ImportError:  # pragma: no cover - fallback for incomplete Qt installs
    QSvgRenderer = None

_ICON_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "file_types")
_ICON_BY_TYPE = {
    "word": "document",
    "opendocument_text": "document",
    "rich_text": "document",
    "ebook": "document",
    "postscript": "document",
    "spreadsheet": "spreadsheet",
    "opendocument_sheet": "spreadsheet",
    "csv": "spreadsheet",
    "presentation": "presentation",
    "opendocument_presentation": "presentation",
    "pdf": "pdf",
    "video": "video",
    "mp4": "video",
    "mov": "video",
    "mkv": "video",
    "webm": "video",
    "avi": "video",
    "flv": "video",
    "wmv": "video",
    "mpeg": "video",
    "mpeg4_video": "video",
    "image": "image",
    "png": "image",
    "jpeg": "image",
    "gif": "image",
    "bmp": "image",
    "webp": "image",
    "tiff": "image",
    "svg": "image",
    "photoshop": "image",
    "illustrator": "image",
    "icon": "image",
    "heif": "image",
    "avif": "image",
    "jp2": "image",
    "raw_image": "image",
    "extended_image": "image",
    "vector_image": "image",
    "mp3": "audio",
    "wav": "audio",
    "ogg": "audio",
    "flac": "audio",
    "audio": "audio",
    "aac": "audio",
    "midi": "audio",
    "archive": "archive",
    "zip": "archive",
    "gzip": "archive",
    "bzip2": "archive",
    "xz": "archive",
    "7z": "archive",
    "rar": "archive",
    "tar": "archive",
    "zstd": "archive",
    "cab": "archive",
    "mail_archive": "archive",
    "disk_image": "archive",
    "text": "code",
    "json": "code",
    "xml": "code",
    "html": "code",
    "yaml": "code",
    "sql": "code",
    "ebook_markup": "code",
    "email": "code",
    "calendar": "code",
    "contact": "code",
    "subtitle": "code",
    "web_source": "code",
    "source_code": "code",
    "config": "code",
    "data": "code",
    "font_source": "code",
    "database": "database",
    "scientific_data": "database",
    "columnar_data": "database",
    "3d_model": "model",
    "cad_model": "model",
    "cad": "model",
    "gis_data": "model",
    "design_project": "model",
    "diagram": "model",
}
_ICON_CACHE: dict[str, QIcon] = {}


def file_type_icon(filename: str) -> QIcon:
    """Return a custom icon selected from the detected file type."""
    icon_name = _ICON_BY_TYPE.get(detect_type_key(filename), "generic")
    cached = _ICON_CACHE.get(icon_name)
    if cached is not None:
        return cached

    icon_path = os.path.join(_ICON_DIR, f"{icon_name}.svg")
    try:
        with open(icon_path, "rb") as svg_file:
            source = svg_file.read()
    except OSError:
        return QIcon()

    if QSvgRenderer is None:
        return QIcon()
    renderer = QSvgRenderer(QByteArray(source))
    if not renderer.isValid():
        return QIcon()

    pixmap = QPixmap(48, 48)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    renderer.render(painter, QRectF(0, 0, 48, 48))
    painter.end()

    icon = QIcon(pixmap)
    _ICON_CACHE[icon_name] = icon
    return icon


def clear_file_type_icon_cache() -> None:
    _ICON_CACHE.clear()