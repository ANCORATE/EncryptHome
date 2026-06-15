#!/usr/bin/env python3
# © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#
# Dateivorschau: Entschlüsselt eine Tresor-Datei in den RAM und zeigt eine Vorschau
# für gängige Dateitypen (Text/Bild; PDF optional, wenn QtPdf verfügbar ist).

from __future__ import annotations

import os
import platform
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QObject, Qt, pyqtSignal
from PyQt6.QtGui import QFont, QGuiApplication, QPixmap, QCloseEvent
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSlider,
    QTextEdit,
    QVBoxLayout,
    QWidget,

)

from base import derive_subkey

# ----------------------------
# Konfiguration / Limits
# ----------------------------

# Max. Bytes, die wir als RAM-Cache für eine Vorschau halten (pro Datei).
# Größere Dateien werden aus Sicherheits-/Performancegründen nicht als vollständige RAM-Preview geladen.
PREVIEW_MAX_BYTES = 512 * 1024 * 1024  # 512 MiB

# Max. Bytes, die in der UI als text angezeigt werden.
PREVIEW_TEXT_SHOW_BYTES = 128 * 1024 * 1024 # 128 MiB

# Wie viele Bytes für Hexdump (fallback)
PREVIEW_HEX_BYTES = 4096 # 4 KiB


@dataclass(frozen=True)
class PreviewInfo:
    name: str
    size: int
    loaded_bytes: int
    truncated: bool


class PreviewDecryptWorker(QObject):
    progress = pyqtSignal(int)
    finished = pyqtSignal(bytes, object)  # (data, PreviewInfo)
    error = pyqtSignal(str)

    def __init__(
        self,
        container_path: str,
        meta_entry: dict,
        master_key: bytes,
        stop_event: Optional[threading.Event] = None,
        max_bytes: int = PREVIEW_MAX_BYTES,
    ):
        super().__init__()
        self.container_path = container_path
        self.meta_entry = meta_entry
        self.master_key = master_key
        self.stop_event = stop_event or threading.Event()
        self.max_bytes = int(max_bytes)

    def run(self):
        try:
            data, info = decrypt_entry_to_bytes(
                self.container_path,
                self.meta_entry,
                self.master_key,
                stop_event=self.stop_event,
                progress_cb=self._progress,
                max_bytes=self.max_bytes,
            )
            self.finished.emit(data, info)
        except Exception as e:
            self.error.emit(str(e))

    def _progress(self, v: int):
        try:
            self.progress.emit(int(v))
        except Exception:
            pass


def _is_cancelled(stop_event: Optional[threading.Event]) -> bool:
    return bool(stop_event and stop_event.is_set())


def decrypt_entry_to_bytes(
    container_path: str,
    meta_entry: dict,
    master_key: bytes,
    *,
    stop_event: Optional[threading.Event] = None,
    progress_cb=None,
    max_bytes: int = PREVIEW_MAX_BYTES,
) -> tuple[bytes, PreviewInfo]:

    if not os.path.isfile(container_path):
        raise FileNotFoundError(f"Container nicht gefunden: {container_path}")

    name = meta_entry.get("name", "<unnamed>")
    plain_size = int(meta_entry.get("size", 0) or 0)
    offset = int(meta_entry["offset"])
    blob_len = int(meta_entry["length"])

    if blob_len < (16 + 12 + 16 + 32):
        raise ValueError("Blob zu klein / ungültig")

    # komplette Datei in den RAM laden – aber mit Sicherheitslimit
    max_bytes = max(0, int(max_bytes))
    if max_bytes and plain_size and plain_size > max_bytes:
        # vollständige RAM-Vorschau ohne Sinn, also rauslassen
        raise ValueError(
            f"Datei zu groß für Vorschau (Größe: {plain_size / (1024**2):.2f} MB, Limit: {max_bytes / (1024**2):.2f} MB)"
        )

    with open(container_path, "rb") as fh:
        fh.seek(offset)
        file_nonce = fh.read(16)
        nonce = fh.read(12)

        if len(file_nonce) != 16 or len(nonce) != 12:
            raise IOError("Konnte Nonces nicht lesen (EOF)")

        ciphertext_len = blob_len - (16 + 12 + 16 + 32)
        if ciphertext_len < 0:
            raise ValueError("Ungültige Blob-Länge")

        ct_start = fh.tell()
        tag_pos = ct_start + ciphertext_len

        # Tag + HMAC lesen (am Ende des Blobs)
        fh.seek(tag_pos)
        tag = fh.read(16)
        hval = fh.read(32)
        if len(tag) != 16 or len(hval) != 32:
            raise IOError("Konnte Tag/HMAC nicht lesen (EOF)")

        # Zurück zum Ciphertext-Start und streamen
        fh.seek(ct_start)

        hm = hmac.HMAC(master_key, hashes.SHA256())
        subkey = derive_subkey(master_key, file_nonce, name)
        decryptor = Cipher(
            algorithms.AES(subkey),
            modes.GCM(nonce, tag),
            backend=default_backend(),
        ).decryptor()

        out = bytearray()
        read_total = 0
        truncated = False

        # Chunkgröße nicht zu groß, damit Cancel schnell wirkt
        chunk_size = 128 * 1024

        while read_total < ciphertext_len:
            if _is_cancelled(stop_event):
                raise RuntimeError("Abgebrochen")

            to_read = min(chunk_size, ciphertext_len - read_total)
            chunk = fh.read(to_read)
            if not chunk:
                raise IOError("Unerwartetes EOF im Ciphertext")

            hm.update(chunk)
            pt = decryptor.update(chunk)

            # In den RAM schreiben – oder abschneiden (falls max_bytes=0 => unbegrenzt)
            if pt:
                if max_bytes == 0:
                    out.extend(pt)
                else:
                    remaining = max_bytes - len(out)
                    if remaining > 0:
                        out.extend(pt[:remaining])
                        if len(pt) > remaining:
                            truncated = True
                    else:
                        truncated = True

            read_total += len(chunk)
            if progress_cb and ciphertext_len:
                progress_cb(int(read_total / ciphertext_len * 100))

        # finalize prüft implizit das GCM-Tag
        last = decryptor.finalize()
        if last:
            if max_bytes == 0:
                out.extend(last)
            else:
                remaining = max_bytes - len(out)
                if remaining > 0:
                    out.extend(last[:remaining])
                    if len(last) > remaining:
                        truncated = True
                else:
                    truncated = True

        # HMAC verifizieren
        hm.verify(hval)

    data = bytes(out)
    info = PreviewInfo(
        name=name,
        size=plain_size if plain_size else len(data),
        loaded_bytes=len(data),
        truncated=truncated,
    )
    return data, info


def _guess_kind(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    if ext in {
        ".txt",
        ".log",
        ".md",
        ".py",
        ".json",
        ".csv",
        ".xml",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".java",
    }:
        return "text"
    if ext in {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"}:
        return "image"
    if ext in {".pdf"}:
        return "pdf"
    if ext in {
        ".mp4",
        ".m4v",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".wmv",
        ".mpg",
        ".mpeg",
        ".3gp",
        ".3g2",
        ".flv",
    }:
        return "video"
    return "binary"


def _hexdump(data: bytes, max_bytes: int = PREVIEW_HEX_BYTES) -> str:
    view = data[: max(0, int(max_bytes))]
    lines = []
    for i in range(0, len(view), 16):
        chunk = view[i : i + 16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08X}  {hexpart:<47}  {asciipart}")
    if len(data) > len(view):
        lines.append(f"... ({len(data) - len(view)} Bytes nicht angezeigt)")
    return "\n".join(lines)


def _decode_text(data: bytes) -> tuple[str, str]:
    # Erst UTF-8, dann Latin-1 als Fallback
    try:
        return data.decode("utf-8"), "utf-8"
    except Exception:
        try:
            return data.decode("utf-8", errors="replace"), "utf-8 (replace)"
        except Exception:
            return data.decode("latin-1", errors="replace"), "latin-1 (replace)"


class PreviewDialog(QDialog):
    def __init__(self, parent: QWidget, filename: str, data: bytes, info: PreviewInfo):
        super().__init__(parent)
        self.setWindowTitle(f"Vorschau: {filename}")
        self.resize(900, 650)
        self.setMinimumSize(700, 500)

        # State für Zoombare Inhalte (Bilder / gerenderte PDFs)
        self._orig_pixmap: QPixmap | None = None
        self._image_label: QLabel | None = None
        self._scroll_area: QScrollArea | None = None
        self._zoom_slider: QSlider | None = None
        self._zoom_label: QLabel | None = None
        self._video_buffer: QBuffer | None = None
        self._video_position_slider: QSlider | None = None
        self._video_time_label: QLabel | None = None
        self.player = None

        layout = QVBoxLayout(self)

        header = QLabel()
        header.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        size_text = (
            f"{info.size / (1024**2):.2f} MB"
            if info.size >= 1024**2
            else f"{info.size} B"
        )
        loaded_text = (
            f"{info.loaded_bytes / (1024**2):.2f} MB"
            if info.loaded_bytes >= 1024**2
            else f"{info.loaded_bytes} B"
        )
        trunc = " (abgeschnitten)" if info.truncated else ""
        header.setText(f"<b>{info.name}</b>")
        layout.addWidget(header)

        kind = _guess_kind(filename)
        if kind == "image":
            self._build_image(layout, data)
        elif kind == "pdf":
            if not self._build_pdf(layout, data):
                self._build_binary(
                    layout,
                    data,
                    hint="PDF-Vorschau ist in dieser Installation nicht verfügbar. Bitte setze dich mit dem Support in Verbindung.",
                )
        elif kind == "video":
            if not self._build_video(layout, data, filename):
                self._build_binary(
                    layout,
                    data,
                    hint="Video-Vorschau ist in dieser Installation nicht verfügbar. Bitte setze dich mit dem Support in Verbindung.",
                )
        elif kind == "text":
            self._build_text(layout, data)
        else:
            self._build_binary(layout, data)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)

        btn_close = QPushButton("Schließen")
        btn_close.clicked.connect(self.close)
        btn_row.addWidget(btn_close)

        layout.addLayout(btn_row)

    def _build_text(self, layout: QVBoxLayout, data: bytes):
        view = data[:PREVIEW_TEXT_SHOW_BYTES]
        text, enc = _decode_text(view)

        box = QTextEdit()
        box.setReadOnly(True)
        box.setFont(QFont("Consolas", 10))
        box.setPlainText(text)

        hint = QLabel(f"Text-Encoding: {enc} — angezeigt: {len(view)} Bytes")
        hint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(hint)
        layout.addWidget(box, 1)

    def _build_image(self, layout: QVBoxLayout, data: bytes):
        pix = QPixmap()
        if not pix.loadFromData(data):
            self._build_binary(layout, data, hint="Bild konnte nicht dekodiert werden.")
            return
        self._setup_zoomable_pixmap(layout, pix)

    def _setup_zoomable_pixmap(
        self, layout: QVBoxLayout, pixmap: QPixmap, info_text: str | None = None
    ):
        """
        Baut eine scrollbare, zoombare Bildansicht auf (für Bilder und gerenderte PDFs).
        """
        self._orig_pixmap = pixmap

        if info_text:
            info_label = QLabel(info_text)
            info_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            layout.addWidget(info_label)

        self._image_label = QLabel()
        self._image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self._scroll_area = QScrollArea()
        self._scroll_area.setWidgetResizable(True)
        self._scroll_area.setWidget(self._image_label)
        layout.addWidget(self._scroll_area, 1)

        # Zoom-Steuerung
        zoom_row = QHBoxLayout()
        zoom_row.addWidget(QLabel("Zoom:"))

        self._zoom_slider = QSlider(Qt.Orientation.Horizontal)
        self._zoom_slider.setRange(10, 400)  # 10% – 400%
        self._zoom_slider.setValue(100)
        self._zoom_slider.valueChanged.connect(self._on_zoom_changed)
        zoom_row.addWidget(self._zoom_slider, 1)

        self._zoom_label = QLabel("100 %")
        zoom_row.addWidget(self._zoom_label)

        layout.addLayout(zoom_row)

        # Initial anwenden
        self._apply_zoom()

    def _on_zoom_changed(self, value: int):
        if self._zoom_label is not None:
            self._zoom_label.setText(f"{value} %")
        self._apply_zoom()

    def _apply_zoom(self):
        if not self._orig_pixmap or not self._image_label or not self._zoom_slider:
            return
        factor = max(0.1, self._zoom_slider.value() / 100.0)
        w = max(1, int(self._orig_pixmap.width() * factor))
        h = max(1, int(self._orig_pixmap.height() * factor))
        scaled = self._orig_pixmap.scaled(
            w,
            h,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self._image_label.setPixmap(scaled)

    def _build_pdf(self, layout: QVBoxLayout, data: bytes) -> bool:
        # Option 1: QtPdf (falls in PyQt6 verfügbar)
        try:
            from PyQt6.QtPdf import QPdfDocument  # type: ignore
            from PyQt6.QtPdfWidgets import QPdfView  # type: ignore

            doc = QPdfDocument(self)
            # loadFromData gibt True/False zurück
            if doc.loadFromData(data):
                view = QPdfView()
                view.setDocument(doc)
                # Lesbare Standardeinstellung: Seite einpassen
                try:
                    view.setZoomMode(QPdfView.ZoomMode.FitInView)  # type: ignore[attr-defined]
                except Exception:
                    pass
                layout.addWidget(view, 1)
                return True
        except ImportError:
            pass
        except Exception:
            # QtPdf vorhanden, aber Fehler beim Laden
            pass

        # Option 2: PyMuPDF (fitz) - sehr beliebte PDF-Bibliothek
        try:
            import fitz  # PyMuPDF

            doc = fitz.open(stream=data, filetype="pdf")
            if doc.page_count > 0:
                # Erste Seite als Bild rendern (Basisauflösung, UI-Zoom wird separat gesteuert)
                page = doc[0]
                zoom = 1.0
                mat = fitz.Matrix(zoom, zoom)
                pix = page.get_pixmap(matrix=mat)

                # QPixmap aus Pixmap-Bytes erstellen
                img_data = pix.tobytes("png")
                qpix = QPixmap()
                if qpix.loadFromData(img_data, "PNG"):
                    info = f"PDF-Seite 1 von {doc.page_count}"
                    self._setup_zoomable_pixmap(layout, qpix, info_text=info)

                    # Button zum Öffnen im externen Viewer
                    btn_open = QPushButton(
                        "Vollständiges PDF im Standard-Viewer öffnen"
                    )
                    btn_open.clicked.connect(lambda: self._open_pdf_external(data))
                    layout.addWidget(btn_open)

                    doc.close()
                    return True
                doc.close()
        except ImportError:
            pass
        except Exception:
            pass

        # Option 3: Externer Viewer als Fallback
        btn_open = QPushButton("PDF im Standard-Viewer öffnen")
        btn_open.clicked.connect(lambda: self._open_pdf_external(data))
        layout.addWidget(btn_open)

        hint = QLabel(
            "PDF-Vorschau nicht verfügbar.\n"
            "Alternativ: Klicke auf den Button, um das PDF im Standard-Viewer zu öffnen."
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        return False

    def _build_video(self, layout: QVBoxLayout, data: bytes, filename: str) -> bool:
        # Option 1: In-App Video via QtMultimedia
        try:
            from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer
            from PyQt6.QtMultimediaWidgets import QVideoWidget

            video_widget = QVideoWidget()
            layout.addWidget(video_widget, 1)

            self.player = QMediaPlayer(self)
            audio = QAudioOutput(self)
            self.player.setAudioOutput(audio)
            self.player.setVideoOutput(video_widget)

            # Daten im RAM halten, QBuffer muss referenziert bleiben
            qbytes = QByteArray(data)
            buf = QBuffer(self)
            buf.setData(qbytes)
            buf.open(QIODevice.OpenModeFlag.ReadOnly)

            try:
                self.player.setSourceDevice(buf)
            except Exception:
                buf.close()
                return self._build_video_external(layout, data, filename)

            # UI Controls
            controls = QHBoxLayout()
            btn_toggle = QPushButton("Play")
            controls.addWidget(btn_toggle)

            pos_slider = QSlider(Qt.Orientation.Horizontal)
            pos_slider.setRange(0, 0)
            controls.addWidget(pos_slider, 1)

            time_label = QLabel("00:00 / 00:00")
            controls.addWidget(time_label)

            layout.addLayout(controls)

            def _format_ms(ms: int) -> str:
                s = max(0, ms // 1000)
                m = s // 60
                h = m // 60
                s = s % 60
                m = m % 60
                if h:
                    return f"{h:02d}:{m:02d}:{s:02d}"
                return f"{m:02d}:{s:02d}"

            def _update_time(pos_ms: int, dur_ms: int):
                time_label.setText(f"{_format_ms(pos_ms)} / {_format_ms(dur_ms)}")

            def _toggle():
                if self.player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
                    self.player.pause()
                    btn_toggle.setText("Play")
                else:
                    self.player.play()
                    btn_toggle.setText("Pause")

            btn_toggle.clicked.connect(_toggle)

            def _on_duration_changed(dur: int):
                pos_slider.setRange(0, max(0, dur))
                _update_time(self.player.position(), dur)

            def _on_position_changed(pos: int):
                if not pos_slider.isSliderDown():
                    pos_slider.setValue(pos)
                _update_time(pos, self.player.duration())

            def _on_slider_moved(val: int):
                self.player.setPosition(val)

            self.player.durationChanged.connect(_on_duration_changed)
            self.player.positionChanged.connect(_on_position_changed)
            pos_slider.sliderMoved.connect(_on_slider_moved)

            self._video_buffer = buf
            self._video_position_slider = pos_slider
            self._video_time_label = time_label
            print("finished building internal")

            return True
        except ImportError:
            return self._build_video_external(layout, data, filename)
        except Exception:
            return self._build_video_external(layout, data, filename)

    def _build_video_external(
        self, layout: QVBoxLayout, data: bytes, filename: str
    ) -> bool:
        btn_open = QPushButton("Video im Standard-Player öffnen")
        btn_open.clicked.connect(lambda: self._open_video_external(data, filename))
        layout.addWidget(btn_open)

        hint = QLabel(
            "Video-Vorschau nicht verfügbar. Möglicherweise unterstützt Ihre Installation dieses System nicht.\n"
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)
        print("finished building external")
        return False

    def _open_video_external(self, data: bytes, filename: str):
        """Öffnet Video in temporärer Datei mit Standard-Player"""
        try:
            suffix = os.path.splitext(filename)[1] or ".mp4"
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            system = platform.system()
            if system == "Windows":
                os.startfile(tmp_path)
            elif system == "Darwin":
                subprocess.run(["open", tmp_path])
            else:
                subprocess.run(["xdg-open", tmp_path])
        except Exception as e:
            QMessageBox.warning(
                self,
                "Fehler",
                f"Konnte Video nicht öffnen: {e}\n"
                f"Temporäre Datei: {tmp_path if 'tmp_path' in locals() else 'N/A'}",
            )
        print("finished opening external")

    def _open_pdf_external(self, data: bytes):
        """Öffnet PDF in temporärer Datei mit Standard-Viewer"""
        try:
            # Temporäre PDF-Datei erstellen
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                tmp.write(data)
                tmp_path = tmp.name

            # Plattform-spezifisch öffnen
            system = platform.system()
            if system == "Windows":
                os.startfile(tmp_path)
            elif system == "Darwin":  # macOS
                subprocess.run(["open", tmp_path])
            else:  # Linux
                subprocess.run(["xdg-open", tmp_path])

            # Datei später löschen (optional - könnte auch bleiben)
            time.sleep(5)
            os.unlink(tmp_path)  # Auskommentiert, damit User das PDF behalten kann
        except Exception as e:
            QMessageBox.warning(
                self,
                "Fehler",
                f"Konnte PDF nicht öffnen: {e}\n"
                f"Temporäre Datei: {tmp_path if 'tmp_path' in locals() else 'N/A'}",
            )

    def _build_binary(self, layout: QVBoxLayout, data: bytes, hint: str = ""):
        label = QLabel(
            "❌ Dieser Dateityp wird leider aktuell nicht unterstützt.\nUnterstützte Dateitypen: .pdf, .txt, .png, .jpg, .jpeg, .bmp, .gif, .webp, .mp4, .m4v, .mov, .avi, .mkv, .webm, .wmv, .mpg, .mpeg, .3gp, .3g2, .flv"
        )
        label.setWordWrap(True)
        label.setAlignment(
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignVCenter
        )
        label.setStyleSheet("""
            QLabel {
                color: #aa0000;
                font-size: 14px;
                padding: 20px;
            }
        """)
        layout.addWidget(label, 1)

    def _copy_best(self, kind: str, data: bytes):
        if kind == "text":
            view = data[:PREVIEW_TEXT_SHOW_BYTES]
            text, _ = _decode_text(view)
            QGuiApplication.clipboard().setText(text)
        else:
            QGuiApplication.clipboard().setText(_hexdump(data))

    def closeEvent(self, a0):
        if self.player:
            self.player.pause()
        a0.accept()


def show_preview(parent: QWidget, filename: str, data: bytes, info: PreviewInfo):
    """
    Öffnet einen modalen Vorschau-Dialog für die bereits in den RAM geladenen Bytes.
    """
    if not data:
        QMessageBox.information(
            parent, "Vorschau", "Keine Daten für die Vorschau vorhanden."
        )
        return
    dlg = PreviewDialog(parent, filename, data, info)
    dlg.exec()
