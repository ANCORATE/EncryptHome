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
# Dialoge + Widgets (aus main.py)
# ============================================================

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


class DetailsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ANCORATE – Technische Details")
        self.setFixedSize(600, 520)
        self.setWindowIcon(get_app_icon())
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        BG = "#0b0f16"
        CARD = "#0f1522"
        BORDER = "rgba(255,255,255,0.08)"
        ACCENT = "#2f7cf6"  # Blauer Akzent (Hauptfenster-Design)
        TEXT = "#e6eef8"
        MUTED = "#9fb0d8"
        TAG_BG = "#111827"
        TAG_FG = "#cfd8ea"

        self.setStyleSheet(f"""
            QDialog {{
                background-color: {BG};
                font-family: 'Segoe UI', 'Roboto', Arial;
                color: {TEXT};
            }}
            QScrollArea, QWidget#Scroll {{
                background: transparent;
                border: none;
            }}
            QLabel {{
                color: {TEXT};
                font-family: 'Segoe UI', 'Roboto', Arial;
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
                font-family: 'Segoe UI', 'Roboto', Arial;
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

        # ── Farb-Palette (Hauptfenster-Design, dark_fixed.css) ──────────────
        BG = "#0b0f16"
        PANEL = "#0f1522"
        BORDER = "rgba(255,255,255,0.08)"
        ACCENT = "#2f7cf6"  # Blau – Primary-Button
        ACCENT2 = "#2a78ff"  # Blau für Hover/Fokus
        TEXT = "#e6eef8"
        MUTED = "#9fb0d8"
        SUBTLE = "#cfd8ea"
        BTN_BG = "#0f1522"

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
                border-radius: 8px;
                padding: 9px 22px;
                font-size: 13px;
                font-weight: 600;
            }}
            QPushButton#CloseBtn:hover {{
                background-color: #121a2b;
                color: {TEXT};
                border-color: {ACCENT2};
            }}
            QPushButton#CloseBtn:pressed {{
                background-color: #0b1220;
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
            f"border-radius: 10px; background-color: #111827; padding: 4px; border: 1px solid {BORDER};"
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
            f"background-color: #111827; color: {ACCENT}; font-size: 10px; "
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

