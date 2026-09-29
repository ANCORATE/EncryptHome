#!/usr/bin/env python3
# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; Ausgangspunkt bleibt main.py)
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#

import os
import sys
import platform

from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *

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


def _paths_from_mime(md) -> list:
    """Lokale Dateipfade aus einer MimeData (Drag&Drop / Zwischenablage)."""
    paths = []
    try:
        if md and md.hasUrls():
            for url in md.urls():
                path = url.toLocalFile()
                if path and os.path.isfile(path):
                    paths.append(path)
    except Exception:
        pass
    return paths


def _clipboard_file_paths() -> list:
    try:
        return _paths_from_mime(QGuiApplication.clipboard().mimeData())
    except Exception:
        return []


class FileTree(QTreeWidget):
    """Dateiliste des Tresors als Baum mit Spalten (Name/Größe/Geändert/Typ).

    Ordner und Dateien werden als echte Hierarchie aufgebaut; die Zuordnung
    zum Metadaten-Index (bzw. ("folder", pfad)) steckt in der UserRole der
    Namensspalte. Dateien können innerhalb des Tresors per Drag&Drop in
    Ordner verschoben werden (Signal ``itemsMoved``).
    """

    fileDropped = pyqtSignal(list)
    itemsMoved = pyqtSignal(list, object)  # (meta-Indizes, Ziel-Rolle)

    COL_NAME, COL_SIZE, COL_DATE, COL_TYPE = range(4)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(4)
        self.setHeaderLabels(["Name", "Größe", "Geändert", "Typ"])
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setRootIsDecorated(True)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setExpandsOnDoubleClick(False)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDropIndicatorShown(True)
        self.header().setStretchLastSection(False)
        self.setColumnWidth(self.COL_SIZE, 90)
        self.setColumnWidth(self.COL_DATE, 150)
        self.setColumnWidth(self.COL_TYPE, 80)
        self.header().setSectionResizeMode(
            self.COL_NAME, QHeaderView.ResizeMode.Stretch
        )

    # ---- Helfer zum Aufbau der Baumzeilen ----
    def make_item(self, role, columns, icon=None, bold=False):
        item = QTreeWidgetItem([str(c) for c in columns])
        item.setData(self.COL_NAME, Qt.ItemDataRole.UserRole, role)
        if icon is not None and not icon.isNull():
            item.setIcon(self.COL_NAME, icon)
        if bold:
            font = QFont(item.font(self.COL_NAME))
            font.setBold(True)
            item.setFont(self.COL_NAME, font)
        return item

    def role(self, item):
        return item.data(self.COL_NAME, Qt.ItemDataRole.UserRole) if item else None

    def count(self) -> int:
        """Kompatibilität mit der früheren QListWidget-API (Top-Level-Einträge)."""
        return self.topLevelItemCount()

    def selected_roles(self):
        return [self.role(it) for it in self.selectedItems()]

    def drop_target_role(self, pos):
        item = self.itemAt(pos)
        return self.role(item) if item is not None else None

    # ---- Ziehen & Ablegen (lokale Dateien + Verschieben im Tresor) ----
    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if not self.isEnabled():
            event.ignore()
            return
        paths = _paths_from_mime(event.mimeData())
        if paths:
            self.fileDropped.emit(paths)
            event.acceptProposedAction()
            return
        if event.source() is self:
            roles = [r for r in self.selected_roles() if isinstance(r, int)]
            pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
            target = self.drop_target_role(pos)
            if roles:
                self.itemsMoved.emit(roles, target)
            event.acceptProposedAction()
            return
        event.ignore()

    def add_vault_entry(self, entry: VaultEntry):
        item = self.make_item(entry, (entry.name, "", "", ""))
        self.addTopLevelItem(item)

    def selected_entries(self):
        return [it for it in self.selected_roles() if isinstance(it, VaultEntry)]

    def selected_file_paths(self) -> list:
        return [it for it in self.selected_roles() if isinstance(it, str)]

    def keyPressEvent(self, event):
        # Strg+V: Dateien aus der Zwischenablage einfügen (kopierte Dateien)
        if (
            self.isEnabled()
            and event.key() == Qt.Key.Key_V
            and bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        ):
            paths = _clipboard_file_paths()
            if paths:
                self.fileDropped.emit(paths)
                event.accept()
                return
        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        ov = getattr(self, "_overlay", None)
        if ov is not None and ov.isVisible():
            self._center_overlay(ov)

    def set_overlay(self, widget):
        self._overlay = widget

    def _center_overlay(self, ov):
        x = max(0, (self.width() - ov.width()) // 2)
        y = max(0, (self.height() - ov.height()) // 2)
        ov.move(x, y)


class FileGrid(QListWidget):
    """Raster-/Kachelansicht des aktuellen Ordners.

    Zeigt Ordner und Dateien als Kacheln; Dateien können per Drag&Drop auf
    Ordnerkacheln oder in den leeren Bereich (Wurzel) verschoben werden.
    """

    fileDropped = pyqtSignal(list)
    itemsMoved = pyqtSignal(list, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setViewMode(QListView.ViewMode.IconMode)
        self.setIconSize(QSize(44, 44))
        self.setGridSize(QSize(140, 96))
        self.setResizeMode(QListView.ResizeMode.Adjust)
        self.setWrapping(True)
        self.setSpacing(10)
        self.setUniformItemSizes(True)
        self.setMovement(QListView.Movement.Static)
        self.setWordWrap(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDropIndicatorShown(True)

    def make_item(self, role, text, icon=None, bold=False):
        item = QListWidgetItem(str(text))
        item.setData(Qt.ItemDataRole.UserRole, role)
        item.setTextAlignment(Qt.AlignmentFlag.AlignHCenter)
        if icon is not None and not icon.isNull():
            item.setIcon(icon)
        if bold:
            font = QFont(item.font())
            font.setBold(True)
            item.setFont(font)
        return item

    def role(self, item):
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def selected_roles(self):
        return [self.role(it) for it in self.selectedItems()]

    def drop_target_role(self, pos):
        item = self.itemAt(pos)
        return self.role(item) if item is not None else None

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.source() is self:
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        if not self.isEnabled():
            event.ignore()
            return
        paths = _paths_from_mime(event.mimeData())
        if paths:
            self.fileDropped.emit(paths)
            event.acceptProposedAction()
            return
        if event.source() is self:
            roles = [r for r in self.selected_roles() if isinstance(r, int)]
            pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
            target = self.drop_target_role(pos)
            if roles:
                self.itemsMoved.emit(roles, target)
            event.acceptProposedAction()
            return
        event.ignore()

    def keyPressEvent(self, event):
        if (
            self.isEnabled()
            and event.key() == Qt.Key.Key_V
            and bool(event.modifiers() & Qt.KeyboardModifier.ControlModifier)
        ):
            paths = _clipboard_file_paths()
            if paths:
                self.fileDropped.emit(paths)
                event.accept()
                return
        super().keyPressEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        ov = getattr(self, "_overlay", None)
        if ov is not None and ov.isVisible():
            self._center_overlay(ov)

    def set_overlay(self, widget):
        self._overlay = widget

    def _center_overlay(self, ov):
        x = max(0, (self.width() - ov.width()) // 2)
        y = max(0, (self.height() - ov.height()) // 2)
        ov.move(x, y)


# Kompatibilitäts-Alias: frühere, flache Listenklasse.
FileDropList = FileTree


class Toast(QFrame):
    """Kompakte, nicht-blockierende Erfolgs-Meldung unten rechts im Fenster.

    Zeitgesteuert ein-/ausblendend (ohne Fenster-Opazität, um Plattform-
    Einschränkungen wie Wayland zu umgehen) und ohne Maus-Interaktion.
    Mehrere Toasts stapeln sich nach oben.
    """

    _stack = []

    def __init__(self, parent, title, message, timeout_ms=3200):
        super().__init__(parent)
        self.setObjectName("Toast")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(12, 8, 14, 9)
        lay.setSpacing(2)
        self._title_lbl = QLabel(title)
        self._title_lbl.setObjectName("ToastTitle")
        self._msg_lbl = QLabel(message)
        self._msg_lbl.setObjectName("ToastMsg")
        self._msg_lbl.setWordWrap(True)
        lay.addWidget(self._title_lbl)
        lay.addWidget(self._msg_lbl)
        self.adjustSize()
        parent_w = self.parentWidget()
        if parent_w is not None:
            parent_w.installEventFilter(self)
        QTimer.singleShot(timeout_ms, self._dismiss)

    def showEvent(self, event):
        super().showEvent(event)
        Toast._stack.append(self)
        Toast._move_all()
        self.raise_()

    def hideEvent(self, event):
        super().hideEvent(event)
        if self in Toast._stack:
            Toast._stack.remove(self)
        Toast._move_all()

    def closeEvent(self, event):
        if self in Toast._stack:
            Toast._stack.remove(self)
        super().closeEvent(event)

    def eventFilter(self, obj, event):
        if obj is self.parentWidget() and event.type() == QEvent.Type.Resize:
            self._move_to_corner()
        return super().eventFilter(obj, event)

    def _move_to_corner(self):
        parent_w = self.parentWidget()
        if parent_w is None:
            return
        above = [t for t in Toast._stack if t is not self and t.isVisible()]
        margin = 16
        x = parent_w.width() - self.width() - margin
        y = parent_w.height() - self.height() - margin
        for t in above:
            y -= t.height() + 8
        self.move(max(0, x), max(0, y))

    def _dismiss(self):
        try:
            self.hide()
            self.deleteLater()
        except Exception:
            pass

    @classmethod
    def _move_all(cls):
        for t in cls._stack:
            try:
                t._move_to_corner()
            except Exception:
                pass


class EmptyStateOverlay(QFrame):
    """Hinweis-Overlay für leere Zustände (kein Tresor / leerer Tresor)."""

    createRequested = pyqtSignal()
    openRequested = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.setObjectName("EmptyState")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(6)
        self._title_lbl = QLabel("")
        self._title_lbl.setObjectName("EmptyStateTitle")
        self._title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hint_lbl = QLabel("")
        self._hint_lbl.setObjectName("EmptyStateHint")
        self._hint_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._hint_lbl.setWordWrap(True)

        self._btn_create = QPushButton("Neuer Tresor")
        self._btn_create.setObjectName("EmptyStateBtn")
        self._btn_create.clicked.connect(self.createRequested)
        self._btn_open = QPushButton("Tresor öffnen")
        self._btn_open.setObjectName("EmptyStateBtn")
        self._btn_open.clicked.connect(self.openRequested)
        self._btn_row = QHBoxLayout()
        self._btn_row.addStretch(1)
        self._btn_row.addWidget(self._btn_create)
        self._btn_row.addWidget(self._btn_open)
        self._btn_row.addStretch(1)

        lay.addStretch(1)
        lay.addWidget(self._title_lbl)
        lay.addWidget(self._hint_lbl)
        lay.addSpacing(10)
        lay.addLayout(self._btn_row)
        lay.addStretch(1)

        self.set_interactive(False)

    def set_text(self, title, hint, buttons: bool = False):
        self._title_lbl.setText(title)
        self._hint_lbl.setText(hint)
        self.set_interactive(buttons)
        self.adjustSize()

    def set_interactive(self, interactive: bool):
        self.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents, not interactive
        )
        self._btn_create.setVisible(interactive)
        self._btn_open.setVisible(interactive)
        self.setFocusPolicy(
            Qt.FocusPolicy.StrongFocus if interactive else Qt.FocusPolicy.NoFocus
        )


def show_toast(parent, title, message, timeout_ms=3200):
    """Zeigt eine kurze Erfolgs-Meldung unten rechts an (nicht-blockierend)."""
    try:
        if parent is None:
            return
        Toast(parent, title, message, timeout_ms).show()
    except Exception:
        pass


class OnboardingDialog(QDialog):
    """Erst-Start-/Hilfe-Dialog: erklärt Sicherheitsmodell & Gerätebindung."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("Onboarding")
        self.setWindowTitle("ANCORATE – Erste Schritte")
        self.setWindowIcon(get_app_icon())
        self.setModal(True)
        self.setMinimumWidth(920)
        self.resize(900, 460)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 18)
        lay.setSpacing(14)

        title = QLabel("Willkommen bei ANCORATE")
        title.setObjectName("WelcomeTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)

        sub = QLabel("Sicher verschlüsselt. Lokal. Gerätegebunden.")
        sub.setObjectName("WelcomeSubtitle")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(sub)

        sections = [
            (
                "VERSCHLÜSSELUNG",
                "Jeder Tresor wird lokal mit starker AES-Verschlüsselung "
                "geschützt. Ohne dein Tresor-Passwort kann niemand deine "
                "Dateien lesen – nicht einmal dieser Rechner.",
            ),
            (
                "GERÄTEBINDUNG",
                "Der Tresor-Schlüssel ist untrennbar an dieses Gerät und "
                "dein Anmeldekonto gekoppelt. Ein Tresor lässt sich nur "
                "auf dem Gerät öffnen, für das er erstellt wurde.",
            ),
            (
                "DATENSCHUTZ",
                "Es gibt keine Cloud, keine Server und keinen Upload. "
                "Deine Daten verlassen dein Gerät nie und bleiben genau "
                "dort, wo du sie ablegst.",
            ),
        ]
        for header, body in sections:
            h = QLabel(header)
            h.setObjectName("SectionHeader")
            b = QLabel(body)
            b.setObjectName("DescText")
            b.setWordWrap(True)
            lay.addWidget(h)
            lay.addWidget(b)

        lay.addStretch(1)

        tip = QLabel(
            "Tipp: Einmal eingerichtet, öffnest du deinen Tresor mit Strg+O "
            "oder über „Zuletzt verwendete Tresore“ im Menü „Datei“."
        )
        tip.setObjectName("EmptyStateHint")
        tip.setWordWrap(True)
        tip.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(tip)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.ok_button = QPushButton("Weiter")
        self.ok_button.setObjectName("primary")
        self.ok_button.setMinimumWidth(120)
        self.ok_button.clicked.connect(self.accept)
        btn_row.addWidget(self.ok_button)
        btn_row.addStretch(1)
        lay.addLayout(btn_row)


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
        self.setMinimumSize(560, 440)
        self.setWindowIcon(get_app_icon())
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ──────────────────────────────────────────────────────────
        header = QWidget()
        header.setObjectName("HeaderBar")
        header.setFixedHeight(64)
        hlay = QHBoxLayout(header)
        hlay.setContentsMargins(24, 0, 24, 0)

        prefix = QLabel("// ")
        prefix.setObjectName("SectionHeader")
        title = QLabel(f"TECHNISCHE DETAILS ZU ANCORATE {edition} {version}")
        title.setStyleSheet("font-size: 14px; font-weight: bold; letter-spacing: 2px;")

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
            t.setObjectName("SectionHeader")
            fl.addWidget(t)
            fl.addWidget(make_separator())

            grid = QGridLayout()
            grid.setVerticalSpacing(8)
            grid.setHorizontalSpacing(24)
            grid.setColumnStretch(1, 1)
            for i, (k, v) in enumerate(rows):
                k_lbl = QLabel(k)
                k_lbl.setObjectName("MetaKey")
                v_lbl = QLabel(v)
                v_lbl.setObjectName("MetaValue")
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
        footer.setObjectName("Footer")
        footer.setFixedHeight(58)
        flay = QHBoxLayout(footer)
        flay.setContentsMargins(24, 0, 24, 0)

        hint = QLabel(f"Build  {version}")
        hint.setObjectName("Copyright")

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
        self.setMinimumSize(480, 360)
        self.setWindowIcon(get_app_icon())
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )

        # ── Farbgebende Definitionen werden zentral in den Theme-Dateien
        #    (standard-dark.css / standard-white.css) gepflegt. ──────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ─────────────────────────────────────────────────────────────────────
        # 1. HEADER  (Icon + Name + Subtitle)
        # ─────────────────────────────────────────────────────────────────────
        header = QWidget()
        header.setObjectName("HeaderBar")
        hlay = QHBoxLayout(header)
        hlay.setContentsMargins(28, 22, 28, 22)
        hlay.setSpacing(18)

        # Icon
        icon_lbl = QLabel()
        px = get_app_icon().pixmap(84, 84)
        if px.isNull():
            px = QPixmap(94, 94)
            px.fill(QColor("#2f7cf6"))
        icon_lbl.setPixmap(px)
        icon_lbl.setFixedSize(94, 94)

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
        badge.setObjectName("VersionBadge")
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
        clay.addWidget(make_separator())

        meta = QGridLayout()
        meta.setVerticalSpacing(9)
        meta.setHorizontalSpacing(32)
        meta.setColumnMinimumWidth(0, 130)

        rows = [
            ("Version", f"{version}  ({type_edition})"),
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
        arrow.setObjectName("DetailLink")

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

        # Styling wird zentral über die Theme-Dateien übernommen.

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
        subtitle.setObjectName("ReqInfo")
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
        self.setMinimumSize(640, 320)

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
        self.title.setObjectName("WelcomeTitle")
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # =========================
        # Subtitle
        # =========================
        self.subtitle = QLabel("Secure · Local · Trusted")
        self.subtitle.setObjectName("WelcomeSubtitle")
        self.subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

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


class EditInVaultDialog(QDialog):
    """Nicht-modaler Dialog während einer In-Tresor-Bearbeitung.

    Zeigt an, welche Datei gerade extern bearbeitet wird. Änderungen werden
    automatisch nach jedem Speichern wieder in den Tresor verschlüsselt.
    """

    sessionFinished = pyqtSignal()
    allow_close = True

    def __init__(self, parent: QWidget | None, filename: str):
        super().__init__(parent)
        self.setWindowTitle("ANCORATE – In-Tresor-Bearbeitung")
        self.setWindowIcon(get_app_icon())
        self.setModal(False)
        # Tool + StaysOnTop: Der Dialog erscheint nicht in der Taskleiste
        # und bleibt über allen anderen Fenstern sichtbar, auch wenn der
        # Editor (z. B. Word) im Vordergrund ist.
        self.setWindowFlags(
            Qt.WindowType.WindowStaysOnTopHint
            | Qt.WindowType.Tool
            | (
                self.windowFlags()
                & ~Qt.WindowType.WindowContextHelpButtonHint
                & ~Qt.WindowType.WindowMinimizeButtonHint
            )
        )
        self.resize(360, 150)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)

        title = QLabel("Datei wird bearbeitet")
        title.setStyleSheet("font-weight: bold; font-size: 15px;")
        layout.addWidget(title)

        self._name_label = QLabel(filename)
        self._name_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self._name_label.setWordWrap(True)
        layout.addWidget(self._name_label)

        info = QLabel(
            "Die Datei wurde entschlüsselt und in Ihrer Standardanwendung geöffnet.\n"
            "Jedes Speichern verschlüsselt die Änderungen automatisch wieder in den Tresor."
        )
        info.setWordWrap(True)
        info.setObjectName("PreviewError")
        layout.addWidget(info)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        self.finish_button = QPushButton("Bearbeitung abschließen")
        self.finish_button.clicked.connect(self.close)
        btn_row.addWidget(self.finish_button)
        layout.addLayout(btn_row)

    def closeEvent(self, event):
        if not self.allow_close:
            event.ignore()
            return
        self.sessionFinished.emit()
        super().closeEvent(event)

