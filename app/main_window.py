#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; Ausgangspunkt bleibt main.py)
#

import os
import struct
import time
import subprocess
import platform
import secrets
import tempfile
import threading
import copy
from collections import OrderedDict

from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *

# Interne Module
from decrypt import *
from decrypt_preview import PREVIEW_MAX_BYTES, PreviewDecryptWorker, show_preview
from encrypt import *
from utilities.container_ops import (
    atomic_container_write,
    recover_container_metadata,
)
from utilities.file_types import type_label
from utilities.file_type_icons import file_type_icon

# Utilities
from utilities.screenshot_protection import (
    install_screenshot_protection,
    uninstall_screenshot_protection,
)
from utilities.settings import *
from utilities.ui_icons import (
    active_icon_colors,
    has_icon,
    icon_size_hint,
    render_pixmap,
    set_active_ui_theme,
    ui_icon,
)

from app.core import *
from app.passwords import *
from app.workers import *
from app.dialogs import *
from app.power_lock import PowerLockMonitor

# ============================================================
# Ordner-Semantik (Phase F)
# ============================================================
# Ordner werden als logische Pfade im Feld "name" geführt (z.B.
# "Ordner/Unterordner/datei.txt"); der Root hat das Präfix "". Die
# explizite Ordner-Liste liegt als optionale Liste "folders" in der
# verschlüsselten Meta und wird von allen bestehenden Schreibpfaden
# unverändert mitgeschrieben.
FOLDER_SEP = "/"


def _normalize_logical_path(value: str, *, allow_empty: bool = False) -> str:
    """Normalize a user-controlled logical folder path."""
    raw = str(value or "").replace("\\", FOLDER_SEP).strip()
    if not raw:
        if allow_empty:
            return ""
        raise ValueError("Ordnername darf nicht leer sein.")
    if raw.startswith(FOLDER_SEP) or ":" in raw:
        raise ValueError("Absolute Ordnerpfade sind nicht erlaubt.")

    parts = [part.strip() for part in raw.strip(FOLDER_SEP).split(FOLDER_SEP)]
    if not parts or any(not part or part in (".", "..") for part in parts):
        raise ValueError("Ungültiger Ordnerpfad.")
    return FOLDER_SEP.join(parts)


def _folder_of(name: str) -> str:
    idx = name.rfind(FOLDER_SEP)
    return name[:idx] if idx >= 0 else ""


def _item_name(name: str) -> str:
    idx = name.rfind(FOLDER_SEP)
    return name[idx + 1:] if idx >= 0 else name
# ============================================================
# Hauptfenster (App-Klasse, aus main.py)
# ============================================================

class App(QMainWindow):
    LAN_DISC_PORT = 48291  # UDP-Port für LAN-Discovery
    LAN_TCP_PORT = 48292  # TCP-Port für LAN-Verbindungen
    LAN_MAGIC = b"ANCORATE_DISCOVER_V1"
    LAN_CHUNK = 64 * 1024  # 64 KiBp

    # Fallback, falls die Toolbar vor dem ersten Messen noch nicht existiert.
    TOOLBAR_WIDE_MIN_WIDTH = 900

    def __init__(self):  # Hauptfenster der Anwendung
        super().__init__()
        self.setWindowTitle(f"ANCORATE {edition} {version} - kein Tresor geöffnet")
        self.setWindowIcon(get_app_icon())
        # 1200 px, damit die beschriftete Leiste (gemessener Bedarf ~1050 px)
        # auch im Standardfenster sichtbar ist. Schmaler schaltet sie selbst
        # auf reine Icons um, _update_responsive_toolbar().
        self.resize(1200, 720)
        self.exporting = False
        self.pwd = ""
        self.container_path = None
        self.master_key = None
        self.flags = 0
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.stop_event = None
        self.progress = None
        self._delete_in_progress = False
        self._delete_close_after = False
        self._delete_committing = False
        self._worker_threads = {}
        self._close_after_workers = False
        self._lan_sharing = False
        self._lan_threads = []
        self._lan_tcp_sock = None
        self._settings_dialog = None
        self.update_worker = None
        self.update_news_shown = False
        self.data = load_settings()
        self.view_mode = "list"
        # Vorschau-Cache (RAM): LRU-Cache für bereits entschlüsselte Bytes
        self._preview_cache: OrderedDict[str, tuple[bytes, object]] = OrderedDict()
        self._preview_cache_bytes: int = 0
        self._preview_cache_limit: int = 200 * 1024 * 1024  # 200 MiB total
        self._preview_max_file_bytes: int = PREVIEW_MAX_BYTES
        # In-Tresor-Bearbeitung (externer Editor auf entschlüsselter Temp-Datei)
        self._edit_session: dict | None = None
        self._edit_cleanup_pending: list = []
        self._edit_poll_timer = QTimer(self)
        self._edit_poll_timer.setInterval(500)
        self._edit_poll_timer.timeout.connect(self._poll_edit_session)

        # ---- GUI Elemente erstellen ----
        # --- Kopfzeile: Tresor-Identität (links) + Suche (rechts) ---
        self.header = QFrame()
        self.header.setObjectName("VaultHeader")
        header_layout = QHBoxLayout(self.header)
        header_layout.setContentsMargins(14, 10, 14, 10)
        header_layout.setSpacing(12)

        self.header_icon = QLabel()
        self.header_icon.setObjectName("VaultHeaderIcon")
        self.header_icon.setFixedSize(36, 36)
        self.header_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._set_header_icon(False)

        name_col = QVBoxLayout()
        name_col.setContentsMargins(0, 0, 0, 0)
        name_col.setSpacing(2)
        self.container_label = QLabel("Kein Tresor geöffnet")
        self.container_label.setObjectName("VaultName")
        self.container_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.path_label = QLabel("")
        self.path_label.setObjectName("VaultMeta")
        self.path_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.path_label.hide()
        name_col.addWidget(self.container_label)
        name_col.addWidget(self.path_label)

        # Suchfeld (rechts in der Kopfzeile, direkt über dem Dateibaum)
        self.search = QLineEdit()
        self.searchbar_content = ""
        self.search.setObjectName("VaultSearch")
        self.search.setPlaceholderText("Im Tresor suchen…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(140)
        self.search.setMaximumWidth(280)
        self.search.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )
        self.search.setEnabled(False)
        # Live-Suche: textChanged feuert im GUI-Thread, sodass keine
        # Qt-Widgets aus einem Hintergrund-Thread angesprochen werden.
        self.search.textChanged.connect(self.start_search)

        header_layout.addWidget(
            self.header_icon, 0, Qt.AlignmentFlag.AlignVCenter
        )
        header_layout.addLayout(name_col, 1)
        # Ansichts-Umschalter (Liste/Kompakt/Raster) und Suche sitzen rechts;
        # die Aktionen selbst werden in _build_view_segment() befuellt.
        self.header_layout = header_layout
        header_layout.addWidget(self.search, 0, Qt.AlignmentFlag.AlignVCenter)

        # --- Dateiliste: Baum + Raster in einem Stapel ---
        self.view_stack = QStackedWidget()
        self._tree = FileTree()
        self._grid = FileGrid()
        for view in (self._tree, self._grid):
            view.fileDropped.connect(self.add_files)
            view.itemsMoved.connect(self._on_items_moved)
            view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            view.customContextMenuRequested.connect(self._on_context_menu)
            view.itemDoubleClicked.connect(self._on_item_double_clicked)
            self.view_stack.addWidget(view)
        self._overlays = {}
        self.file_list = self._tree  # aktuell aktive Ansicht

        # Statusmeldungen in der nativen Statusleiste
        self.status = QLabel(
            "Bereit. Kein Tresor geöffnet. - 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin"
        )
        self.status.setObjectName("status")
        self.status.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        self.statusBar().addWidget(self.status, 1)

        central = QWidget()
        central_layout = QVBoxLayout(central)
        central_layout.setContentsMargins(12, 10, 12, 10)
        central_layout.setSpacing(10)
        central_layout.addWidget(self.header)
        central_layout.addWidget(self.view_stack, 1)
        self.setCentralWidget(central)

        # --- Toolbar ---
        self._create_actions()
        self._build_view_segment()
        self._build_toolbar()
        self._set_vault_actions_enabled(False)

        # Ordner-Navigation/-Entfaltung (Sitzungszustand)
        self.current_folder = ""
        self._expanded_folders = None  # None = alle Ordner entfaltet

        # --- Shortcuts ---
        self.create_vault_sc = QShortcut(QKeySequence("Ctrl+N"), self)
        self.add_sec_sc = QShortcut(QKeySequence("Ctrl++"), self)
        self.ex_selected_sc = QShortcut(QKeySequence("Ctrl+E"), self)
        self.ex_all_seq = QShortcut(QKeySequence("Alt+E"), self)
        self.open_vault_sc = QShortcut(QKeySequence("Ctrl+O"), self)
        self.remove_sc = QShortcut(QKeySequence("Del"), self)
        self.del_container_sc = QShortcut(QKeySequence("Alt+Del"), self)
        self.search_sc = QShortcut(QKeySequence("Return"), self)
        self.recent_containers_sc = QShortcut(QKeySequence("Ctrl+R"), self)

        # --- Shortcut Verbindungen ---
        self.create_vault_sc.activated.connect(lambda: self.choose_container(2))
        self.add_sec_sc.activated.connect(self.add_file_dialog)
        self.ex_selected_sc.activated.connect(self.export_selected)
        self.ex_all_seq.activated.connect(self.export_all)
        self.open_vault_sc.activated.connect(lambda: self.choose_container(1))
        self.remove_sc.activated.connect(self.delete_selected)
        self.del_container_sc.activated.connect(lambda: self.delete_container())
        self.search_sc.activated.connect(self.start_search)
        self.recent_containers_sc.activated.connect(self.show_recent_containers)

        # Tooltips der Toolbar-Aktionen um die Kürzel ergänzen
        self._register_action_shortcuts()

        self.setStyleSheet(APP_STYLE)

        # Hauptfenster für animierte Theme-Wechsel (Fade-Überblendung) anmelden
        register_main_window(self)

        # Geführter Leerzustand zum Start (kein Tresor geöffnet)
        self._update_empty_state(True)
        
        # ---- Auto-Lock (Inaktivität) ----
        self._auto_lock_timer = QTimer(self)
        self._auto_lock_timer.setSingleShot(True)
        self._auto_lock_timer.timeout.connect(self._auto_lock_triggered)
        self._auto_lock_rearm()
        # Inaktivität (Mouse/Key) app-weit erkennen – auch bei Eingaben in
        # Kind-Widgets (Dateiliste, Suche, Menüleiste), nicht nur im Hauptfenster.
        self._auto_lock_app = QApplication.instance()
        if self._auto_lock_app is not None:
            self._auto_lock_app.installEventFilter(self)

        # ---- Schlaf/Screen-Lock: Tresor sofort sperren ----
        # Nutzt denselben geschützten Sperrpfad wie der Auto-Lock (respektiert
        # laufende Operationen: Export, Add, Bearbeitung, Passwort-Änderung).
        self._power_monitor = PowerLockMonitor(self)
        self._power_monitor.lockRequested.connect(self._auto_lock_triggered)
        self._power_monitor.start()

        self.apply_settings()  # Initial anwenden
        self._set_view_mode(
            str(self.data.get("list_view_mode", "list")), persist=False
        )
        
        # ---- Menüleiste hinzufügen ----
        self.add_menubar()
        
        # ---- File Watcher für sofortige Updates ----
        # Hinweis: Atome Writes (os.replace) beenden den Watch nach dem ersten
        # Ereignis. Die direkte Listener-Benachrichtigung (save_settings) ist
        # deshalb der primäre Weg; der Watcher bleibt für externe Änderungen.
        self._settings_apply_pending = False
        register_settings_listener(self._on_settings_saved)
        self.settings_watcher = QFileSystemWatcher([SETTINGS_FILE], self)
        self.settings_watcher.fileChanged.connect(self.on_settings_changed)
        print("[SETTINGS] File Watcher aktiviert für sofortige Updates")
    
    

    def open_settings(self):
        dialog = SettingsDialog()
        dialog.exec()  # Modal Popup

    def check_updates_quick(self):
        if not hasattr(self, "_settings_dialog") or self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)
        self._settings_dialog.display_category(3)
        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()
        self._settings_dialog.check_updates_manual()

    def start_update_check(self):
        if self.update_worker is not None and self.update_worker.isRunning():
            return

        self.update_worker = StartupUpdateWorker()
        self._track_worker_thread(self.update_worker, container_operation=False)
        self.update_worker.finished.connect(self.on_update_check_finished)
        self.update_worker.error.connect(self.on_update_check_error)
        self.update_worker.start()

    def is_update_available(self, data: dict) -> bool:
        try:
            from utilities.updater import is_newer_version

            return is_newer_version(
                data.get("version", VERSION_FULL), VERSION_FULL
            )
        except Exception:
            return False

    def on_update_check_finished(self, data: dict):
        worker = self.update_worker
        if worker is not None:
            worker.wait()
            worker.deleteLater()
            self._release_worker_thread(worker)
        if self._close_after_workers:
            return
        if not self.is_update_available(data):
            return

        self.status.setText(
            f"Update verfügbar: v{data.get('version')} – Öffnen Sie Einstellungen > Updates"
        )

        self.show_update_news(data)

    def on_update_check_error(self, error_msg: str):
        worker = self.update_worker
        if worker is not None:
            worker.wait()
            worker.deleteLater()
            self._release_worker_thread(worker)
        print(f"[UPDATE] Updatecheck fehlgeschlagen: {error_msg}")

    def _track_worker_thread(self, thread, stop_event=None, *, container_operation=True):
        self._worker_threads[thread] = (stop_event, container_operation)

    def _container_worker_active(self):
        return any(
            container_operation
            for _, container_operation in self._worker_threads.values()
        )

    def _ensure_container_idle(self):
        if not self._container_worker_active():
            return True
        QMessageBox.information(
            self,
            "Vorgang läuft",
            "Bitte warten Sie, bis der laufende Tresorvorgang abgeschlossen ist.",
        )
        return False

    def _release_worker_thread(self, thread):
        self._worker_threads.pop(thread, None)
        if self._close_after_workers and not self._worker_threads:
            QTimer.singleShot(0, self.close)

    def show_update_news(self, data: dict):
        if self.update_news_shown:
            return
        self.update_news_shown = True

        dlg = UpdateNewsDialog(self, data)
        dlg.exec()

    # ------------------ Menüleiste ------------------
    def add_menubar(self):
        if not getattr(self, "act_new", None):
            self._create_actions()
        self._rebuild_menubar()

    def _create_actions(self):
        """Alle Aktionen einmal anlegen; Menü und Toolbar teilen sie sich."""
        # --- Tresor ---
        self.act_new = QAction("Neuer Tresor…", self)
        self.act_new.triggered.connect(lambda: self.choose_container(2))
        self.act_open = QAction("Tresor öffnen…", self)
        self.act_open.triggered.connect(lambda: self.choose_container(1))
        self.act_close = QAction("Tresor schließen", self)
        self.act_close.triggered.connect(self.close_container)
        self.act_change_pwd = QAction("Tresorpasswort ändern…", self)
        self.act_change_pwd.triggered.connect(self.change_container_password_dialog)
        self.act_delete_vault = QAction("Tresor löschen…", self)
        self.act_delete_vault.triggered.connect(self.delete_container)
        self.act_settings = QAction("Einstellungen…", self)
        self.act_settings.triggered.connect(lambda: self.show_settings_dialog())
        self.act_quit = QAction("Beenden", self)
        self.act_quit.setShortcut(QKeySequence("Ctrl+Q"))
        self.act_quit.triggered.connect(self.close)

        # --- Dateien & Ordner ---
        self.act_add = QAction("Datei(en) hinzufügen…", self)
        self.act_add.triggered.connect(self.add_file_dialog)
        self.act_preview = QAction("Dateivorschau", self)
        self.act_preview.triggered.connect(self.preview_selected)
        self.act_edit = QAction("Im Tresor bearbeiten", self)
        self.act_edit.triggered.connect(self.start_in_vault_edit)
        self.act_export = QAction("Datei exportieren…", self)
        self.act_export.triggered.connect(self.export_selected)
        self.act_export_all = QAction("Alles exportieren…", self)
        self.act_export_all.triggered.connect(self.export_all)
        self.act_delete = QAction("Datei löschen", self)
        self.act_delete.triggered.connect(self.delete_selected)
        self.act_new_folder = QAction("Neuer Ordner…", self)
        self.act_new_folder.triggered.connect(self._new_folder)
        self.act_move = QAction("In Ordner verschieben…", self)
        self.act_move.triggered.connect(lambda: self._move_selected_to_folder(""))

        # --- Ansicht ---
        self.act_expand = QAction("Alle Ordner ausklappen", self)
        self.act_expand.triggered.connect(self._expand_all_folders)
        self.act_collapse = QAction("Alle Ordner einklappen", self)
        self.act_collapse.triggered.connect(self._collapse_all_folders)
        self.act_find = QAction("Suchen", self)
        self.act_find.setShortcut(QKeySequence.StandardKey.Find)
        self.act_find.triggered.connect(self._focus_search)

        # --- Hilfe ---
        self.act_onboarding = QAction("Erste Schritte", self)
        self.act_onboarding.triggered.connect(self.show_onboarding_dialog)
        self.act_about = QAction(f"Über {edition} {version_year}", self)
        self.act_about.triggered.connect(self.show_about_dialog)

        self._create_view_actions()

        # Aktionen, die einen geöffneten Tresor benötigen
        self._vault_actions = [
            self.act_close, self.act_change_pwd, self.act_delete_vault,
            self.act_add, self.act_preview, self.act_edit, self.act_export,
            self.act_export_all, self.act_delete, self.act_new_folder,
            self.act_move, self.act_expand, self.act_collapse,
        ]

    def _create_view_actions(self):
        """Umschaltbare Layout-Aktionen (Liste / Kompakt / Raster)."""
        self.act_view_list = QAction("Liste", self)
        self.act_view_compact = QAction("Kompakt", self)
        self.act_view_grid = QAction("Raster", self)
        self.view_group = QActionGroup(self)
        self.view_group.setExclusive(True)
        for action in (self.act_view_list, self.act_view_compact, self.act_view_grid):
            action.setCheckable(True)
            self.view_group.addAction(action)
        self.act_view_list.triggered.connect(lambda: self._set_view_mode("list"))
        self.act_view_compact.triggered.connect(lambda: self._set_view_mode("compact"))
        self.act_view_grid.triggered.connect(lambda: self._set_view_mode("grid"))

    def _set_vault_actions_enabled(self, enabled: bool):
        for action in getattr(self, "_vault_actions", []):
            action.setEnabled(enabled)
        self._update_chrome_visibility()

    def _set_views_enabled(self, enabled: bool):
        """Aktiviert/deaktiviert Baum- und Rasteransicht gemeinsam."""
        self._tree.setEnabled(enabled)
        self._grid.setEnabled(enabled)

    def _rebuild_menubar(self):
        menubar = QMenuBar(self)

        # Datei: Tresor-Lebenszyklus
        file_menu = QMenu("Datei", self)
        self.recent_menu = self._build_recent_submenu()
        file_menu.aboutToShow.connect(self._refresh_recent_submenu)
        file_menu.addAction(self.act_new)
        file_menu.addAction(self.act_open)
        file_menu.addMenu(self.recent_menu)
        file_menu.addSeparator()
        file_menu.addAction(self.act_close)
        file_menu.addAction(self.act_change_pwd)
        file_menu.addAction(self.act_delete_vault)
        file_menu.addSeparator()
        file_menu.addAction(self.act_settings)
        file_menu.addSeparator()
        file_menu.addAction(self.act_quit)

        # Bearbeiten: erst Dateiablage, dann Verwaltung
        edit_menu = QMenu("Bearbeiten", self)
        edit_menu.addAction(self.act_add)
        edit_menu.addSeparator()
        edit_menu.addAction(self.act_preview)
        edit_menu.addAction(self.act_edit)
        edit_menu.addSeparator()
        edit_menu.addAction(self.act_export)
        edit_menu.addAction(self.act_export_all)
        edit_menu.addSeparator()
        edit_menu.addAction(self.act_delete)
        edit_menu.addSeparator()
        edit_menu.addAction(self.act_new_folder)
        edit_menu.addAction(self.act_move)

        # Ansicht
        view_menu = QMenu("Ansicht", self)
        layout_menu = view_menu.addMenu("Layout")
        layout_menu.addAction(self.act_view_list)
        layout_menu.addAction(self.act_view_compact)
        layout_menu.addAction(self.act_view_grid)
        view_menu.addSeparator()
        view_menu.addAction(self.act_expand)
        view_menu.addAction(self.act_collapse)
        view_menu.addSeparator()
        view_menu.addAction(self.act_find)

        # Hilfe
        help_menu = QMenu("Hilfe", self)
        help_menu.addAction(self.act_onboarding)
        help_menu.addSeparator()
        help_menu.addAction(self.act_about)

        menubar.addMenu(file_menu)
        menubar.addMenu(edit_menu)
        menubar.addMenu(view_menu)
        menubar.addMenu(help_menu)

        self.setMenuBar(menubar)

    def _build_toolbar(self):
        """Primäre Aktionen als Icon-Toolbar (Ansicht + Suche in der Kopfzeile)."""
        tb = QToolBar("Toolbar einblenden", self)
        tb.setObjectName("MainToolBar")
        tb.setMovable(False)
        tb.setFloatable(False)
        tb.setIconSize(icon_size_hint())
        tb.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

        self.act_more = QAction("Mehr", self)
        self.act_more.setToolTip("Weitere Aktionen")
        self.act_more.setMenu(self._build_overflow_menu())

        # iconText steuert die Beschriftung des QToolButton, nicht die
        # Menüeinträge: Im Menü bleibt "Datei(en) hinzufügen…" stehen, während
        # die Toolbar eine kurze Beschriftung zeigt - und ohne eine zweite
        # Aktion mit eigenem Enable-Status zu duplizieren.
        self._action_glyphs = {
            self.act_new: "vault-new",
            self.act_open: "vault-open",
            self.act_add: "add-file",
            self.act_preview: "preview",
            self.act_export: "export",
            self.act_delete: "trash",
            self.act_more: "more",
        }
        for action in self._action_glyphs:
            action.setIconText(action.text().rstrip(". …"))
        # Innerhalb der Tresor-Leiste ist das führende "Datei" redundant, und
        # die Leiste soll auch bei 1200 px Breite beschriftet bleiben. Kürzere
        # Beschriftungen erzeugen zudem einen niedrigeren sizeHint.
        self.act_add.setIconText("Hinzufügen")
        self.act_preview.setIconText("Vorschau")
        self.act_export.setIconText("Exportieren")
        self.act_delete.setIconText("Löschen")
        self._refresh_action_icons()

        tb.addAction(self.act_new)
        tb.addAction(self.act_open)
        self._tb_sep_files = tb.addSeparator()
        tb.addAction(self.act_add)
        tb.addAction(self.act_preview)
        tb.addAction(self.act_export)
        tb.addAction(self.act_delete)
        self._tb_sep_more = tb.addSeparator()
        tb.addAction(self.act_more)

        self.addToolBar(tb)
        self.toolbar = tb
        # QToolBar setzt bei einer Aktion mit Menü "MenuButtonPopup": der
        # Knopf selbst löst nur die Aktion aus, erst der kleine Pfeil öffnet
        # das Menü. Für "Mehr" ist das die falsche Bedienung, deshalb wird der
        # ganze Knopf zum Aufklapper.
        more_button = tb.widgetForAction(self.act_more)
        if more_button is not None:
            more_button.setPopupMode(
                QToolButton.ToolButtonPopupMode.InstantPopup)
        self._measure_toolbar_width()
        self._update_responsive_toolbar()
        self._update_chrome_visibility()

    def _build_view_segment(self):
        """Ansichtsmodi als Segment-Control in die Kopfzeile, links der Suche."""
        self.view_segment = QFrame(self.header)
        self.view_segment.setObjectName("ViewSegment")
        seg_layout = QHBoxLayout(self.view_segment)
        seg_layout.setContentsMargins(2, 2, 2, 2)
        seg_layout.setSpacing(2)
        self._view_buttons = []
        for action in (self.act_view_list, self.act_view_compact,
                       self.act_view_grid):
            button = QToolButton(self.view_segment)
            button.setObjectName("ViewSegmentButton")
            # setDefaultAction bindet den Button an die Aktion: Text, Icon und
            # Checkzustand bleiben dadurch einheitlich mit Menü und _set_view_mode.
            button.setDefaultAction(action)
            button.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
            button.setAutoRaise(True)
            button.setFocusPolicy(Qt.FocusPolicy.TabFocus)
            seg_layout.addWidget(button)
            self._view_buttons.append(button)
        self._view_glyphs = {
            self.act_view_list: "view-list",
            self.act_view_compact: "view-compact",
            self.act_view_grid: "view-grid",
        }
        self._refresh_action_icons()
        self.header_layout.insertWidget(
            self.header_layout.indexOf(self.search), self.view_segment
        )

    def _build_overflow_menu(self):
        """Dateiaktionen ohne dauerhaften Toolbar-Slot.

        Bewusst nur die drei Aktionen, die bisher weder in der Toolbar noch
        sonst gut auffindbar waren. Alles Weitere bleibt in der Menüleiste,
        damit das Overflow-Menü sie nicht dupliziert.
        """
        menu = QMenu(self)
        menu.addAction(self.act_edit)
        menu.addAction(self.act_export_all)
        menu.addAction(self.act_new_folder)
        return menu

    def _refresh_action_icons(self):
        """Toolbar- und Ansichts-Glyphen aus dem aktiven Theme neu laden."""
        for action, glyph in getattr(self, "_action_glyphs", {}).items():
            action.setIcon(ui_icon(glyph))
        for action, glyph in getattr(self, "_view_glyphs", {}).items():
            action.setIcon(ui_icon(glyph))
        if hasattr(self, "toolbar"):
            self.toolbar.setIconSize(icon_size_hint())
            self._measure_toolbar_width()

    def _register_action_shortcuts(self):
        """Ordnet Toolbar-Aktionen ihre Tastenkürzel zu und schreibt die Tooltips.

        Gelesen wird das QShortcut-Objekt, nicht die settings.json - so zeigt
        der Tooltip immer das wirklich aktive Kürzel.
        """
        self._action_shortcuts = {
            self.act_new: self.create_vault_sc,
            self.act_open: self.open_vault_sc,
            self.act_add: self.add_sec_sc,
            self.act_export: self.ex_selected_sc,
            self.act_delete: self.remove_sc,
        }
        for action, shortcut in self._action_shortcuts.items():
            label = action.text().rstrip(". …")
            keys = shortcut.key().toString(
                QKeySequence.SequenceFormat.NativeText
            )
            action.setToolTip(f"{label} ({keys})" if keys else label)
        for action in getattr(self, "_view_glyphs", {}):
            action.setToolTip(f"Ansicht: {action.text()}")

    def _measure_toolbar_width(self):
        """Mindestbreite der Toolbar für die beschriftete Variante.

        Gemessen statt hart kodiert, weil Schriftgröße (Dichte) und Theme die
        Buttonbreiten mitbestimmen; eine feste Pixelgrenze wäre bei
        "Komfortabel" zu klein und bei "Kompakt" zu groß.
        """
        if not hasattr(self, "toolbar"):
            return
        wide = Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        previous = self.toolbar.toolButtonStyle()
        self.toolbar.setToolButtonStyle(wide)
        self.toolbar.layout().invalidate()
        needed = self.toolbar.sizeHint().width()
        self.toolbar.setToolButtonStyle(previous)
        self.toolbar.layout().invalidate()
        self._toolbar_wide_min_width = int(needed) + 16

    def _update_responsive_toolbar(self):
        """Beschriftung und Suchfeld an die tatsächliche Breite anpassen."""
        if not hasattr(self, "toolbar"):
            return

        min_width = getattr(
            self, "_toolbar_wide_min_width", self.TOOLBAR_WIDE_MIN_WIDTH
        )
        compact = self.width() < min_width
        self.toolbar.setToolButtonStyle(
            Qt.ToolButtonStyle.ToolButtonIconOnly
            if compact else Qt.ToolButtonStyle.ToolButtonTextBesideIcon
        )
        self.search.setMaximumWidth(200 if compact else 280)
        self.search.setMinimumWidth(140 if compact else 200)

    def _update_chrome_visibility(self):
        """Ohne Tresor bleiben nur „Neuer Tresor“ und „Tresor öffnen“ sichtbar.

        Dateiaktionen und Ansichts-Umschalter wären ohne Tresor dauerhaft
        deaktiviert und auf dem Startbildschirm reines Ballast-UI.
        """
        if not hasattr(self, "toolbar"):
            return
        has_vault = self.master_key is not None
        for action in (self.act_add, self.act_preview, self.act_export,
                       self.act_delete, self.act_more):
            action.setVisible(has_vault)
        self._tb_sep_files.setVisible(has_vault)
        self._tb_sep_more.setVisible(has_vault)
        self.view_segment.setVisible(has_vault)
        self._measure_toolbar_width()
        self._update_responsive_toolbar()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_responsive_toolbar()

    def _set_view_mode(self, mode: str, persist: bool = True):
        """Layout umschalten: Liste / Kompakt (nur Name) / Raster."""
        if mode not in ("list", "compact", "grid"):
            mode = "list"
        self.view_mode = mode
        active = self._grid if mode == "grid" else self._tree
        self.file_list = active
        self.view_stack.setCurrentWidget(active)
        {
            "list": self.act_view_list,
            "compact": self.act_view_compact,
            "grid": self.act_view_grid,
        }[mode].setChecked(True)
        self._apply_view_columns()
        if persist and isinstance(getattr(self, "data", None), dict):
            self.data["list_view_mode"] = mode
            save_settings(self.data)
        self.refresh_list(bool(self.search.text()))

    def _apply_view_columns(self):
        """Spaltensichtbarkeit je nach Layout/Einstellungen."""
        if self.view_mode == "compact":
            self._tree.setColumnHidden(FileTree.COL_SIZE, False)
            self._tree.setColumnHidden(FileTree.COL_DATE, True)
            self._tree.setColumnHidden(FileTree.COL_TYPE, True)
            return
        s = self.data if isinstance(getattr(self, "data", None), dict) else {}
        self._tree.setColumnHidden(
            FileTree.COL_SIZE, not bool(s.get("list_show_size", True))
        )
        self._tree.setColumnHidden(
            FileTree.COL_DATE, not bool(s.get("list_show_date", True))
        )
        self._tree.setColumnHidden(FileTree.COL_TYPE, False)

    def _set_header_icon(self, has_vault: bool):
        """Kopfzeilen-Icon: Buendel offen bei geoeffnetem, verschlossen sonst.

        Bewusst eigene Glyphen statt QStyle-Standardpixmaps: bei 28 px
        rendern SP_FileDialogDetailedView als geschlossener Block und
        SP_DriveHDIcon als kaum sichtbares Eckdreieck - beide ohne
        erkennbare Bedeutung. Die Kopfzeile nutzt dieselbe Pipeline wie die
        Toolbar, damit Farbe, DPI und Theme einheitlich mitziehen.

        Farbwahl folgt dem Stylesheet: bei geoeffnetem Tresor steht die
        Glyphe auf ``accent-soft`` und nutzt daher ``on-soft`` - denselben
        Token, den das Segment-Control fuer seine Auswahl verwendet. Ohne
        Tresor steht sie auf ``surface-2``, dort ist ``text`` die kontrast-
        staerkste vorhandene Wahl (``text-disabled`` laege bei unter 2:1).
        """
        colors = active_icon_colors()
        name = "lock-open" if has_vault else "lock-closed"
        color = colors["on"] if has_vault else colors["normal"]
        if has_icon(name):
            self.header_icon.setPixmap(render_pixmap(name, color, 28))
        else:  # pragma: no cover - nur falls eine Glyphe fehlt
            self.header_icon.setPixmap(
                self.style().standardIcon(
                    QStyle.StandardPixmap.SP_DirOpenIcon if has_vault
                    else QStyle.StandardPixmap.SP_DirClosedIcon
                ).pixmap(28, 28)
            )
        self.header_icon.setProperty("hasVault", has_vault)
        style = self.header_icon.style()
        style.unpolish(self.header_icon)
        style.polish(self.header_icon)

    # ------------------ Dialoge ------------------
    def show_recent_containers(self):
        """Öffnet das 'Zuletzt verwendete Container'-Untermenü (Ctrl+R)."""
        if hasattr(self, "recent_menu"):
            self._refresh_recent_submenu()
            pos = self.mapToGlobal(QPoint(0, 0))
            self.recent_menu.popup(QPoint(pos.x() + 20, pos.y() + 30))
        else:
            QMessageBox.information(
                self, "Zuletzt verwendet", "Kein Menü verfügbar."
            )

    def _build_recent_submenu(self):
        """Erstellt das (leere) Untermenü, das im Datei-Menü bei Hover öffnet."""
        return QMenu("Zuletzt verwendete Tresore", self)

    def _refresh_recent_submenu(self):
        """Befüllt das Recent-Untermenü frisch aus den gespeicherten Containern."""
        if not hasattr(self, "recent_menu"):
            return
        menu = self.recent_menu
        menu.clear()
        containers = load_recent_containers()
        added = False
        for container in containers if isinstance(containers, list) else []:
            if not isinstance(container, dict):
                continue
            path = container.get("path")
            if not path:
                continue
            name = container.get("name") or os.path.basename(str(path))
            last_accessed = container.get("last_accessed", 0)
            label = f"📁 {name}"
            if last_accessed:
                try:
                    time_str = time.strftime(
                        "%Y-%m-%d %H:%M", time.localtime(last_accessed)
                    )
                    label += f" – {time_str}"
                except Exception:
                    pass
            action = menu.addAction(label)
            action.setToolTip(str(path))
            action.setData(path)
            action.triggered.connect(lambda _=False, p=path: self._open_recent_vault(p))
            added = True
        if not added:
            empty = menu.addAction("Keine kürzlich genutzten Container gefunden")
            empty.setEnabled(False)
        menu.addSeparator()
        clear = menu.addAction("Liste löschen")
        clear.triggered.connect(self._clear_recent_list)

    def _clear_recent_list(self):
        reply = QMessageBox.question(
            self,
            "Bestätigen",
            "Möchten Sie die Liste der kürzlich genutzten Container wirklich leeren?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            save_recent_containers([])

    def _open_recent_vault(self, path):
        if not self._ensure_container_idle():
            return
        if path and os.path.exists(path):
            self.container_path = path
            self.open_container()
        else:
            # Verwaisten Eintrag entfernen (z. B. extern oder per Notfall-Löschung
            # gelöscht), damit die Liste nicht auf nicht existierende Tresore zeigt.
            remove_recent_container(path)
            if hasattr(self, "recent_menu"):
                self._refresh_recent_submenu()
            QMessageBox.warning(self, "Fehler", "Container existiert nicht mehr.")


    def change_container_password_dialog(self):
            """Show password change dialog for current container"""
            if not self._ensure_container_idle():
                return
            if getattr(self, "_edit_session", None):
                QMessageBox.information(
                    self, "Info", "Schließe zuerst die laufende In-Tresor-Bearbeitung ab."
                )
                return
            if not self.container_path or not self.master_key:
                QMessageBox.warning(self, "Kein Container", "Bitte öffnen Sie zuerst einen Container.")
                return
            
            success, new_pwd = change_container_password(
                self.container_path, 
                self.master_key, 
                self.meta, 
                self.pwd,
                self.flags,
                self
            )
            
            if success and new_pwd:
                self.append_log("Passwort wurde erfolgreich geändert.")
                
                # Preserve current container path before closing
                container_path = self.container_path
                self.close_container()
                
                # Re-open the container with new password
                try:
                    # Re-open container with new password
                    self.open_container_with_password(container_path, new_pwd)
                    self.append_log("Container mit neuem Passwort erneut geöffnet.")
                    
                except Exception as e:
                    self.append_log(f"Fehler beim erneuten Öffnen des Containers: {str(e)}")
                    QMessageBox.warning(self, "Fehler", f"Container konnte nicht mit neuem Passwort geöffnet werden: {str(e)}")
                    self.close_container()
            else:
                self.append_log("Passwortänderung abgebrochen")


    def show_about_dialog(self):
            if not hasattr(self, "_about_dialog"):
                self._about_dialog = AboutDialog(self)
            self._about_dialog.show()
            self._about_dialog.raise_()
            self._about_dialog.activateWindow()

    def show_onboarding_dialog(self):
        dlg = OnboardingDialog(self)
        dlg.exec()

    def show_settings_dialog(self):
        if not hasattr(self, "_settings_dialog") or self._settings_dialog is None:
            self._settings_dialog = SettingsDialog(self)

        self._settings_dialog.show()
        self._settings_dialog.raise_()
        self._settings_dialog.activateWindow()

    def get_pwd_dialog(self):
        print("Passwortabfrage")
        pwd, cancelled = get_password_with_requirements(self, "Passwort eingeben")
        self.setWindowIcon(get_app_icon())

        if cancelled or not pwd:
            return ""

        print("Passwort erhalten")
        return pwd

    def update_container_path(self, path: str = None):
        self.container_path = path
        if path:
            self.container_label.setText(os.path.basename(path))
            self.container_label.setToolTip(path)
            self.path_label.setText(os.path.dirname(path) or os.sep)
            self.path_label.setToolTip(path)
            self.path_label.show()
        else:
            self.container_label.setText("Kein Tresor geöffnet")
            self.container_label.setToolTip("")
            self.path_label.clear()
            self.path_label.hide()
        self.search.setEnabled(path is not None)
        self._set_header_icon(bool(path))
        if path is None:
            self.status.setText("Tresor-Pfad zurückgesetzt")
        else:
            self.status.setText(f"Tresor-Pfad gesetzt: {path}")

    # ------------------------------------------------------

    def _auto_lock_rearm(self):
        """Auto-Lock-Timer gemäß Einstellung neu aufziehen (0 = deaktiviert).

        Wird bei jeder Nutzeraktivität (Mouse/Key) sowie bei Öffnen eines
        Tresors neu gestartet.
        """
        minutes = int(self.data.get("auto_lock_minutes", 5) or 0)
        if minutes <= 0:
            self._auto_lock_minutes = 0
            self._auto_lock_timer.stop()
            return
        self._auto_lock_minutes = minutes
        self._auto_lock_timer.start(minutes * 60 * 1000)

    def _auto_lock_touch(self):
        """Setzt die Inaktivitäts-Uhr bei erkannter Nutzeraktivität zurück."""
        if self._auto_lock_minutes > 0:
            self._auto_lock_timer.start(self._auto_lock_minutes * 60 * 1000)

    def _auto_lock_triggered(self):
        """Sperrt den Tresor nach Inaktivität (nur wenn ein Tresor geöffnet ist)."""
        if not self.master_key or not self.container_path:
            return
        # Nicht sperren, solange eine Container-Operation läuft (Export, Add,
        # Preview, Bearbeitung, Rewrite, Passwort-Änderung), um einen laufenden
        # Schreibvorgang nicht abzubrechen oder einen nativen Zustand zu stören.
        if (
            self.exporting
            or self.changing_password
            or self.password_change_in_progress
            or getattr(self, "_edit_session", None) is not None
        ):
            self._auto_lock_rearm()
            return
        p = getattr(self, "progress", None)
        if p is not None:
            try:
                if p.isVisible():
                    self._auto_lock_rearm()
                    return
            except Exception:
                pass
        self.append_log("Auto-Lock: Tresor wegen Inaktivität gesperrt.")
        self.close_container()
        notifier.show("Tresor gesperrt 🔒", "Der Tresor wurde automatisch gesperrt.")

    def eventFilter(self, obj: object, event: object) -> bool:
        """Nutzeraktivität (Input) erkennt und Auto-Lock-Uhr zurücksetzen."""
        try:
            etype = event.type()
            if etype in (
                QEvent.Type.MouseButtonPress,
                QEvent.Type.MouseMove,
                QEvent.Type.KeyPress,
                QEvent.Type.Wheel,
            ):
                self._auto_lock_touch()
        except Exception:
            pass
        return super().eventFilter(obj, event)

    def apply_settings(self):
        try:
            s = load_settings()
            
            # 1. Theme sofort anwenden (inkl. Akzentfarbe + Dichte)
            self.apply_theme(s.get("theme", "Standard-dark"))
            
            # 2. Shortcuts aktualisieren
            self.apply_shortcuts(s)
            
            # 3. Verhaltens-Einstellungen aktualisieren
            self.apply_behavior_settings(s)

            # 4. Dateilisten-Ansicht aktualisieren
            self.apply_list_settings(s)
            self.refresh_list(bool(self.search.text()))
            
        except Exception as e:
            print("[SETTINGS] Fehler beim Anwenden der Einstellungen:", e)
    
    def apply_theme(self, theme_name):
        """Theme anwenden – bei Theme-Wechsel mit sanfter Fade-Überblendung."""
        try:
            s = load_settings()
            accent = str(s.get("ui_accent", "") or "")
            density = str(s.get("ui_density", "Mittel") or "Mittel")

            # Icons aus derselben Palette beziehen, damit QSS und Glyphen
            # bei Theme-, Akzent- und Dichtewechsel gemeinsam umschalten.
            set_active_ui_theme(theme_name, accent, density)

            def _swap():
                self.setStyleSheet(build_stylesheet(theme_name, accent, density))
                self._refresh_action_icons()
                # Kopfzeilen-Glyphe ebenfalls neu einfärben, sonst behält sie
                # nach einem Theme- oder Akzentwechsel die alte Palettenfarbe.
                self._set_header_icon(bool(self.container_path))

            fade_theme_swap(_swap, theme_name)
            print(f"[SETTINGS] Theme '{theme_name}' angewendet "
                  f"(Akzent='{accent}', Dichte='{density}')")
        except Exception as e:
            print(f"[SETTINGS] Theme-Fehler: {e}")

    def apply_list_settings(self, settings):
        """Layout, Spaltensichtbarkeit und Sortierung sofort anwenden."""
        try:
            mode = str(settings.get("list_view_mode", "list"))
            if mode != self.view_mode:
                self._set_view_mode(mode, persist=False)
                return
            sort_mode = settings.get("list_sort", "Keine")
            show_size = bool(settings.get("list_show_size", True))
            show_date = bool(settings.get("list_show_date", True))
            self._apply_view_columns()
            print(f"[SETTINGS] Dateiliste: Layout={self.view_mode}, "
                  f"Sortierung={sort_mode}, Größe={'an' if show_size else 'aus'}, "
                  f"Datum={'an' if show_date else 'aus'}")
        except Exception as e:
            print(f"[SETTINGS] Listen-Fehler: {e}")
    
    def apply_shortcuts(self, settings):
        """Shortcuts sofort anwenden"""
        try:
            # Hilfsfunktion: Key setzen
            def set_key(shortcut_obj, key_name, fallback=""):
                key_str = settings.get(key_name, settings.get(fallback, ""))
                if key_str is None:
                    key_str = ""
                shortcut_obj.setKey(QKeySequence(key_str))

            # Shortcuts setzen
            set_key(self.ex_selected_sc, "o_seq")
            set_key(self.ex_all_seq, "o_all_seq")
            set_key(self.create_vault_sc, "crea_vault_seq")
            set_key(self.open_vault_sc, "vault_o_seq")
            set_key(self.remove_sc, "del_seq")
            set_key(self.del_container_sc, "del_vault_seq")
            set_key(self.search_sc, "search_seq")
            
            print("[SETTINGS] Shortcuts aktualisiert")
        except Exception as e:
            print(f"[SETTINGS] Shortcuts-Fehler: {e}")
    
    def apply_behavior_settings(self, settings):
        """Verhaltens-Einstellungen aktualisieren"""
        try:
            self.data = settings
            self._apply_screenshot_protection(settings)
            self._auto_lock_rearm()
            print("[SETTINGS] Verhaltens-Einstellungen aktualisiert")
        except Exception as e:
            print(f"[SETTINGS] Verhaltens-Fehler: {e}")

    def _apply_screenshot_protection(self, settings):
        """Aktiviert/deaktiviert den Bildschirmaufnahme-Schutz zur Laufzeit."""
        try:
            enabled = bool(settings.get("screenshot_protection", True))
            if enabled:
                install_screenshot_protection(QApplication.instance())
            else:
                uninstall_screenshot_protection(QApplication.instance())
            print(f"[SETTINGS] Bildschirmaufnahme-Schutz: {'AN' if enabled else 'AUS'}")
        except Exception as e:
            print(f"[SETTINGS] Screenshot-Schutz-Fehler: {e}")
    
    def _schedule_settings_apply(self):
        """Einstellungen gebündelt (eine 100-ms-Verzögerung) anwenden."""
        if self._settings_apply_pending:
            return
        self._settings_apply_pending = True
        QTimer.singleShot(100, self._flush_settings_apply)

    def _flush_settings_apply(self):
        self._settings_apply_pending = False
        self.apply_settings()

    def _on_settings_saved(self):
        """Direkte In-Prozess-Benachrichtigung nach erfolgreichem Speichern."""
        self._schedule_settings_apply()

    def on_settings_changed(self, path):
        """Wird aufgerufen wenn settings.json von außen geändert wird"""
        try:
            print(f"[SETTINGS] Settings-Datei geändert: {path}")
            # Atome Writes (os.replace) entfernen den Watch -> neu anmelden.
            if path not in self.settings_watcher.files():
                self.settings_watcher.addPath(path)
            self._schedule_settings_apply()
        except Exception as e:
            print(f"[SETTINGS] Watcher-Fehler: {e}")

    # ------------------ Container wählen / erstellen ------------------
    def choose_container(self, mode: int = 0):
        if not self._ensure_container_idle():
            return
        if not mode:
            action = QMessageBox()
            action.setWindowIcon(get_app_icon())
            action.setWindowTitle("ANCORATE – Tresor wählen")
            action.setText(
                "Möchten Sie einen bestehenden Tresor öffnen oder einen neuen erstellen?"
            )
            o = action.addButton("Öffnen", QMessageBox.ButtonRole.YesRole)
            n = action.addButton("Erstellen", QMessageBox.ButtonRole.NoRole)
            action.exec()

            result = action.clickedButton()
            if result == o:
                mode = 1
            elif result == n:
                mode = 2

        # 1. Bestehenden Tresor öffnen
        path = ""
        creating = False
        if mode == 1:
            path, _ = QFileDialog.getOpenFileName(
                None,
                f"ANCORATE {edition} - Tresor wählen",
                "",
                "ANC Secure Authentication Layer Tresor (*.salt)",
            )

        # 2. Neuen Tresor erstellen
        elif mode == 2:
            folder = QFileDialog.getExistingDirectory(
                self, "Speicherort für neuen Tresor wählen"
            )
            if folder:
                name, ok = QInputDialog.getText(
                    None,
                    "Tresornamen wählen",
                    "Wähle einen Namen für deinen Tresor",
                    text="new-vault",
                )

                # Standardname, falls leer
                if not name:
                    name = "secure"
                if "." in name:
                    name, _ = os.path.splitext(name)
                # Erweiterung hinzufügen
                name += ".salt"
                path = os.path.join(folder, name)
                creating = True

        # 3. Pfad setzen
        if path:
            # Keep the selection pending until opening or creation succeeds.
            # This prevents a cancelled/failed operation from advertising a
            # vault that is not actually open in the header.
            self.container_path = path
            if creating:
                self.create_container()
            else:
                self.open_container()

    def open_container_with_password(self, container_path: str, password: str):
        """Öffnet einen bestehenden Container mit dem angegebenen Passwort"""

        # Use provided path and password
        self.container_path = container_path
        pwd = password

        try:
            if recover_container_metadata(self.container_path):
                self.append_log(
                    "Unterbrochene Metadatenänderung wurde zurückgesetzt."
                )
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "rb") as fh:
                # 4a. Header lesen: Flags + Salt
                flags, salt = read_header(fh)
                if salt is None:
                    raise ValueError("Salt konnte nicht gelesen werden.")

                if flags & FLAG_PRO_VAULT:
                    self.append_log(
                        "Open blocked: Pro vault detected in Home (flag 0x04)."
                    )
                    QMessageBox.critical(
                        self,
                        "Nicht unterstützter Tresor",
                        "Dieser Tresor wurde mit ANCORATE EncryptPro erstellt und kann in EncryptHome nicht geöffnet werden.\n\nBitte verwende ANCORATE EncryptPro.\nWeitere Informationen unter ancorate.com",
                    )
                    self.update_container_path()
                    return

                # 4b. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4c. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Master-Key bestimmen (inkl. Legacy-Kandidaten für
            #    gerätegebundene Tresore aus älteren Versionen) und Meta
            #    entschlüsseln
            # ------------------------------------------------------------------
            master = determine_master_key(pwd, salt, flags, meta_blob)
            if master is None:
                raise ValueError("signature did not match digest")
            meta = decrypt_meta(meta_blob, master)

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags
            self.update_container_path(self.container_path)
            self._auto_lock_rearm()

            # ------------------------------------------------------------------
            # 7. GUI aktualisieren
            # ------------------------------------------------------------------
            file_name = os.path.basename(self.container_path)
            folder_name = os.path.basename(os.path.dirname(self.container_path))

            self.status.setText(f"Tresor geöffnet: {file_name}")
            self.append_log("Tresor geöffnet.")
            self.setWindowTitle(
                f"ANCORATE {edition} {version} – {file_name} aus {folder_name} geöffnet"
            )
            self._set_views_enabled(True)
            self._set_vault_actions_enabled(True)
            self.refresh_list()
            # Add to recent containers only after successful open
            add_recent_container(self.container_path)

        except Exception as e:
            error_msg = str(e)

            if "signature did not match digest" in error_msg.lower():
                self.update_container_path()
                user_msg = (
                    """Der Tresor konnte nicht geöffnet werden.
Mögliche Ursache
• Der Tresor wurde auf einem anderen Gerät erstellt
• Das eingegebene Passwort ist falsch\n"""
                    f"• Der Tresor wurde mit einer veralteten Version von {edition} erstellt"
                )
                log_msg = "Open failed: signature/digest mismatch (device or password)"

            elif isinstance(e, FileNotFoundError) or "errno 2" in error_msg.lower():
                user_msg = (
                    "Der Tresor konnte nicht geöffnet werden.\n\n"
                    "Mögliche Ursachen:\n"
                    "• Der Tresor wurde durch fehlerhaftes Kopieren beschädigt\n"
                    "• Der Speicherplatz Ihres Laufwerks war beim letzten Hinzufügen von Dateien nicht ausreichend\n"
                    f"• {edition} ist beim Hinzufügen von Dateien zu diesem Tresor unerwartet geschlossen worden\n\n"
                    "Der Tresor ist irreparabel beschädigt und kann nicht wiederhergestellt werden."
                )
                log_msg = f"Open failed: FileNotFoundError ({error_msg})"

            else:
                user_msg = f"Öffnen fehlgeschlagen:\n{error_msg}"
                log_msg = f"Open failed: {error_msg}"

            QMessageBox.critical(self, "ANCORATE – Tresorfehler", user_msg)
            self.append_log(log_msg)
            # Clean up state on failure
            self.update_container_path()
            self.pwd = ""
            self.master_key = None
            self.meta = {"files": []}
            self.flags = 0

    def open_container(self):
        """Öffnet einen bestehenden Container"""

        # 1. Prüfen, ob Container-Pfad gesetzt ist
        if not self.container_path:
            QMessageBox.warning(
                self,
                "Fehler",
                "Kein Container-Pfad gesetzt. Wähle zuerst einen Container.",
            )
            self.choose_container()
            return

        # 2. Prüfen, ob Container existiert
        if not os.path.exists(self.container_path):
            QMessageBox.warning(
                self,
                "Fehler",
                f"Container nicht gefunden unter:\n{self.container_path}",
            )
            self.update_container_path()
            self.choose_container()
            return

        # 3. Passwort abfragen
        pwd = self.pwd
        while not pwd:
            pwd = self.get_pwd_dialog()
            if not pwd:
                self.update_container_path()
                return
        if not pwd:
            QMessageBox.warning(self, "Passwort fehlt", "Kein Passwort bereitgestellt.")
            return

        try:
            if recover_container_metadata(self.container_path):
                self.append_log(
                    "Unterbrochene Metadatenänderung wurde zurückgesetzt."
                )
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "rb") as fh:
                # 4a. Header lesen: Flags + Salt
                flags, salt = read_header(fh)
                if salt is None:
                    raise ValueError("Salt konnte nicht gelesen werden.")

                if flags & FLAG_PRO_VAULT:
                    self.append_log(
                        "Open blocked: Pro vault detected in Home (flag 0x04)."
                    )
                    QMessageBox.critical(
                        self,
                        "Nicht unterstützter Tresor",
                        "Dieser Tresor wurde mit ANCORATE EncryptPro erstellt und kann in EncryptHome nicht geöffnet werden.\n\nBitte verwende ANCORATE EncryptPro.\nWeitere Informationen unter ancorate.com",
                    )
                    self.update_container_path()
                    return

                # 4b. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4c. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Master-Key bestimmen (inkl. Legacy-Kandidaten für
            #    gerätegebundene Tresore aus älteren Versionen) und Meta
            #    entschlüsseln
            # ------------------------------------------------------------------
            master = determine_master_key(pwd, salt, flags, meta_blob)
            if master is None:
                raise ValueError("signature did not match digest")
            meta = decrypt_meta(meta_blob, master)

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags
            self.update_container_path(self.container_path)
            self._auto_lock_rearm()

            # ------------------------------------------------------------------
            # 7. GUI aktualisieren
            # ------------------------------------------------------------------
            file_name = os.path.basename(self.container_path)
            folder_name = os.path.basename(os.path.dirname(self.container_path))

            self.status.setText(f"Tresor geöffnet: {file_name}")
            self.append_log("Tresor geöffnet.")
            self.setWindowTitle(
                f"ANCORATE {edition} {version} – {file_name} aus {folder_name} geöffnet"
            )
            self._set_views_enabled(True)
            self._set_vault_actions_enabled(True)
            self.refresh_list()
            # Add to recent containers only after successful open
            add_recent_container(self.container_path)

        except Exception as e:
            error_msg = str(e)

            if "signature did not match digest" in error_msg.lower():
                self.update_container_path()
                user_msg = (
                    """Der Tresor konnte nicht geöffnet werden.
Mögliche Ursache
• Der Tresor wurde auf einem anderen Gerät erstellt
• Das eingegebene Passwort ist falsch\n"""
                    f"• Der Tresor wurde mit einer veralteten Version von {edition} erstellt"
                )
                log_msg = "Open failed: signature/digest mismatch (device or password)"

            elif isinstance(e, FileNotFoundError) or "errno 2" in error_msg.lower():
                user_msg = (
                    "Der Tresor konnte nicht geöffnet werden.\n\n"
                    "Mögliche Ursachen:\n"
                    "• Der Tresor wurde durch fehlerhaftes Kopieren beschädigt\n"
                    "• Der Speicherplatz Ihres Laufwerks war beim letzten Hinzufügen von Dateien nicht ausreichend\n"
                    f"• {edition} ist beim Hinzufügen von Dateien zu diesem Tresor unerwartet geschlossen worden\n\n"
                    "Der Tresor ist irreparabel beschädigt und kann nicht wiederhergestellt werden."
                )
                log_msg = f"Open failed: FileNotFoundError ({error_msg})"

            else:
                user_msg = f"Öffnen fehlgeschlagen:\n{error_msg}"
                log_msg = f"Open failed: {error_msg}"

            QMessageBox.critical(self, "ANCORATE – Tresorfehler", user_msg)

            self.append_log(log_msg)
            return

    def create_container(self):
        if not self._ensure_container_idle():
            return
        if self.container_path is None:
            QMessageBox.warning(self, "Fehler", "Wähle zuerst einen Dateipfad aus.")
            return
        # Prüfen, ob Container bereits existiert
        existing_stat = None
        if os.path.exists(self.container_path):
            existing_stat = os.stat(self.container_path)
            if (
                QMessageBox.question(
                    self,
                    "Tresor bereits vorhanden",
                    "Tresor existiert bereits — überschreiben?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                != QMessageBox.StandardButton.Yes
            ):
                self.update_container_path()
                return

        # Passwort mit Anforderungen abfragen
        pwd = self.pwd
        while not pwd:
            pwd = self.get_pwd_dialog()
            if not pwd:
                return

        # Container-Daten erzeugen
        salt = secrets.token_bytes(SALT_LEN)

        # Flags Device-Binding
        flags = 0
        if getattr(self, "device_bound", False):
            flags |= FLAG_DEVICE

        # Master-Key ableiten (nur Passwort + optional Device-Key)
        master = derive_master_key(
            pwd,
            salt,
            bool(flags & FLAG_DEVICE),
            load_device_key() if (flags & FLAG_DEVICE) else None,
        )

        meta = {"files": [], "created": int(time.time()), "flags": flags}

        meta_blob = encrypt_meta(meta, master)

        try:
            with atomic_container_write(
                self.container_path, expected_stat=existing_stat
            ) as fh:
                write_header(fh, flags, salt)
                fh.write(meta_blob)
                fh.write(struct.pack("<Q", len(meta_blob)))
        except Exception as e:
            QMessageBox.critical(
                self,
                "Tresor konnte nicht erstellt werden",
                f"Der Tresor wurde nicht ersetzt oder erstellt:\n{e}",
            )
            return

        self.master_key = master
        self.meta = meta
        self.flags = flags
        self.pwd = pwd
        self.update_container_path(self.container_path)
        self._auto_lock_rearm()
        self._set_vault_actions_enabled(True)
        self.refresh_list()

        self.status.setText("Container erstellt.")
        self.append_log("Container created.")

    def delete_container(self):
        if not self._ensure_container_idle():
            return
        if getattr(self, "_edit_session", None):
            QMessageBox.information(
                self, "Info", "Schließe zuerst die laufende In-Tresor-Bearbeitung ab."
            )
            return
        if self._delete_in_progress:
            return
        if not self.container_path:
            QMessageBox.warning(self, "Fehler", "Keine Tresordatei geöffnet.")
            return
        # 1. Validierung des Pfads
        c_path = getattr(self, "container_path", "")
        if not c_path or not os.path.exists(c_path):
            QMessageBox.warning(self, "Fehler", "Kein gültiger Tresor ausgewählt.")
            return

        # 2. Sicherheitsabfrage
        method = self.data.get("deletion_method", "Standard")

        # Warnung verschärfen, wenn Vaporizer gewählt ist
        warning_text = f"Möchtest du den Tresor wirklich mit '{method}' vernichten?\n\n"
        if "Vaporizer 1" in method:
            warning_text += "ACHTUNG: ANCORATE Vaporizer 1 mit 100 Durchgängen gewählt. Dies wird lange dauern (1+ min)!"
        elif "Furnace Max" in method:
            warning_text += "ACHTUNG: ANCORATE Furnace Max mit 200 Durchgängen gewählt. Der Löschvorgang wird mindestens 5 min dauern!"

        elif "Shatterer Ultra" in method:
            warning_text += "ACHTUNG: ANCORATE Shatterer Ultra mit 300 Durchgängen gewählt. Der Löschvorgang wird sehr lange dauern (10+ min)!\nEr kann bei HDDs (Hard Disk Drives) zu dauerhaften Schäden an der Disk führen!"
        else:
            warning_text += (
                "Dies überschreibt alle Daten physisch und löscht die Tresordatei."
            )

        confirm = QMessageBox.question(
            self,
            "Tresor vernichten",
            warning_text,
            defaultButton=QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        try:
            self.append_log(f"Vernichtung gestartet (Modus: {method})...")

            delete_stop_event = threading.Event()
            self._delete_in_progress = True
            self._delete_committing = False
            self._set_vault_actions_enabled(False)
            self._set_views_enabled(False)

            worker = DeleteContainerWorker(c_path, method, delete_stop_event)
            thread = QThread()
            self._track_worker_thread(thread, delete_stop_event)
            worker.moveToThread(thread)

            self.progress = QProgressDialog(
                f"Vernichte Tresor mit '{method}'...", "Abbrechen", 0, 100, self
            )
            self.progress.setWindowTitle(f"ANCORATE {edition}")
            self.progress.setValue(0)
            self.progress.canceled.connect(delete_stop_event.set)
            self.progress.show()

            worker.progress.connect(self._on_progress)
            worker.finished.connect(
                lambda path, mth: self._delete_container_finished(path, mth, thread, worker)
            )
            worker.error.connect(
                lambda error: self._delete_container_error(error, thread, worker, delete_stop_event)
            )
            thread.started.connect(worker.run)
            thread.start()

        except Exception as e:
            self._delete_in_progress = False
            self._delete_committing = False
            self._set_views_enabled(bool(self.master_key))
            self._set_vault_actions_enabled(bool(self.master_key))
            self.append_log(f"Fehler: {str(e)}")
            QMessageBox.critical(
                self, "Kritischer Fehler", f"Löschvorgang fehlgeschlagen: {e}"
            )

    # ------------------ Datei hinzufügen ------------------
    def add_file_dialog(self):
        if not getattr(self, "master_key", None):
            QMessageBox.information(
                self,
                "Hinweis",
                "Öffne oder erstelle zuerst einen Container und gib dein Passwort ein.",
            )
            return

        # Geändert auf getOpenFileNames (Plural!) für Mehrfachauswahl im Fenster
        fns, _ = QFileDialog.getOpenFileNames(self, "Dateien wählen")
        if not fns:
            return

        # Wir übergeben die Liste 'fns' an add_files
        print("adding files")
        self.add_files(fns)
        # self.refresh_list() # Nicht nötig, da der Worker am Ende finished -> _add_finished -> refresh_list aufruft

    # ------------------ Container Operationen ------------------
    def close_container(self):
        if not self._ensure_container_idle():
            return
        self._auto_lock_timer.stop()
        self._end_edit_session()
        if hasattr(self, "stop_event") and self.stop_event:
            try:
                self.stop_event.set()
            except Exception:
                pass

        try:
            if self.progress:
                self.progress.close()
        except Exception:
            pass

        self.pwd = ""
        # Python bytes are immutable; release the application's key reference.
        self.master_key = None
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.flags = 0
        self.stop_event = None
        self.progress = None
        self.exporting = False
        self._preview_cache.clear()
        self._preview_cache_bytes = 0
        self.current_folder = ""
        self._expanded_folders = None
        self._tree.clear()
        self._grid.clear()
        self._set_views_enabled(False)
        self._set_vault_actions_enabled(False)
        self.search.clear()
        self.searchbar_content = ""
        self._update_empty_state(True)
        self.update_container_path()
        self.status.setText("Tresor geschlossen.")
        print("Container closed.")
        self.setWindowTitle(f"ANCORATE {edition} {version} - Tresor geschlossen")
        notifier.show("Tresor geschlossen 🔐", "Der Tresor wurde geschlossen. ✅")

    def add_files(self, filepaths=None):
        """
        Datei(en) zum Tresor hinzufügen.
        :param filepaths: Liste von Pfaden oder None → Dialog öffnen
        """
        if not self._ensure_container_idle():
            return
        if getattr(self, "_edit_session", None):
            QMessageBox.information(
                self, "Info", "Schließe zuerst die laufende In-Tresor-Bearbeitung ab, bevor du Dateien hinzufügst."
            )
            return
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist."
            )
            return
        if filepaths is None:
            files, _ = QFileDialog.getOpenFileNames(
                self, "Dateien zum Tresor hinzufügen", "", "Alle Dateien (*.*)"
            )
        else:
            files = filepaths

        if not files:
            return

        # Cancel any previous operation before starting a new one
        if self.stop_event is not None:
            self.stop_event.set()

        # Local stop event for this specific add operation
        add_stop_event = threading.Event()
        self.stop_event = add_stop_event

        v2 = self.master_key
        if len(v2) != 32:
            raise ValueError(f"Ungültige Master-Key-Länge: {len(v2)} Bytes (erwartet 32)")

        worker = AddWorker(
            self.container_path, files, v2, self.flags, stop_event=add_stop_event,
            folder=self._target_folder(),
        )

        thread = QThread()
        self._track_worker_thread(thread, add_stop_event)
        worker.moveToThread(thread)
        self._set_vault_actions_enabled(False)
        self._set_views_enabled(False)

        # Verbindung für Fortschritt und Fehler
        worker.progress.connect(self._on_progress)
        worker.error.connect(lambda e: self._add_worker_error(e, thread, worker))

        # Hier die korrekte Lambda‑Verbindung:
        worker.finished.connect(
            lambda added, w=worker: self._add_finished(added, thread, w)
        )

        # UI: Fortschrittsdialog
        count = len(files)
        msg = (
            f"Verschlüssele {count} Datei(en)..."
            if count > 1
            else "Änderungen am Tresor werden vorgenommen..."
        )
        self.progress = QProgressDialog(msg, "Abbrechen", 0, 100, self)

        # konkreter Modality‑Wert
        self.progress.setWindowTitle(f"ANCORATE {edition}")  # ← hier
        self.progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.progress.canceled.connect(lambda ev=add_stop_event: ev.set())
        worker.stage.connect(self.progress.setLabelText)
        self.progress.setValue(0)
        self.progress.show()

        # Erfolg‑Benachrichtigung
        def show_success():
            text = (
                f"{count} Dateien hinzugefügt." if count > 1 else "Datei hinzugefügt."
            )
            show_toast(self, "Verschlüsselung abgeschlossen", text)

        worker.finished.connect(show_success)
        worker.finished.connect(self.progress.close)

        thread.started.connect(worker.run)
        thread.start()

    # ------------------ Datei exportieren ------------------
    def _selected_meta_indexes(self) -> list[int]:
        indexes = []
        for item in self.file_list.selectedItems():
            data = self.file_list.role(item)
            if isinstance(data, int):
                indexes.append(data)

        if not indexes:
            selected_index = self._selected_meta_index()
            if selected_index is not None:
                indexes.append(selected_index)

        seen = set()
        unique_indexes = []
        for index in indexes:
            if index not in seen:
                seen.add(index)
                unique_indexes.append(index)
        return sorted(unique_indexes)

    def export_selected(self, idx: int = 0, mode: int = 0, target_dir: str = ""):
        if not self._ensure_container_idle():
            return
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist, bevor Sie Dateien exportieren."
            )
            return
        if self.exporting:
            QMessageBox.information(self, "Info", "Ein Export läuft bereits. Bitte kurz warten.")
            return
        if mode:
            selected_indexes = [int(idx)]
        else:
            selected_indexes = self._selected_meta_indexes()

        if not selected_indexes:
            QMessageBox.information(self, "Info", "Bitte mindestens eine Datei auswählen.")
            return

        selected_entries = [dict(self.meta["files"][i]) for i in selected_indexes]
        multiple = len(selected_entries) > 1

        if multiple:
            if not target_dir:
                target_dir = QFileDialog.getExistingDirectory(
                    self, "Exportordner wählen"
                )
            if not target_dir:
                return
            self._start_batch_export(selected_entries, target_dir)
            return

        entry = selected_entries[0]
        if not target_dir:
            save, _ = QFileDialog.getSaveFileName(
                self, "Speichere Datei", _item_name(entry["name"])
            )
        else:
            save = os.path.join(target_dir, entry["name"])
        if not save:
            return

        self._start_single_export(entry, save)

    # ------------------ Dateivorschau (RAM) ------------------
    def _selected_meta_index(self) -> int | None:
        """
        Liefert den Index in self.meta['files'] für das aktuell ausgewählte List-Item.
        Wichtig: Die List-Row ist bei Suche/Filter nicht gleich dem Meta-Index.
        """
        item = self.file_list.currentItem()
        if not item:
            return None

        data = self.file_list.role(item)
        if isinstance(data, int):
            return data

        # Fallback: Text parsen (Name in der Namensspalte)
        try:
            name = item.text(FileTree.COL_NAME).strip()
            for i, ent in enumerate(self.meta.get("files", [])):
                if ent.get("name") == name:
                    return i
        except Exception:
            pass
        return None

    def _preview_cache_key(self, entry: dict) -> str:
        return f"{self.container_path}|{entry.get('offset')}|{entry.get('length')}|{entry.get('name')}"

    def _preview_cache_put(self, key: str, data: bytes, info_obj: object):
        # Entferne alten Eintrag, falls vorhanden
        if key in self._preview_cache:
            old_data, _old_info = self._preview_cache.pop(key)
            self._preview_cache_bytes -= len(old_data)

        self._preview_cache[key] = (data, info_obj)
        self._preview_cache.move_to_end(key)
        self._preview_cache_bytes += len(data)

        # LRU-Eviction
        while (
            self._preview_cache_bytes > self._preview_cache_limit
            and self._preview_cache
        ):
            _k, (d, _i) = self._preview_cache.popitem(last=False)
            self._preview_cache_bytes -= len(d)

    def preview_selected(self, *_args):
        if not self._ensure_container_idle():
            return
        if not self.container_path or not self.master_key:
            QMessageBox.information(
                self, "Vorschau", "Bitte zuerst einen Tresor öffnen."
            )
            return

        idx = self._selected_meta_index()
        if idx is None or idx < 0:
            QMessageBox.information(self, "Vorschau", "Bitte eine Datei auswählen.")
            return

        entry = self.meta["files"][int(idx)]
        key = self._preview_cache_key(entry)

        # Cache hit
        if key in self._preview_cache:
            data, info_obj = self._preview_cache[key]
            self._preview_cache.move_to_end(key)
            show_preview(self, entry.get("name", "Datei"), data, info_obj)
            return

        # Cache miss: im Hintergrund entschlüsseln und in RAM laden
        # Cancel any previous operation before starting a new one
        if self.stop_event is not None:
            self.stop_event.set()

        preview_stop_event = threading.Event()
        self.stop_event = preview_stop_event
        worker = PreviewDecryptWorker(
            self.container_path,
            entry,
            self.master_key,
            stop_event=preview_stop_event,
            max_bytes=self._preview_max_file_bytes,
        )
        thread = QThread()
        self._track_worker_thread(thread, preview_stop_event)
        worker.moveToThread(thread)

        # UI: Fortschrittsdialog
        self.progress = QProgressDialog(
            "Entschlüssle Datei für Vorschau...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(lambda ev=preview_stop_event: ev.set())
        self.progress.setValue(0)
        self.progress.show()

        worker.progress.connect(self._on_progress)

        def _done(data: bytes, info_obj: object):
            try:
                self.progress.close()
            except Exception:
                pass
            thread.quit()
            thread.wait()
            worker.deleteLater()
            thread.deleteLater()
            self._release_worker_thread(thread)
            if self._close_after_workers:
                return
            self._preview_cache_put(key, data, info_obj)
            show_preview(self, entry.get("name", "Datei"), data, info_obj)

        worker.finished.connect(_done)
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    # ------------------ In-Tresor-Bearbeitung (externer Editor) ------------------
    def start_in_vault_edit(self, *_args):
        if not self._ensure_container_idle():
            return
        if not self.container_path or not self.master_key:
            QMessageBox.information(
                self, "Bearbeiten", "Bitte zuerst einen Tresor öffnen."
            )
            return
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self,
                "Info",
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist, bevor Sie Dateien bearbeiten.",
            )
            return
        if getattr(self, "_edit_session", None):
            QMessageBox.information(
                self,
                "Info",
                "Es wird bereits eine Datei bearbeitet.\nSchließe zuerst die laufende Bearbeitung ab.",
            )
            return
        if getattr(self, "exporting", False):
            QMessageBox.information(
                self, "Info", "Eine andere Aktion läuft gerade. Bitte kurz warten."
            )
            return

        idx = self._selected_meta_index()
        if idx is None or idx < 0:
            QMessageBox.information(self, "Bearbeiten", "Bitte eine Datei auswählen.")
            return

        entry = dict(self.meta["files"][int(idx)])
        name = entry.get("name", "datei")
        suffix = os.path.splitext(name)[1]

        try:
            fd, tmp_path = tempfile.mkstemp(prefix="ancorate_edit_", suffix=suffix or ".tmp")
            os.close(fd)
        except OSError as e:
            QMessageBox.critical(
                self, "Fehler", f"Temporäre Datei konnte nicht erstellt werden:\n{e}"
            )
            return

        # Cancel any previous operation
        if self.stop_event is not None:
            self.stop_event.set()

        edit_stop_event = threading.Event()
        self.stop_event = edit_stop_event
        worker = ExportWorker(
            self.container_path,
            {**entry, "__save_to": tmp_path},
            self.master_key,
            stop_event=edit_stop_event,
        )
        thread = QThread()
        self._track_worker_thread(thread, edit_stop_event)
        worker.moveToThread(thread)

        self.progress = QProgressDialog(
            "Entschlüssle Datei zum Bearbeiten...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(lambda ev=edit_stop_event: ev.set())
        worker.progress.connect(self._on_progress)
        worker.finished.connect(
            lambda p: self._edit_decrypt_finished(p, thread, worker, int(idx), entry, tmp_path)
        )
        worker.error.connect(lambda e: self._edit_decrypt_error(e, thread, worker, tmp_path))
        thread.started.connect(worker.run)
        thread.start()

    def _open_file_default_app(self, path):
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(path)
            elif system == "Darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
            return True
        except OSError:
            return False

    def _edit_decrypt_finished(self, path, thread, worker, idx, entry, tmp_path):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)

        if self._close_after_workers:
            if not self._secure_purge_file(tmp_path):
                self._discard_edit_tmp(tmp_path)
            return

        if not os.path.isfile(tmp_path) or os.path.getsize(tmp_path) <= 0:
            if not self._secure_purge_file(tmp_path):
                self._discard_edit_tmp(tmp_path)
            QMessageBox.critical(
                self, "Fehler", "Die Datei konnte nicht entschlüsselt werden."
            )
            return

        opened = self._open_file_default_app(tmp_path)
        if not opened:
            self.append_log(
                "Warnung: Keine Standardanwendung für diese Datei gefunden. "
                "Öffnen Sie die Datei manuell aus dem Temp-Verzeichnis."
            )

        try:
            st = os.stat(tmp_path)
            last_stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            last_stat = None

        dlg = EditInVaultDialog(self, _item_name(entry.get("name", "datei")))
        dlg.sessionFinished.connect(self._end_edit_session)

        self._edit_session = {
            "index": int(idx),
            "name": entry.get("name", "datei"),
            "temp_path": tmp_path,
            "last_stat": last_stat,
            "pending_stat": None,
            "stable_ticks": 0,
            "missing_ticks": 0,
            "rewriting": False,
            "dialog": dlg,
        }
        self._edit_poll_timer.start()
        dlg.show()
        self.append_log(f"In-Tresor-Bearbeitung gestartet: {entry.get('name', 'datei')}")

    def _edit_decrypt_error(self, error, thread, worker, tmp_path):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        if not self._secure_purge_file(tmp_path):
            self._discard_edit_tmp(tmp_path)
        if not self._close_after_workers:
            QMessageBox.critical(
                self, "Fehler", f"Entschlüsselung fehlgeschlagen:\n{error}"
            )

    def _poll_edit_session(self):
        s = getattr(self, "_edit_session", None)
        if not s or s.get("rewriting"):
            return
        path = s.get("temp_path")
        if not path:
            return
        try:
            st = os.stat(path)
            stat = (st.st_mtime_ns, st.st_size)
        except OSError:
            s["missing_ticks"] = s.get("missing_ticks", 0) + 1
            return
        s["missing_ticks"] = 0
        if stat == s.get("last_stat"):
            s["stable_ticks"] = 0
            return
        if stat == s.get("pending_stat"):
            s["stable_ticks"] = s.get("stable_ticks", 0) + 1
            if s["stable_ticks"] >= 2:  # ~1 s stabil, Editor hat fertig geschrieben
                self._run_edit_rewrite(s)
        else:
            s["pending_stat"] = stat
            s["stable_ticks"] = 1

    def _run_edit_rewrite(self, s):
        s["rewriting"] = True
        s["last_stat"] = s.get("pending_stat")
        s["pending_stat"] = None
        s["stable_ticks"] = 0

        dialog = s.get("dialog")
        if dialog is not None:
            dialog.allow_close = False
            dialog.finish_button.setEnabled(False)

        # Cancel any previous operation
        if self.stop_event is not None:
            self.stop_event.set()

        rewrite_stop_event = threading.Event()
        self.stop_event = rewrite_stop_event
        worker = RewriteEntryWorker(
            self.container_path,
            dict(self.meta),
            s["index"],
            s["temp_path"],
            self.master_key,
            self.flags,
            stop_event=self.stop_event,
        )
        thread = QThread()
        self._track_worker_thread(thread, rewrite_stop_event)
        worker.moveToThread(thread)

        self.progress = QProgressDialog(
            "Speichere Änderungen im Tresor...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(lambda ev=rewrite_stop_event: ev.set())
        worker.progress.connect(self._on_progress)
        worker.finished.connect(lambda m: self._edit_rewrite_finished(m, thread, worker))
        worker.error.connect(lambda e: self._edit_rewrite_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _edit_rewrite_finished(self, new_meta, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        self.meta = new_meta
        s = getattr(self, "_edit_session", None)
        if s:
            s["rewriting"] = False
            dialog = s.get("dialog")
            if dialog is not None:
                try:
                    dialog.allow_close = True
                    dialog.finish_button.setEnabled(True)
                except Exception:
                    pass
            try:
                st = os.stat(s["temp_path"])
                s["last_stat"] = (st.st_mtime_ns, st.st_size)
            except OSError:
                s["last_stat"] = None
            self.append_log(f"Änderungen im Tresor gespeichert: {s.get('name')}")
        try:
            self.refresh_list()
        except Exception:
            pass

    def _edit_rewrite_error(self, error, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        s = getattr(self, "_edit_session", None)
        if s:
            s["rewriting"] = False
            dialog = s.get("dialog")
            if dialog is not None:
                try:
                    dialog.allow_close = True
                    dialog.finish_button.setEnabled(True)
                except Exception:
                    pass
            try:
                st = os.stat(s["temp_path"])
                s["last_stat"] = (st.st_mtime_ns, st.st_size)
            except OSError:
                s["last_stat"] = None
        if not self._close_after_workers:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Änderungen konnten nicht im Tresor gespeichert werden:\n{error}",
            )
        self.append_log(f"Fehler beim Zurückschreiben in den Tresor: {error}")

    def _end_edit_session(self):
        s = getattr(self, "_edit_session", None)
        if not s:
            return
        self._edit_session = None
        if self._edit_poll_timer.isActive():
            self._edit_poll_timer.stop()

        dialog = s.get("dialog")
        if dialog is not None:
            try:
                dialog.sessionFinished.disconnect(self._end_edit_session)
            except Exception:
                pass
            try:
                dialog.close()
                dialog.deleteLater()
            except Exception:
                pass

        tmp_path = s.get("temp_path")
        if not self._secure_purge_file(tmp_path):
            self._discard_edit_tmp(tmp_path)
        try:
            self.progress.close()
        except Exception:
            pass
        self.append_log(f"In-Tresor-Bearbeitung beendet: {s.get('name')}")

    def _secure_purge_file(self, path, retries=3, delay=0.5):
        """Überschreibt eine entschlüsselte Temp-Datei und löscht sie."""
        if not path or not os.path.exists(path):
            return True
        attempts = 0
        while attempts < retries:
            try:
                size = os.path.getsize(path)
                with open(path, "r+b") as fh:
                    if size > 0:
                        remaining = size
                        chunk = 1024 * 1024
                        fh.seek(0)
                        while remaining > 0:
                            n = min(chunk, remaining)
                            fh.write(os.urandom(n))
                            remaining -= n
                    fh.flush()
                    os.fsync(fh.fileno())
                break
            except OSError:
                attempts += 1
                if delay > 0:
                    time.sleep(delay)
        try:
            os.remove(path)
            return True
        except OSError:
            return False

    def _discard_edit_tmp(self, path):
        """Registriert eine Temp-Datei für spätere Löschversuche."""
        if os.path.exists(path) and [str(path), 0] not in self._edit_cleanup_pending:
            self._edit_cleanup_pending.append([str(path), 0])
            self._schedule_edit_cleanup_retries()

    def _retry_edit_cleanup(self):
        pending = []
        for item in self._edit_cleanup_pending:
            path, attempt = item
            if not self._secure_purge_file(path, retries=1, delay=0):
                if attempt < 12:
                    pending.append([path, attempt + 1])
                else:
                    self.append_log(f"Temporäre Datei konnte nicht gelöscht werden: {path}")
        self._edit_cleanup_pending = pending

    def _schedule_edit_cleanup_retries(self):
        if not self._edit_cleanup_pending:
            return

        def _tick():
            self._retry_edit_cleanup()
            if self._edit_cleanup_pending:
                QTimer.singleShot(10000, _tick)

        QTimer.singleShot(10000, _tick)

    def export_all(self):
        if not self._ensure_container_idle():
            return
        if self.changing_password or self.password_change_in_progress:
            QMessageBox.information(
                self, 
                "Info", 
                "Ein Passwortwechsel wird durchgeführt. Bitte warten Sie, bis dieser abgeschlossen ist, bevor Sie Dateien exportieren."
            )
            return
        if not self.meta.get("files"):
            QMessageBox.information(
                self, "Info", "Keine Dateien zum Exportieren vorhanden."
            )
            return

        # Zielordner wählen
        target_dir = QFileDialog.getExistingDirectory(self, "Zielordner wählen")
        if not target_dir:
            return

        self._start_batch_export([dict(entry) for entry in self.meta["files"]], target_dir)

    def _start_single_export(self, entry: dict, save_to: str):
        self.exporting = True
        # Cancel any previous operation
        if self.stop_event is not None:
            self.stop_event.set()

        export_stop_event = threading.Event()
        self.stop_event = export_stop_event
        entry_copy = dict(entry)
        entry_copy["__save_to"] = save_to
        worker = ExportWorker(
            self.container_path, entry_copy, self.master_key, stop_event=export_stop_event
        )
        thread = QThread()
        self._track_worker_thread(thread, export_stop_event)
        worker.moveToThread(thread)
        worker.finished.connect(lambda p: self._export_finished(p, thread, worker))
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _start_batch_export(self, entries: list[dict], target_dir: str):
        self.exporting = True
        # Cancel any previous operation
        if self.stop_event is not None:
            self.stop_event.set()

        batch_stop_event = threading.Event()
        self.stop_event = batch_stop_event
        worker = ExportBatchWorker(
            self.container_path,
            entries,
            self.master_key,
            target_dir,
            stop_event=batch_stop_event,
        )
        thread = QThread()
        self._track_worker_thread(thread, batch_stop_event)
        worker.moveToThread(thread)

        self.progress = QProgressDialog(
            "Exportiere Dateien...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(lambda ev=batch_stop_event: ev.set())
        self.progress.setValue(0)
        self.progress.show()

        worker.progress.connect(self._on_progress)
        worker.finished.connect(
            lambda paths: self._batch_export_finished(paths, thread, worker)
        )
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _batch_export_finished(self, paths, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        self.exporting = False
        if paths:
            self.append_log(f"Export fertig: {len(paths)} Datei(en)")
            show_toast(
                self,
                "Export fertig",
                f"{len(paths)} Datei(en) wurden exportiert.",
            )
        else:
            QMessageBox.information(self, "Export fertig", "Keine Dateien exportiert.")

    def delete_selected(self):
        if self._delete_in_progress:
            return
        if not self._ensure_container_idle():
            return
        if (
            self.exporting
            or self.changing_password
            or self.password_change_in_progress
            or (self.progress is not None and self.progress.isVisible())
        ):
            QMessageBox.information(
                self,
                "Vorgang läuft",
                "Schließen Sie zuerst den laufenden Datei- oder Tresorvorgang ab.",
            )
            return
        if getattr(self, "_edit_session", None):
            QMessageBox.information(
                self, "Info", "Schließe zuerst die laufende In-Tresor-Bearbeitung ab."
            )
            return
        idx = self._selected_meta_index()
        if idx is None or idx < 0:
            QMessageBox.information(self, "Info", "Bitte eine Datei auswählen.")
            return

        method = self.data.get("deletion_method", "Standard")
        confirm = QMessageBox.question(
            self,
            "Sicheres Löschen",
            f"Datei wirklich mit '{method}' vernichten?\nDies kann bei großen Dateien sehr lange dauern!",
            defaultButton=QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        target = self.meta["files"][int(idx)]
        delete_stop_event = threading.Event()
        self._delete_in_progress = True
        self._delete_committing = False
        self._set_vault_actions_enabled(False)
        self._set_views_enabled(False)
        worker = DeleteWorker(
            self.container_path,
            {
                **self.meta,
                "files": [dict(entry) for entry in self.meta.get("files", [])],
            },
            int(idx),
            self.master_key,
            method,
            delete_stop_event,
        )
        thread = QThread()
        self._track_worker_thread(thread, delete_stop_event)
        worker.moveToThread(thread)
        self.progress = QProgressDialog(
            f"Vernichte Datei mit '{method}'...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.setValue(0)
        self.progress.canceled.connect(delete_stop_event.set)
        self.progress.show()
        worker.progress.connect(self._on_progress)
        worker.committing.connect(self._delete_commit_started)
        worker.finished.connect(
            lambda name, new_meta, overwrite_error: self._delete_finished(
                name, new_meta, overwrite_error, thread, worker
            )
        )
        worker.error.connect(
            lambda error: self._delete_error(error, thread, worker, delete_stop_event)
        )
        thread.started.connect(worker.run)
        thread.start()

    def _delete_commit_started(self):
        self._delete_committing = True
        if self.progress is not None:
            self.progress.setLabelText(
                "Datei entfernt. Der alte Datenbereich wird noch sicher überschrieben..."
            )
            self.progress.setCancelButton(None)

    def _finish_delete_operation(self, thread, worker):
        if self.progress is not None:
            self.progress.close()
            self.progress = None
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)

        self._delete_in_progress = False
        self._delete_committing = False
        self._set_views_enabled(bool(self.master_key))
        self._set_vault_actions_enabled(bool(self.master_key))

    def _delete_finished(self, name, new_meta, overwrite_error, thread, worker):
        self._finish_delete_operation(thread, worker)
        self.meta = new_meta
        self.append_log(f"Erfolgreich vernichtet: {name}")
        self.refresh_list()
        if overwrite_error:
            QMessageBox.warning(
                self,
                "Datei entfernt",
                "Der Eintrag wurde aus dem Tresor entfernt, aber der alte Datenbereich "
                f"konnte nicht vollständig überschrieben werden:\n{overwrite_error}",
            )
        else:
            show_toast(self, "Erfolg", "Die Datei wurde unwiderruflich gelöscht.")
        if self._delete_close_after:
            self._delete_close_after = False
            self.close()

    def _delete_error(self, error, thread, worker, stop_event):
        # Status VOR dem Teardown lesen: _finish_delete_operation() schliesst den
        # QProgressDialog, dessen close() canceled() emittiert und damit den
        # stop_event setzt. Nach dem Teardown waere also jeder echte Fehler als
        # Nutzerabbruch getarnt.
        aborted = stop_event.is_set()
        self._finish_delete_operation(thread, worker)
        if aborted:
            self.append_log("Löschvorgang abgebrochen")
            show_toast(self, "Abgebrochen", "Löschvorgang abgebrochen.")
        else:
            self.append_log(f"FEHLER beim Löschen: {error}")
            QMessageBox.critical(self, "Kritischer Fehler", f"Löschvorgang abgebrochen: {error}")
        if self._delete_close_after:
            self._delete_close_after = False
            self.close()

    def _delete_container_finished(self, path, method, thread, worker):
        self._finish_delete_operation(thread, worker)
        remove_recent_container(path)
        if hasattr(self, "recent_menu"):
            self._refresh_recent_submenu()
        self.update_container_path()
        self.meta = {"files": []}
        self.changing_password = False
        self.password_change_in_progress = False
        self.refresh_list()
        self.append_log(f"Tresor mit {method} erfolgreich vernichtet.")
        show_toast(
            self,
            "Erfolg",
            f"Der Tresor wurde mit {method} sicher gelöscht.",
        )
        if self._delete_close_after:
            self._delete_close_after = False
            self.close()

    def _delete_container_error(self, error, thread, worker, stop_event):
        # Status VOR dem Teardown lesen (siehe _delete_error): das Schliessen
        # des Dialogs setzt selbst den stop_event und wuerde echte Fehler
        # als Nutzerabbruch tarnen.
        aborted = stop_event.is_set()
        self._finish_delete_operation(thread, worker)
        if aborted:
            self.append_log("Löschvorgang des Tresors abgebrochen")
            show_toast(self, "Abgebrochen", "Löschvorgang abgebrochen.")
        else:
            self.append_log(f"Fehler: {error}")
            QMessageBox.critical(
                self, "Kritischer Fehler", f"Löschvorgang fehlgeschlagen: {error}"
            )
        if self._delete_close_after:
            self._delete_close_after = False
            self.close()

    # ------------------ Worker Callbacks ------------------
    def _add_finished(self, added, thread, worker):
        try:
            self.progress.close()
        except Exception:
            pass
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        self.append_log(f"{len(added)} Datei(en) hinzugefügt.")
        try:
            with open(self.container_path, "rb") as fh:
                fh.seek(-META_LEN_SIZE, os.SEEK_END)
                meta_len = struct.unpack("<Q", fh.read(META_LEN_SIZE))[0]
                meta_pos = (
                    os.path.getsize(self.container_path) - META_LEN_SIZE - meta_len
                )
                fh.seek(meta_pos)
                meta_blob = fh.read(meta_len)
                self.meta = decrypt_meta(meta_blob, self.master_key)
        except Exception as e:
            self.append_log(f"Error reloading meta: {e}")
        self._set_views_enabled(bool(self.master_key))
        self._set_vault_actions_enabled(bool(self.master_key))
        self.refresh_list(bool(self.search.text()))

    def _add_worker_error(self, error, thread, worker):
        try:
            self._worker_error(error, thread, worker)
        finally:
            self._set_views_enabled(bool(self.master_key))
            self._set_vault_actions_enabled(bool(self.master_key))

    # ------------------ Worker Callbacks ------------------
    def _worker_error(self, error, thread, worker):
        """Handles errors from worker threads."""
        try:
            self.progress.close()
        except Exception:
            pass

        self.exporting = False

        # Thread sauber beenden
        if thread.isRunning():
            thread.quit()
            thread.wait()

        # Worker und Thread freigeben
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)

        # Fehler anzeigen und loggen
        error_msg = error if isinstance(error, str) else str(error)
        if not error_msg:
            error_msg = repr(error)
        if not self._close_after_workers:
            QMessageBox.critical(self, "Fehler", error_msg)
        self.append_log(f"Fehler: {error_msg}")

    def _export_finished(self, path, thread, worker):
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        self.exporting = False
        show_toast(self, "Export fertig", f"Datei gespeichert: {path}")
        self.append_log(f"Export fertig: {path}")

    def append_log(self, txt):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {txt}")
        self.status.setText(txt)

    def closeEvent(self, event):
        if self._delete_in_progress:
            if self._delete_committing:
                self._delete_close_after = True
                event.ignore()
                return
            if not self._delete_close_after:
                reply = QMessageBox.question(
                    self,
                    "Löschvorgang abbrechen?",
                    "Der laufende Löschvorgang muss beendet werden, bevor das Programm schließen kann. Abbrechen?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
                self._delete_close_after = True
                if self._delete_in_progress and self.progress is not None:
                    self.progress.cancel()
                elif not self._delete_in_progress:
                    QTimer.singleShot(0, self.close)
            event.ignore()
            return

        if self._worker_threads:
            if not self._close_after_workers:
                reply = QMessageBox.question(
                    self,
                    "Vorgänge werden beendet",
                    "Es laufen noch Hintergrundvorgänge. Möchten Sie sie abbrechen und nach ihrem sicheren Ende schließen?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                if reply != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return

                self._close_after_workers = True
                for stop_event, _container_operation in self._worker_threads.values():
                    if stop_event is not None:
                        stop_event.set()
                if self.progress is not None and self.progress.isVisible():
                    self.progress.setLabelText("Vorgang wird sicher beendet...")
                    self.progress.setCancelButton(None)
            if not self._worker_threads:
                QTimer.singleShot(0, self.close)
            event.ignore()
            return

        self._end_edit_session()

        # Schlaf-/Lock-Monitor stoppen (optionaler gdbus-Subprozess beenden)
        try:
            self._power_monitor.stop()
        except Exception:
            pass

        # Best effort: clean up any remaining temp files
        for item in list(self._edit_cleanup_pending):
            path, _ = item
            self._secure_purge_file(path, retries=1, delay=0)
        self._edit_cleanup_pending.clear()

        # Einstellungen neu laden für aktuellen confirm_exit Status
        current_settings = load_settings()
        if current_settings.get("confirm_exit", True):
            reply = QMessageBox.question(
                self,
                f"ANCORATE {edition} beenden",
                f"Möchten Sie ANCORATE {edition} wirklich beenden?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )

            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return

        event.accept()

        # Python bytes are immutable; release any remaining application reference.
        if getattr(self, "master_key", None) is not None:
            self.master_key = None

    # ------------------ Worker Callbacks ------------------
    def _on_progress(self, v):
        """Aktualisiert den Fortschrittsbalken."""
        try:
            # 'self.progress' in __init__ initialisieren, damit es immer existiert
            self.progress.setValue(v)
        except Exception as e:
            print(f"Fehler beim Update des Progressbars: {e}")

    # ------------------ Suchfunktion ------------------
    def start_search(self):
        query = self.search.text().strip()
        if not query:
            self.refresh_list()
            return

        self.refresh_list(True)
    
    def keep_search(self):
        """Suchleiste am Leben erhalten (Kompatibilitäts-Stub).

        Die Live-Suche wird über das textChanged-Signal des QLineEdit im
        GUI-Thread ausgelöst (siehe __init__). Diese Methode greift deshalb
        NICHT mehr auf Qt-Widgets aus einem Hintergrund-Thread zu, um
        Race-Conditions und Qt-Cross-Thread-Fehler zu vermeiden.
        """
        return

    # ------------------ Dateibaum aktualisieren ------------------
    def _file_columns(self, name, ent, show_size, show_date):
        """Spaltenwerte (Name, Größe, Geändert, Typ) für eine Dateizeile."""
        size_text = self._size_text(ent.get("size", 0)) if show_size else ""
        mtime = ent.get("mtime") if show_date else None
        date_text = (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)) if mtime else ""
        )
        return (_item_name(name), size_text, date_text, type_label(name))

    def _file_icon(self, filename=""):
        icon = file_type_icon(filename)
        if not icon.isNull():
            return icon
        return self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)

    # ------------------ Geführter Leerzustand ------------------
    def _ensure_empty_state(self):
        key = id(self.file_list)
        ov = self._overlays.get(key)
        if ov is None:
            ov = EmptyStateOverlay(self.file_list)
            ov.createRequested.connect(lambda: self.choose_container(2))
            ov.openRequested.connect(lambda: self.choose_container(1))
            self.file_list.set_overlay(ov)
            ov.hide()
            self._overlays[key] = ov
        return ov

    def _update_empty_state(self, show: bool):
        ov = self._ensure_empty_state()
        if not show:
            ov.hide()
            return
        if self.master_key is not None:
            title = "Noch keine Dateien in diesem Tresor"
            hint = (
                "Füge Dateien per Ziehen & Ablegen, Strg+V oder über das "
                "Menü „Datei(en) hinzufügen“ (Strg++) hinzu."
            )
            ov.set_text(title, hint, buttons=False)
        else:
            title = f"Willkommen bei ANCORATE {edition}"
            hint = (
                "Öffne einen Tresor (Strg+O), wähle einen zuletzt verwendeten "
                "im Menü „Datei“, oder erstelle einen neuen (Strg+N)."
            )
            ov.set_text(title, hint, buttons=True)
        ov.show()
        self.file_list._center_overlay(ov)
        QTimer.singleShot(
            0,
            lambda view=self.file_list, overlay=ov: (
                view._center_overlay(overlay) if overlay.isVisible() else None
            ),
        )

    @staticmethod
    def _search_terms(query: str) -> list:
        return [t for t in query.lower().split() if t]

    @staticmethod
    def _matches(terms, *texts) -> bool:
        """Alle Suchbegriffe müssen vorkommen (UND-Verknüpfung)."""
        hay = " ".join(str(t) for t in texts if t).lower()
        return all(term in hay for term in terms)

    def _show_empty_message(self, title: str, hint: str):
        ov = self._ensure_empty_state()
        ov.set_text(title, hint, buttons=False)
        ov.show()
        self.file_list._center_overlay(ov)
        QTimer.singleShot(
            0,
            lambda view=self.file_list, overlay=ov: (
                view._center_overlay(overlay) if overlay.isVisible() else None
            ),
        )

    def refresh_list(self, searching: bool = False):
        if not getattr(self.file_list, "isEnabled", lambda: True)():
            return
        self.file_list.clear()
        files = self.meta.get("files", [])
        s = self.data if isinstance(self.data, dict) else {}
        show_size = bool(s.get("list_show_size", True))
        show_date = bool(s.get("list_show_date", True))
        sort_by_name = s.get("list_sort", "Keine") == "Name"

        if searching:
            self._render_search_results(show_size, show_date)
            return

        if self.view_mode == "grid":
            self._render_grid(show_size, show_date, sort_by_name)
            self._update_empty_state(not files)
            return

        self._render_tree(show_size, show_date, sort_by_name)
        self._update_empty_state(not files)

    def _render_search_results(self, show_size, show_date):
        """Smarte, flache Trefferliste über Dateien UND Ordner.

        Mehrere Begriffe werden UND-verknüpft; Treffer im Datei-/Ordnernamen
        werden gegenüber reinen Pfadtreffern bevorzugt sortiert.
        """
        terms = self._search_terms(self.search.text())
        if not terms:
            self.refresh_list()
            return

        rows = []  # (score, sort_name, role, ent|None)
        for folder in self._all_folders():
            if self._matches(terms, folder):
                name = _item_name(folder).lower()
                score = 0 if self._matches(terms, name) else 1
                rows.append((score, name, ("folder", folder), None))
        for idx, ent in enumerate(self.meta.get("files", [])):
            name = ent.get("name", "<unnamed>")
            if not self._matches(terms, name):
                continue
            base = _item_name(name).lower()
            score = 0 if self._matches(terms, base) else 1
            rows.append((score, base, idx, ent))
        rows.sort(key=lambda r: (r[0], r[1]))

        if self.view_mode == "grid":
            for _score, _name, role, ent in rows:
                if ent is None:
                    self._grid.addItem(
                        self._grid.make_item(
                            role, _item_name(role[1]),
                            self._folder_icon(), bold=True,
                        )
                    )
                else:
                    file_name = ent.get("name", "?")
                    self._grid.addItem(
                        self._grid.make_item(
                            role, _item_name(file_name),
                            self._file_icon(file_name),
                        )
                    )
        else:
            for _score, _name, role, ent in rows:
                if ent is None:
                    columns = (_item_name(role[1]), "", "", "Ordner")
                    self._tree.addTopLevelItem(
                        self._tree.make_item(
                            role, columns, icon=self._folder_icon(), bold=True
                        )
                    )
                else:
                    self._add_file_row(role, ent, show_size, show_date)

        if rows:
            self._update_empty_state(False)
        else:
            self._show_empty_message(
                "Keine Treffer",
                f'Keine Dateien oder Ordner für „{self.search.text()}“ gefunden.',
            )

    def _add_file_row(self, idx, ent, show_size, show_date, parent=None):
        name = ent.get("name", "<unnamed>")
        columns = self._file_columns(
            name, ent, show_size, show_date
        )
        item = self._tree.make_item(idx, columns, icon=self._file_icon(name))
        if parent is None:
            self._tree.addTopLevelItem(item)
        else:
            parent.addChild(item)
        return item

    def _render_grid(self, show_size, show_date, sort_by_name):
        """Rasteransicht des aktuellen Ordners (mit 'Zurück'-Kachel)."""
        if self.current_folder:
            self._grid.addItem(
                self._grid.make_item(
                    ("folder_up", _folder_of(self.current_folder)),
                    "\u2190 Zurück",
                    self._folder_icon(),
                )
            )
        for folder in self._child_folders(
            self.current_folder, self._all_folders()
        ):
            self._grid.addItem(
                self._grid.make_item(
                    ("folder", folder), _item_name(folder),
                    self._folder_icon(), bold=True,
                )
            )
        entries = self._direct_files()
        if sort_by_name:
            entries.sort(key=lambda t: _item_name(t[1].get("name", "")).lower())
        for idx, ent in entries:
            name = ent.get("name", "")
            label = _item_name(name)
            item = self._grid.make_item(idx, label, self._file_icon(name))
            size = self._size_text(ent.get("size", 0)) if show_size else ""
            item.setToolTip(f"{name}\n{size}" if size else name)
            self._grid.addItem(item)

    # ------------------ Ordner: Datenmodell & Helfer ------------------
    def _all_folders(self) -> set:
        """Alle Ordnerpfade: explizit (meta['folders']) plus implizite Eltern."""
        folders = set(self.meta.get("folders") or [])
        for ent in self.meta.get("files", []):
            name = ent.get("name", "")
            parts = name.split(FOLDER_SEP)[:-1]
            p = ""
            for part in parts:
                p = f"{p}{FOLDER_SEP}{part}" if p else part
                if p:
                    folders.add(p)
        return {f for f in folders if f}

    def _folder_icon(self):
        if getattr(self, "_folder_icon_impl", None) is None:
            self._folder_icon_impl = self.style().standardIcon(
                QStyle.StandardPixmap.SP_DirIcon)
        return self._folder_icon_impl

    def _child_folders(self, folder: str, folders: set) -> list:
        prefix = folder + FOLDER_SEP if folder else ""
        return sorted(
            (f for f in folders
             if f.startswith(prefix) and FOLDER_SEP not in f[len(prefix):]),
            key=str.lower,
        )

    def _direct_files(self):
        """Dateien direkt im aktuellen Ordner (ohne Unterordner)."""
        prefix = (
            self.current_folder + FOLDER_SEP if self.current_folder else ""
        )
        items = []
        for idx, ent in enumerate(self.meta.get("files", [])):
            name = ent.get("name", "")
            if name.startswith(prefix) and FOLDER_SEP not in name[len(prefix):]:
                items.append((idx, ent))
        return items

    def _is_expanded(self, folder: str) -> bool:
        return self._expanded_folders is None or folder in self._expanded_folders

    def _toggle_folder(self, folder: str):
        if self._expanded_folders is None:
            self._expanded_folders = set(self._all_folders())
        if folder in self._expanded_folders:
            self._expanded_folders.discard(folder)
        else:
            self._expanded_folders.add(folder)

    def _size_text(self, size: int) -> str:
        if size < 1024:
            return f"{size} B"
        if size < 1024**2:
            return f"{size / 1024:.1f} KB"
        if size < 1024**3:
            return f"{size / 1024**2:.2f} MB"
        if size < 1024**4:
            return f"{size / 1024**3:.2f} GB"
        return f"{size / 1024**4:.2f} TB"

    def _render_tree(self, show_size: bool, show_date: bool, sort_by_name: bool):
        """Baut den Ordnerbaum: echte Hierarchie, Ordner vor Dateien."""
        self.file_list.setSortingEnabled(False)
        folder_items = {}

        def ensure_folder(path: str):
            if path in folder_items:
                return folder_items[path]
            parent_path = _folder_of(path)
            parent_item = ensure_folder(parent_path) if parent_path else None
            item = self.file_list.make_item(
                ("folder", path),
                (_item_name(path), "", "", "Ordner"),
                icon=self._folder_icon(),
                bold=True,
            )
            if parent_item is None:
                self.file_list.addTopLevelItem(item)
            else:
                parent_item.addChild(item)
            folder_items[path] = item
            return item

        for folder in sorted(self._all_folders(), key=str.lower):
            ensure_folder(folder)

        # Dateien nach ihrem Elternordner gruppieren
        by_parent: dict[str, list] = {}
        for idx, ent in enumerate(self.meta.get("files", [])):
            parent = _folder_of(ent.get("name", ""))
            by_parent.setdefault(parent, []).append((idx, ent))

        # Root-Dateien (nach den Ordnern)
        root_files = by_parent.get("", [])
        if sort_by_name:
            root_files.sort(key=lambda t: _item_name(t[1].get("name", "")).lower())
        for idx, ent in root_files:
            self._add_file_row(idx, ent, show_size, show_date)

        # Dateien je Ordner
        for path, item in folder_items.items():
            entries = by_parent.get(path, [])
            if sort_by_name:
                entries.sort(key=lambda t: _item_name(t[1].get("name", "")).lower())
            for idx, ent in entries:
                self._add_file_row(idx, ent, show_size, show_date, parent=item)
            item.setExpanded(self._is_expanded(path))

    def _on_item_double_clicked(self, item, _column=0):
        role = self.file_list.role(item)
        if isinstance(role, tuple) and len(role) == 2:
            kind, path = role
            if kind == "folder":
                if self.search.text():
                    # Treffer aus der Suche: Suche beenden und Ordner ansteuern
                    self._activate_folder(path)
                elif self.view_mode == "grid":
                    self.current_folder = path
                    self.refresh_list()
                else:
                    self._toggle_folder(path)
                    item.setExpanded(self._is_expanded(path))
                return
            if kind == "folder_up":
                self.current_folder = path
                self.refresh_list()
                return
        self.start_in_vault_edit()

    def _set_search_text(self, text: str):
        self.search.blockSignals(True)
        self.search.setText(text)
        self.search.blockSignals(False)
        self.start_search()

    def _focus_search(self):
        self.search.setFocus()
        self.search.selectAll()

    def _expand_all_folders(self):
        self._expanded_folders = None  # None = alle ausgeklappt
        self.refresh_list()

    def _collapse_all_folders(self):
        self._expanded_folders = set()
        self.refresh_list()

    def _scroll_to_role(self, role):
        if self.view_mode == "grid":
            for i in range(self._grid.count()):
                item = self._grid.item(i)
                if self._grid.role(item) == role:
                    self._grid.setCurrentItem(item)
                    self._grid.scrollToItem(item)
                    item.setSelected(True)
                    return item
            return None

        def walk(item):
            if self._tree.role(item) == role:
                return item
            for i in range(item.childCount()):
                found = walk(item.child(i))
                if found is not None:
                    return found
            return None

        for i in range(self._tree.topLevelItemCount()):
            found = walk(self._tree.topLevelItem(i))
            if found is not None:
                self._tree.setCurrentItem(found)
                self._tree.scrollToItem(found)
                found.setSelected(True)
                return found
        return None

    def _activate_folder(self, folder: str):
        """Ordner aus der Suchtrefferliste ansteuern (Suche beenden + aufklappen)."""
        if self.search.text():
            self._set_search_text("")
        if self.view_mode == "grid":
            self.current_folder = folder
            self.refresh_list()
            return
        if self._expanded_folders is not None:
            self._expanded_folders.add(folder)
        self.refresh_list()
        self._scroll_to_role(("folder", folder))

    def _target_folder(self) -> str:
        """Ordner-Zielkontext für Hinzufügen (Auswahl ↝ Ordner ↝ aktueller)."""
        item = self.file_list.currentItem()
        if item is not None:
            role = self.file_list.role(item)
            if isinstance(role, tuple) and len(role) == 2 and role[0] == "folder":
                return role[1]
            if isinstance(role, int):
                try:
                    return _folder_of(self.meta["files"][role].get("name", ""))
                except Exception:
                    pass
        if self.view_mode == "grid":
            return self.current_folder
        return ""

    def _on_context_menu(self, pos):
        item = self.file_list.itemAt(pos)
        role = self.file_list.role(item) if item is not None else None
        if isinstance(role, tuple) and len(role) == 2 and role[0] == "folder":
            self._folder_context_menu(role[1], pos)
        elif isinstance(role, int):
            self._file_context_menu(pos, role)
        else:
            self._empty_context_menu(pos)

    def _folder_context_menu(self, folder, pos):
        menu = QMenu(self)
        act_open = menu.addAction("Ordner aufklappen")
        act_newsub = menu.addAction("Unterordner erstellen…")
        menu.addSeparator()
        act_rename = menu.addAction("Ordner umbenennen…")
        act_move = menu.addAction("Ausgewählte Dateien hierher verschieben")
        act_move.setEnabled(bool(self.file_list.selectedItems()))
        menu.addSeparator()
        act_delete = menu.addAction("Ordner löschen")
        chosen = menu.exec(self.file_list.viewport().mapToGlobal(pos))
        if chosen == act_open:
            self._activate_folder(folder)
        elif chosen == act_newsub:
            self._new_folder(target=folder)
        elif chosen == act_rename:
            self._rename_folder(folder)
        elif chosen == act_move:
            self._move_selected_to_folder(folder)
        elif chosen == act_delete:
            self._delete_folder(folder)

    def _file_context_menu(self, pos, file_index):
        menu = QMenu(self)
        act_preview = menu.addAction("Vorschau")
        act_edit = menu.addAction("Im Tresor bearbeiten")
        menu.addSeparator()
        act_export = menu.addAction("Exportieren…")
        act_move = menu.addAction("In Ordner verschieben…")
        menu.addSeparator()
        act_delete = menu.addAction("Löschen")
        menu.addSeparator()
        act_properties = menu.addAction("Eigenschaften")
        chosen = menu.exec(self.file_list.viewport().mapToGlobal(pos))
        if chosen == act_properties:
            self._show_file_properties(file_index)
        elif chosen == act_preview:
            self.preview_selected()
        elif chosen == act_edit:
            self.start_in_vault_edit()
        elif chosen == act_export:
            self.export_selected()
        elif chosen == act_move:
            self._move_selected_to_folder("")
        elif chosen == act_delete:
            self.delete_selected()

    def _show_file_properties(self, file_index):
        entries = self.meta.get("files", [])
        if not isinstance(entries, list) or not 0 <= file_index < len(entries):
            return

        entry = entries[file_index]
        name = str(entry.get("name", "<unbenannt>"))
        try:
            size_text = self._size_text(int(entry.get("size", 0)))
        except (TypeError, ValueError, OverflowError):
            size_text = "Unbekannt"

        rows = [
            ("Name", _item_name(name)),
            ("Typ", type_label(name)),
            ("Größe", size_text),
        ]
        folder = _folder_of(name)
        if folder:
            rows.append(("Ordner im Tresor", folder))

        for field, label in (
            ("mtime", "Quelle zuletzt geändert"),
            ("created", "Quelle erstellt (Dateisystem)"),
            ("added", "Zum Tresor hinzugefügt"),
            ("edited", "Im Tresor bearbeitet"),
        ):
            timestamp = entry.get(field)
            if timestamp is None:
                continue
            try:
                formatted = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(float(timestamp))
                )
            except (OverflowError, OSError, TypeError, ValueError):
                formatted = "Unbekannt"
            rows.append((label, formatted))

        if entry.get("sha256"):
            rows.append(("SHA-256", str(entry["sha256"])))

        FilePropertiesDialog(self, rows).exec()

    def _empty_context_menu(self, pos):
        menu = QMenu(self)
        act_add = menu.addAction("Dateien hinzufügen…")
        act_new = menu.addAction("Neuer Ordner…")
        menu.addSeparator()
        act_expand = menu.addAction("Alle Ordner ausklappen")
        act_collapse = menu.addAction("Alle Ordner einklappen")
        menu.addSeparator()
        act_refresh = menu.addAction("Aktualisieren")
        chosen = menu.exec(self.file_list.viewport().mapToGlobal(pos))
        if chosen == act_add:
            self.add_file_dialog()
        elif chosen == act_new:
            self._new_folder()
        elif chosen == act_expand:
            self._expand_all_folders()
        elif chosen == act_collapse:
            self._collapse_all_folders()
        elif chosen == act_refresh:
            self.refresh_list(bool(self.search.text()))

    def _new_folder(self, target: str | None = None):
        if not self.master_key or not self.container_path:
            QMessageBox.information(self, "Info", "Bitte zuerst einen Tresor öffnen.")
            return
        if target is None:
            target = self._target_folder()
        base = f"{target}{FOLDER_SEP}" if target else ""
        name, ok = QInputDialog.getText(
            self, "Neuer Ordner", "Ordnername (verschachtelt möglich, z.B. A/B):",
            text="Neuer Ordner",
        )
        if not ok or not name.strip():
            return
        previous_meta = copy.deepcopy(self.meta)
        try:
            clean_name = _normalize_logical_path(name)
            target = _normalize_logical_path(target, allow_empty=True)
        except ValueError as error:
            QMessageBox.warning(self, "Ungültiger Ordnername", str(error))
            return
        base = f"{target}{FOLDER_SEP}" if target else ""
        path = f"{base}{clean_name}"
        folders = set(self.meta.get("folders") or [])
        folders.add(path)
        self.meta["folders"] = sorted(folders, key=str.lower)

        def on_saved():
            self.current_folder = path
            if self._expanded_folders is None:
                self._expanded_folders = set(self._all_folders())
            self._expanded_folders.add(_folder_of(path))
            self._expanded_folders.add(path)
            self.refresh_list(bool(self.search.text()))
            show_toast(self, "Ordner erstellt", path)

        self._save_meta(previous_meta, on_saved)

    def _move_selected_to_folder(self, target: str):
        idxs = self._selected_meta_indexes()
        if not idxs:
            QMessageBox.information(self, "Verschieben", "Bitte zuerst Dateien auswählen.")
            return
        if target == "":
            folders_now = sorted(self._all_folders(), key=str.lower)
            choices = folders_now + ["(Root)"]
            current, ok = QInputDialog.getItem(
                self, "In Ordner verschieben",
                "Zielordner (oder neuen Namen eingeben):",
                choices, 0, True,
            )
            if not ok or not current:
                return
            try:
                target = (
                    ""
                    if current == "(Root)"
                    else _normalize_logical_path(current)
                )
            except ValueError as error:
                QMessageBox.warning(self, "Ungültiger Zielordner", str(error))
                return
        self._apply_move(idxs, target)

    # ------------------ Drag&Drop: Dateien im Tresor verschieben ------------------
    def _on_items_moved(self, roles, target_role):
        """Dateien aus der Baum-/Rasteransicht in einen Ordner verschieben."""
        if isinstance(target_role, tuple) and len(target_role) == 2 \
                and target_role[0] == "folder":
            target = target_role[1]
        elif isinstance(target_role, int):
            try:
                target = _folder_of(self.meta["files"][target_role].get("name", ""))
            except Exception:
                target = ""
        elif self.view_mode == "grid":
            target = self.current_folder
        else:
            target = ""  # auf leeren Bereich -> Wurzel
        self._apply_move([int(r) for r in roles], target)

    def _apply_move(self, indexes, target: str):
        """Verschiebt Datei-Einträge in den Zielordner (nur Pfad/Name, keine
        Neuverschlüsselung) und hält Namen eindeutig."""
        previous_meta = copy.deepcopy(self.meta)
        try:
            target = _normalize_logical_path(target, allow_empty=True)
        except ValueError as error:
            QMessageBox.warning(self, "Ungültiger Zielordner", str(error))
            return
        folders = set(self.meta.get("folders") or [])
        prefix = target + FOLDER_SEP if target else ""
        changed = []
        for i in indexes:
            try:
                ent = self.meta["files"][i]
            except (IndexError, TypeError):
                continue
            name = ent.get("name", "")
            if _folder_of(name) == target:
                continue
            basename = _item_name(name)
            new_name = prefix + basename
            if new_name == name:
                continue
            ent["name"] = self._unique_entry_name(new_name, exclude=i)
            changed.append(basename)
        if not changed:
            show_toast(self, "Verschieben", "Keine Dateien verschoben.")
            return
        if target:
            folders.add(target)
        self.meta["folders"] = sorted(folders, key=str.lower)

        def on_saved():
            self.current_folder = target
            self.refresh_list(bool(self.search.text()))
            show_toast(
                self, "Verschoben",
                f"{len(changed)} Datei(en) nach „{target or '(Root)'}“.",
            )

        self._save_meta(previous_meta, on_saved)

    def _unique_entry_name(self, name: str, exclude: int) -> str:
        """Fügt bei Namenskollision einen Zähler an (datei.txt -> datei (2).txt)."""
        existing = {
            e.get("name")
            for i, e in enumerate(self.meta.get("files", []))
            if i != exclude
        }
        if name not in existing:
            return name
        folder = _folder_of(name)
        base = _item_name(name)
        stem, ext = os.path.splitext(base)
        counter = 2
        while True:
            candidate_base = f"{stem} ({counter}){ext}"
            candidate = f"{folder}{FOLDER_SEP}{candidate_base}" if folder else candidate_base
            if candidate not in existing:
                return candidate
            counter += 1

    def _rename_folder(self, folder: str):
        name, ok = QInputDialog.getText(
            self, "Ordner umbenennen", "Neuer Name:", text=_item_name(folder)
        )
        if not ok or not name.strip():
            return
        try:
            new_name = _normalize_logical_path(name)
        except ValueError as error:
            QMessageBox.warning(self, "Ungültiger Ordnername", str(error))
            return
        parent = _folder_of(folder)
        new_folder = f"{parent}{FOLDER_SEP}{new_name}" if parent else new_name
        if new_folder == folder:
            return
        existing = self._all_folders() - {folder}
        if new_folder in existing:
            QMessageBox.information(
                self, "Umbenennen",
                f"Der Ordner „{new_folder}“ existiert bereits.",
            )
            return
        previous_meta = copy.deepcopy(self.meta)
        old_prefix = folder + FOLDER_SEP
        new_prefix = new_folder + FOLDER_SEP
        new_folders = set()
        for f in (self.meta.get("folders") or []):
            if f == folder:
                new_folders.add(new_folder)
            elif f.startswith(old_prefix):
                new_folders.add(new_prefix + f[len(old_prefix):])
            else:
                new_folders.add(f)
        for ent in self.meta.get("files", []):
            name = ent.get("name", "")
            if name.startswith(old_prefix):
                ent["name"] = new_prefix + name[len(old_prefix):]
        self.meta["folders"] = sorted(new_folders, key=str.lower)

        def on_saved():
            self.current_folder = new_folder
            self.refresh_list(bool(self.search.text()))
            show_toast(self, "Umbenannt", f"{folder} → {new_folder}")

        self._save_meta(previous_meta, on_saved)

    def _delete_folder(self, folder: str):
        prefix = folder + FOLDER_SEP
        members = sum(1 for e in self.meta.get("files", [])
                      if e.get("name", "").startswith(prefix))
        reply = QMessageBox.question(
            self,
            "Ordner löschen",
            f"Ordner „{folder}“ löschen?\n\n"
            f"{members} Datei(en) werden eine Ebene nach oben verschoben.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        previous_meta = copy.deepcopy(self.meta)
        parent = _folder_of(folder)
        for ent in self.meta.get("files", []):
            name = ent.get("name", "")
            if name.startswith(prefix):
                tail = name[len(prefix):]
                ent["name"] = f"{parent}{FOLDER_SEP}{tail}" if parent else tail
        folders = {
            f for f in (self.meta.get("folders") or [])
            if f != folder and not f.startswith(prefix)
        }
        self.meta["folders"] = sorted(folders, key=str.lower)

        def on_saved():
            self.current_folder = parent
            self.refresh_list(bool(self.search.text()))
            show_toast(self, "Ordner gelöscht", folder)

        self._save_meta(previous_meta, on_saved)

    def _save_meta(self, previous_meta, on_success):
        """Schreibt ausschließlich die (verschlüsselte) Meta neu (keine Blob-Änderung).

        Der atomare Austausch läuft im Hintergrund; bis zum Commit bleibt der
        bisherige Container unverändert.
        """
        pending_meta = copy.deepcopy(self.meta)
        self.meta = previous_meta
        stop_event = threading.Event()
        worker = MetadataSaveWorker(
            self.container_path,
            pending_meta,
            self.master_key,
            self.flags,
            stop_event,
        )
        thread = QThread()
        self._track_worker_thread(thread, stop_event)
        worker.moveToThread(thread)

        self._set_vault_actions_enabled(False)
        self._set_views_enabled(False)
        self.progress = QProgressDialog(
            "Speichere Tresoränderung sicher...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.setWindowModality(Qt.WindowModality.ApplicationModal)
        self.progress.canceled.connect(stop_event.set)
        worker.progress.connect(self._on_progress)
        worker.finished.connect(
            lambda new_meta: self._metadata_save_finished(
                new_meta, thread, worker, on_success
            )
        )
        worker.error.connect(
            lambda error: self._metadata_save_error(
                error, previous_meta, thread, worker
            )
        )
        self.progress.show()
        thread.started.connect(worker.run)
        thread.start()

    def _finish_metadata_save(self, thread, worker):
        if self.progress is not None:
            self.progress.close()
            self.progress = None
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self._release_worker_thread(thread)
        self._set_views_enabled(bool(self.master_key))
        self._set_vault_actions_enabled(bool(self.master_key))

    def _metadata_save_finished(self, new_meta, thread, worker, on_success):
        self.meta = new_meta
        self._finish_metadata_save(thread, worker)
        on_success()

    def _metadata_save_error(self, error, previous_meta, thread, worker):
        self.meta = previous_meta
        self._finish_metadata_save(thread, worker)
        error_msg = str(error) or repr(error)
        self.append_log(f"FEHLER beim Speichern der Metadaten: {error_msg}")
        if not self._close_after_workers:
            QMessageBox.critical(
                self,
                "Fehler",
                f"Metadaten konnten nicht gespeichert werden. "
                f"Der Tresor blieb unverändert:\n{error_msg}",
            )