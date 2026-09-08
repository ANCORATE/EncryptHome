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
import secrets
import requests
import tempfile
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
from utilities.screenshot_protection import (
    install_screenshot_protection,
    uninstall_screenshot_protection,
)
from utilities.settings import *

from app.core import *
from app.core import _secure_zero_bytes
from app.passwords import *
from app.workers import *
from app.dialogs import *
# ============================================================
# Hauptfenster (App-Klasse, aus main.py)
# ============================================================

class App(QWidget):
    LAN_DISC_PORT = 48291  # UDP-Port für LAN-Discovery
    LAN_TCP_PORT = 48292  # TCP-Port für LAN-Verbindungen
    LAN_MAGIC = b"ANCORATE_DISCOVER_V1"
    LAN_CHUNK = 64 * 1024  # 64 KiBp

    def __init__(self):  # Hauptfenster der Anwendung
        super().__init__()
        self.setWindowTitle(f"ANCORATE {edition} {version} - kein Tresor geöffnet")
        self.setWindowIcon(get_app_icon())
        self.resize(1080, 720)
        self.exporting = False
        self.pwd = ""
        self.MAX_ATTEMPTS = 3
        self.attempts = 0
        self.container_path = None
        self.master_key = None
        self.flags = 0
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.rekey_temp_backup = None
        self.stop_event = None
        self.progress = None
        self._lan_sharing = False
        self._lan_threads = []
        self._lan_tcp_sock = None
        self.settings_dialog = SettingsDialog
        self._settings_dialog = None
        self.update_worker = None
        self.update_news_shown = False
        self.data = load_settings()
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

        self.layout = QVBoxLayout(self)
        
        # ---- GUI Elemente erstellen ----
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Container (.salt)"))
        self.container_label = QLineEdit()
        row1.addWidget(self.container_label)
        btn_choose = QPushButton("➕")
        btn_choose.clicked.connect(self.choose_container)
        row1.addWidget(btn_choose)
        self.layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Suchen:"))
        self.search = QLineEdit()
        self.searchbar_content = ""
        row2.addWidget(self.search)
        self.layout.addLayout(row2)

        # --- File List ---
        self.file_list = FileDropList()
        self.file_list.fileDropped.connect(self.add_files)
        self.layout.addWidget(self.file_list)

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

        self.file_list.itemDoubleClicked.connect(self.start_in_vault_edit)

        # Live-Suche: textChanged feuert im GUI-Thread, sodass keine
        # Qt-Widgets aus einem Hintergrund-Thread angesprochen werden.
        self.search.textChanged.connect(self.start_search)

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

        self.status = QLabel(
            "Session gestartet. - 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin"
        )
        self.status.setObjectName("status")
        self.layout.addWidget(self.status)

        self.setLayout(self.layout)
        self.setStyleSheet(APP_STYLE)

        # Hauptfenster für animierte Theme-Wechsel (Fade-Überblendung) anmelden
        register_main_window(self)
        
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

        self.apply_settings()  # Initial anwenden
        
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
        self.update_data = data
        if not self.is_update_available(data):
            return

        self.status.setText(
            f"Update verfügbar: v{data.get('version')} – Öffnen Sie Einstellungen > Updates"
        )

        self.show_update_news(data)

    def on_update_check_error(self, error_msg: str):
        print(f"[UPDATE] Updatecheck fehlgeschlagen: {error_msg}")

    def show_update_news(self, data: dict):
        if self.update_news_shown:
            return
        self.update_news_shown = True

        dlg = UpdateNewsDialog(self, data)
        dlg.exec()

    # ------------------ Menüleiste ------------------
    def add_menubar(self):
        self._rebuild_menubar()

    def _rebuild_menubar(self):
        menubar = QMenuBar()
        
        # Datei-Menü
        file_menu = QMenu("Datei", self)
        self.recent_menu = self._build_recent_submenu()
        file_menu.aboutToShow.connect(self._refresh_recent_submenu)
        actions_file = [
            QAction("Neuer Tresor", self),
            QAction("Tresor öffnen", self),
            None,  # Platzhalter - wird durch das Recent-Untermenü ersetzt
            QAction("Tresorpasswort ändern", self),
            QAction("Tresor schließen", self),
            QAction("Tresor löschen", self),
            None,  # Separator
            QAction("Einstellungen", self),
        ]
        actions_file[1].triggered.connect(lambda: self.choose_container(1))
        actions_file[0].triggered.connect(lambda: self.choose_container(2))
        actions_file[3].triggered.connect(self.change_container_password_dialog)
        actions_file[4].triggered.connect(self.close_container)
        actions_file[5].triggered.connect(self.delete_container)
        actions_file[7].triggered.connect(lambda: self.show_settings_dialog())
        for i, a in enumerate(actions_file):
            if i == 2:
                # „Zuletzt verwendete Tresore" als Untermenü (öffnet bei Hover)
                file_menu.addMenu(self.recent_menu)
            elif a is None:
                file_menu.addSeparator()
            else:
                file_menu.addAction(a)

        # Bearbeiten-Menü
        edit_menu = QMenu("Bearbeiten", self)
        actions_edit = [
            QAction("Datei(en) hinzufügen", self),
            QAction("Dateivorschau starten", self),
            QAction("Datei im Tresor bearbeiten", self),
            QAction("Datei löschen", self),
            QAction("Datei exportieren", self),
            QAction("Alles exportieren", self),
        ]
        actions_edit[0].triggered.connect(self.add_file_dialog)
        actions_edit[1].triggered.connect(self.preview_selected)
        actions_edit[2].triggered.connect(self.start_in_vault_edit)
        actions_edit[3].triggered.connect(self.delete_selected)
        actions_edit[4].triggered.connect(self.export_selected)
        actions_edit[5].triggered.connect(self.export_all)
        for a in actions_edit:
            edit_menu.addAction(a)

        # Hilfe-Menü
        help_menu = QMenu("Hilfe", self)
        about_action = QAction(f"Über {edition} {version_year}", self)
        about_action.triggered.connect(self.show_about_dialog)
        help_menu.addAction(about_action)

        # Menüs hinzufügen
        menubar.addMenu(file_menu)
        menubar.addMenu(edit_menu)
        menubar.addMenu(help_menu)
        
        self.layout.setMenuBar(menubar)

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
            empty = menu.addAction("Keine kürzlichen Container gefunden")
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
        if path and os.path.exists(path):
            self.container_path = path
            self.container_label.setText(path)
            self.open_container()
        else:
            QMessageBox.warning(self, "Fehler", "Container existiert nicht mehr.")


    def change_container_password_dialog(self):
            """Show password change dialog for current container"""
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
        self.container_label.setText(path or "")
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

            def _swap():
                self.setStyleSheet(build_stylesheet(theme_name, accent, density))

            fade_theme_swap(_swap, theme_name)
            print(f"[SETTINGS] Theme '{theme_name}' angewendet "
                  f"(Akzent='{accent}', Dichte='{density}')")
        except Exception as e:
            print(f"[SETTINGS] Theme-Fehler: {e}")

    def apply_list_settings(self, settings):
        """Dateilisten-Ansicht (Liste/Raster, Sortierung) sofort anwenden."""
        try:
            grid = settings.get("list_view_mode", "list") == "grid"
            sort_mode = settings.get("list_sort", "Keine")

            # Vorsicht: Sortierung und Drag&Drop-Reorder (InternalMove)
            # schliessen sich gegenseitig aus -> nur "Name" sortiert.
            self.file_list.setViewMode(
                QListView.ViewMode.IconMode if grid
                else QListView.ViewMode.ListMode)
            self.file_list.setSortingEnabled(not grid and sort_mode == "Name")

            if grid:
                self.file_list.setIconSize(QSize(40, 40))
                self.file_list.setGridSize(QSize(150, 78))
                self.file_list.setResizeMode(QListView.ResizeMode.Adjust)
                self.file_list.setWrapping(True)
                self.file_list.setSpacing(10)
                self.file_list.setUniformItemSizes(True)
                self.file_list.setMovement(QListView.Movement.Free)
            else:
                self.file_list.setIconSize(QSize(16, 16))
                self.file_list.setGridSize(QSize())
                self.file_list.setWrapping(False)
                self.file_list.setSpacing(0)
                self.file_list.setUniformItemSizes(False)

            self._grid_mode = grid
            print(f"[SETTINGS] Listen-Ansicht: {'Raster' if grid else 'Liste'}, "
                  f"Sortierung: {sort_mode}")
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
            self.update_container_path(path)
            if creating:
                self.create_container()
            else:
                self.open_container()

    # ------------------ In-Tresor-Bearbeitung: Helfer ------------------
    def _persist_meta(self):
        """Schreibt self.meta als neuen Meta-Blob ans Container-Ende."""
        if not self.container_path or not self.master_key:
            return
        with open(self.container_path, "rb+") as fh:
            fh.seek(-META_LEN_SIZE, os.SEEK_END)
            meta_len_bytes = fh.read(META_LEN_SIZE)
            if len(meta_len_bytes) != META_LEN_SIZE:
                raise ValueError("Meta-Länge konnte nicht gelesen werden.")
            meta_len = struct.unpack("<Q", meta_len_bytes)[0]
            meta_pos = os.path.getsize(self.container_path) - META_LEN_SIZE - meta_len
            fh.truncate(meta_pos)
            fh.seek(0, os.SEEK_END)
            blob = encrypt_meta(self.meta, self.master_key)
            fh.write(blob)
            fh.write(struct.pack("<Q", len(blob)))

    def _record_container_opened(self):
        """Protokolliert den letzten Öffnungszeitpunkt des Tresors."""
        try:
            meta = dict(self.meta)
            meta["opened"] = int(time.time())
            meta["app_version"] = f"{edition} {version}"
            self.meta = meta
            self._persist_meta()
        except Exception as e:
            self.append_log(f"Opened-Zeitstempel konnte nicht gespeichert werden: {e}")

    def open_container_with_password(self, container_path: str, password: str):
        """Öffnet einen bestehenden Container mit dem angegebenen Passwort"""

        # Use provided path and password
        self.container_path = container_path
        pwd = password

        try:
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "r+b") as fh:
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
            self._record_container_opened()
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
            self.file_list.setEnabled(True)
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
                return
        if not pwd:
            QMessageBox.warning(self, "Passwort fehlt", "Kein Passwort bereitgestellt.")
            return

        try:
            # ------------------------------------------------------------------
            # 4. Datei öffnen
            # ------------------------------------------------------------------
            with open(self.container_path, "r+b") as fh:
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
            self._record_container_opened()
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
            self.file_list.setEnabled(True)
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
        if self.container_path is None:
            QMessageBox.warning(self, "Fehler", "Wähle zuerst einen Dateipfad aus.")
            return
        # Prüfen, ob Container bereits existiert
        if os.path.exists(self.container_path):
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

        with open(self.container_path, "wb") as fh:
            write_header(fh, flags, salt)
            fh.write(meta_blob)
            fh.write(struct.pack("<Q", len(meta_blob)))

        self.master_key = master
        self.meta = meta
        self.flags = flags
        self.pwd = pwd
        self._auto_lock_rearm()

        self.status.setText("Container erstellt.")
        self.append_log("Container created.")

    def delete_container(self):
        if getattr(self, "_edit_session", None):
            QMessageBox.information(
                self, "Info", "Schließe zuerst die laufende In-Tresor-Bearbeitung ab."
            )
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

            # Fortschrittsdialog für das (ggf. lange) sichere Überschreiben
            self.progress = QProgressDialog(
                f"Vernichte Tresor mit '{method}'...", None, 0, 100, self
            )
            self.progress.setWindowTitle(f"ANCORATE {edition}")
            self.progress.setValue(0)
            self.progress.show()

            # 3. Physisches Überschreiben (Die gesamte Datei, aber den
            #    Header überspringen, damit der Tresor lesbar bleibt, falls
            #    der Vorgang unterbrochen wird)
            try:
                file_size = os.path.getsize(c_path)
                with open(c_path, "rb+") as fh:
                    # Header überspringen, um Container im Notfall noch lesen zu können
                    data_offset = HEADER_LEN
                    data_length = file_size - data_offset
                    if data_length > 0:
                        self._secure_overwrite(fh, data_offset, data_length)
            finally:
                try:
                    self.progress.close()
                except Exception:
                    pass
                self.progress = None

            # 4. Datei vom Dateisystem entfernen
            os.remove(c_path)

            # 5. UI Aufräumen
            self.update_container_path()

            self.meta = {"files": []}
            # Passwort-Änderungs-Zustandsvariablen
            self.changing_password = False
            self.password_change_in_progress = False
            self.rekey_temp_backup = None

            self.refresh_list()
            self.append_log(f"Tresor mit {method} erfolgreich vernichtet.")

            QMessageBox.information(
                self, "Erfolg", f"Der Tresor wurde mit {method} sicher gelöscht."
            )

        except Exception as e:
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
        # Attempt to zero sensitive key material from memory
        if self.master_key is not None:
            _secure_zero_bytes(self.master_key)
        self.master_key = None
        self.meta = {"files": []}
        # Passwort-Änderungs-Zustandsvariablen
        self.changing_password = False
        self.password_change_in_progress = False
        self.rekey_temp_backup = None
        self.flags = 0
        self.keyfile_bytes = None
        self.stop_event = None
        self.progress = None
        self.exporting = False
        self._preview_cache.clear()
        self._preview_cache_bytes = 0
        self.file_list.clear()
        self.file_list.setEnabled(False)
        self.search.clear()
        self.searchbar_content = ""
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
            self.container_path, files, v2, self.flags, stop_event=add_stop_event
        )

        thread = QThread()
        worker.moveToThread(thread)

        # Verbindung für Fortschritt und Fehler
        worker.progress.connect(self._on_progress)
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))

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
        self.progress.canceled.connect(lambda ev=add_stop_event: ev.set())
        self.progress.setValue(0)
        self.progress.show()

        # Erfolg‑Benachrichtigung
        def show_success():
            text = (
                f"{count} Dateien hinzugefügt." if count > 1 else "Datei hinzugefügt."
            )
            notifier.show("Verschlüsselung abgeschlossen ✅", text)

        worker.finished.connect(show_success)
        worker.finished.connect(self.progress.close)

        thread.started.connect(worker.run)
        thread.start()

    # ------------------ Datei exportieren ------------------
    def _selected_meta_indexes(self) -> list[int]:
        indexes = []
        for item in self.file_list.selectedItems():
            data = item.data(Qt.ItemDataRole.UserRole)
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
            save, _ = QFileDialog.getSaveFileName(self, "Speichere Datei", entry["name"])
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

        data = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(data, int):
            return data

        # Fallback: Text parsen (Name vor "—")
        try:
            txt = item.text()
            name = txt.split(" — ", 1)[0].strip()
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
            self._preview_cache_put(key, data, info_obj)
            show_preview(self, entry.get("name", "Datei"), data, info_obj)

        worker.finished.connect(_done)
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    # ------------------ In-Tresor-Bearbeitung (externer Editor) ------------------
    def start_in_vault_edit(self, *_args):
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
        except OSError as e:
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

        dlg = EditInVaultDialog(self, entry.get("name", "datei"))
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
        if not self._secure_purge_file(tmp_path):
            self._discard_edit_tmp(tmp_path)
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
        self.exporting = False
        if paths:
            self.append_log(f"Export fertig: {len(paths)} Datei(en)")
            QMessageBox.information(
                self,
                "Export fertig",
                f"{len(paths)} Datei(en) wurden exportiert.",
            )
        else:
            QMessageBox.information(self, "Export fertig", "Keine Dateien exportiert.")

    def _secure_overwrite(self, file_handle, offset, length):
        """Überschreibt Daten physisch – jetzt inklusive Vaporizer 1 Modus."""
        method = self.data.get("deletion_method", "Standard")

        # Durchgänge festlegen

        if "Shatterer Ultra" in method:
            passes = 300
        elif "Furnace Max" in method:
            passes = 200
        elif "Vaporizer 1" in method:
            passes = 100
        elif "Gutmann (35x)" in method:
            passes = 35
        elif "DoD 5220.22-M (3x)" in method:
            passes = 3
        else:
            passes = 1

        total_work = length * passes
        total_written = 0
        chunks_since_events = 0

        for i in range(passes):
            file_handle.seek(offset)
            bytes_left = length
            chunk_size = 1024 * 1024  # 1MB Chunks

            while bytes_left > 0:
                current_chunk = min(bytes_left, chunk_size)
                # Kryptographischer Zufall
                file_handle.write(secrets.token_bytes(current_chunk))
                bytes_left -= current_chunk

                # Fortschritt berechnen
                total_written += current_chunk
                chunks_since_events += 1
                if hasattr(self, "progress") and self.progress:
                    prog = int((total_written / total_work) * 100)
                    self.progress.setValue(prog)

            # Puffer erzwingen
            file_handle.flush()
            os.fsync(file_handle.fileno())

    def delete_selected(self):
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
        f_offset = target["offset"]
        f_length = target["length"]
        f_name = target["name"]

        temp_path = None
        try:
            import tempfile as _tf
            container_dir = os.path.dirname(os.path.abspath(self.container_path)) or os.curdir

            # Securely overwrite the blob data before rebuilding the container
            method = self.data.get("deletion_method", "Standard")
            self.progress = QProgressDialog(
                f"Vernichte Datei mit '{method}'...", "Abbrechen", 0, 100, self
            )
            self.progress.setWindowTitle(f"ANCORATE {edition}")
            self.progress.setValue(0)
            self.progress.show()

            try:
                with open(self.container_path, "rb+") as fh:
                    self._secure_overwrite(fh, f_offset, f_length)
            except Exception as ow_err:
                self.append_log(f"Warnung: Sicheres Überschreiben fehlgeschlagen: {ow_err}")

            try:
                self.progress.close()
            except Exception:
                pass

            with _tf.NamedTemporaryFile(delete=False, dir=container_dir) as tmp:
                temp_path = tmp.name

            with open(self.container_path, "rb") as src:
                header = src.read(HEADER_LEN)

                with open(temp_path, "wb") as dst:
                    dst.write(header)

                    remaining = f_offset - HEADER_LEN
                    while remaining > 0:
                        chunk = src.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise IOError("Unexpected EOF before deleted region")
                        dst.write(chunk)
                        remaining -= len(chunk)

                    src.seek(f_offset + f_length)
                    data_end = os.path.getsize(self.container_path) - META_LEN_SIZE
                    after_deleted = data_end - (f_offset + f_length)
                    while after_deleted > 0:
                        chunk = src.read(min(1024 * 1024, after_deleted))
                        if not chunk:
                            raise IOError("Unexpected EOF after deleted region")
                        dst.write(chunk)
                        after_deleted -= len(chunk)

                self.meta["files"].pop(int(idx))
                for f in self.meta["files"]:
                    if f["offset"] > f_offset:
                        f["offset"] -= f_length

                new_meta_blob = encrypt_meta(self.meta, self.master_key)
                with open(temp_path, "ab") as dst:
                    dst.write(new_meta_blob)
                    dst.write(struct.pack("<Q", len(new_meta_blob)))

            os.replace(temp_path, self.container_path)
            temp_path = None

            self.append_log(f"Erfolgreich vernichtet: {f_name}")
            self.refresh_list()
            QMessageBox.information(
                self, "Erfolg", f"Die Datei wurde unwiderruflich gelöscht."
            )

        except Exception as e:
            self.append_log(f"FEHLER beim Löschen: {str(e)}")
            QMessageBox.critical(
                self, "Kritischer Fehler", f"Löschvorgang abgebrochen: {e}"
            )
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

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
        self.append_log("Added files: " + ", ".join(added))
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
        self.refresh_list()

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

        # Fehler anzeigen und loggen
        error_msg = error if isinstance(error, str) else str(error)
        if not error_msg:
            error_msg = repr(error)
        QMessageBox.critical(self, "Fehler", error_msg)
        self.append_log(f"Fehler: {error_msg}")

    def _export_finished(self, path, thread, worker):
        thread.quit()
        thread.wait()
        worker.deleteLater()
        thread.deleteLater()
        self.exporting = False
        QMessageBox.information(self, "Export fertig", f"Datei gespeichert: {path}")
        self.append_log(f"Export fertig: {path}")

    def append_log(self, txt):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {txt}")
        self.status.setText(txt)

    def closeEvent(self, event):
        self._end_edit_session()

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

    # ------------------ Dateiliste aktualisieren ------------------
    def _detail_line(self, name, size_text, ent, show_size, show_date):
        """Detailzeile gemäß Sichtbarkeits-Einstellungen (Größe/Datum)."""
        parts = [name]
        if show_size:
            parts.append(size_text)
        if show_date:
            mtime = ent.get("mtime")
            if mtime:
                parts.append(time.strftime("%Y-%m-%d %H:%M", time.localtime(mtime)))
        return " — ".join(parts)

    def _grid_icon(self):
        if getattr(self, "_grid_icon_impl", None) is None:
            self._grid_icon_impl = self.style().standardIcon(
                QStyle.StandardPixmap.SP_FileIcon)
        return self._grid_icon_impl

    def refresh_list(self, searching: bool = False, intelligence_results=None):
        if getattr(self.file_list, "isEnabled", lambda: True)():
            self.file_list.clear()
            files = self.meta.get("files", [])
            s = self.data if isinstance(self.data, dict) else {}
            show_size = bool(s.get("list_show_size", True))
            show_date = bool(s.get("list_show_date", True))
            grid = s.get("list_view_mode", "list") == "grid"

            # Sortierung (nur im Listenmodus; Drag&Drop-Reorder verträgt sich
            # nicht mit aktivem Sortieren)
            self.file_list.setSortingEnabled(
                not grid and s.get("list_sort", "Keine") == "Name")

            result_mapping = {}
            if intelligence_results:
                for result in intelligence_results:
                    fname = result.get("filename")
                    if fname:
                        result_mapping[fname] = result
                    docname = result.get("document_name")
                    if docname:
                        result_mapping[docname] = result

            for idx, ent in enumerate(files):
                name = ent.get("name", "<unnamed>")
                size = ent.get("size", 0)

                if size < 1024:
                    size_text = f"{size} B"
                elif size < 1024**2:
                    size_text = f"{size / 1024:.1f} KB"
                elif size < 1024**3:
                    size_text = f"{size / 1024**2:.2f} MB"
                elif size < 1024**4:
                    size_text = f"{size / 1024**3:.2f} GB"
                else:
                    size_text = f"{size / 1024**4:.2f} TB"

                if intelligence_results is not None:
                    result = result_mapping.get(name)
                    if not result:
                        continue
                    display_text = (
                        f"{name} — {size_text} — KI {result['score']:.2f}\n"
                        f"{result['snippet']}"
                    )
                elif self.search.text() and searching:
                    if self.search.text().lower() not in name.lower():
                        continue
                    display_text = self._detail_line(
                        name, size_text, ent, show_size, show_date)
                elif grid:
                    # Raster-Modus: kompakte Kachel (nur Name, mittig)
                    display_text = name
                else:
                    display_text = self._detail_line(
                        name, size_text, ent, show_size, show_date)

                item = QListWidgetItem(display_text)
                if grid:
                    item.setIcon(self._grid_icon())
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                item.setData(Qt.ItemDataRole.UserRole, idx)
                self.file_list.addItem(item)


