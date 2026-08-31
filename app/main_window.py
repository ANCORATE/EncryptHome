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

        self.file_list.itemDoubleClicked.connect(self.preview_selected)

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
        
        # Auto-Lock Timeout (5 Minuten)
        self.timeout_ms = 300000

        # ---- Automatisch ständig aktualisieren ----
        self.timer = QTimer(self)
        self.timer.setInterval(10000)  # Alle 10 Sekunden (Performance)
        self.timer.timeout.connect(self._simple_cleanup)
        self.timer.start()
        
        self.apply_settings()  # Initial anwenden
        
        # ---- Menüleiste hinzufügen ----
        self.add_menubar()
        
        # ---- File Watcher für sofortige Updates ----
        self.settings_watcher = QFileSystemWatcher([SETTINGS_FILE], self)
        self.settings_watcher.fileChanged.connect(self.on_settings_changed)
        print("[SETTINGS] File Watcher aktiviert für sofortige Updates")
    
    
    def _simple_cleanup(self):
        """Einfache Cleanup Funktion"""
        try:
            import gc
            gc.collect()
            print("[CLEANUP] Simple Cleanup durchgeführt")
        except Exception as e:
            print(f"[CLEANUP] Fehler: {e}")

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
                data.get("version", version), version
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
        actions_file = [
            QAction("Neuer Tresor", self),
            QAction("Tresor öffnen", self),
            QAction("Zuletzt verwendete Tresore", self),
            QAction("Tresorpasswort ändern", self),
            QAction("Tresor schließen", self),
            QAction("Tresor löschen", self),
            None,  # Separator
            QAction("Einstellungen", self),
        ]
        actions_file[1].triggered.connect(lambda: self.choose_container(1))
        actions_file[0].triggered.connect(lambda: self.choose_container(2))
        actions_file[2].triggered.connect(self.show_recent_containers)
        actions_file[3].triggered.connect(self.change_container_password_dialog)
        actions_file[4].triggered.connect(self.close_container)
        actions_file[5].triggered.connect(self.delete_container)
        actions_file[7].triggered.connect(lambda: self.show_settings_dialog())
        for a in actions_file:
            if a is None:
                file_menu.addSeparator()
            else:
                file_menu.addAction(a)

        # Bearbeiten-Menü
        edit_menu = QMenu("Bearbeiten", self)
        actions_edit = [
            QAction("Datei(en) hinzufügen", self),
            QAction("Dateivorschau starten", self),
            QAction("Datei löschen", self),
            QAction("Datei exportieren", self),
            QAction("Alles exportieren", self),
        ]
        actions_edit[0].triggered.connect(self.add_file_dialog)
        actions_edit[1].triggered.connect(self.preview_selected)
        actions_edit[2].triggered.connect(self.delete_selected)
        actions_edit[3].triggered.connect(self.export_selected)
        actions_edit[4].triggered.connect(self.export_all)
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
        """Show recent containers dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Zuletzt verwendete Container")
        dialog.setWindowIcon(get_app_icon())
        dialog.setFixedSize(600, 400)
        dialog.setModal(True)
        
        layout = QVBoxLayout(dialog)
        
        # Recent containers list
        list_widget = QListWidget()
        containers = load_recent_containers()
        
        for container in containers:
            item = QListWidgetItem(f"📁 {container['name']}")
            item.setData(Qt.ItemDataRole.UserRole, container["path"])
            item.setToolTip(container["path"])
            
            # Format last accessed time
            last_accessed = container.get("last_accessed", 0)
            if last_accessed:
                time_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(last_accessed))
                item.setText(f"📁 {container['name']} - {time_str}")
            
            list_widget.addItem(item)
        
        if not containers:
            list_widget.addItem(QListWidgetItem("Keine kürzlichen Container gefunden"))
        
        layout.addWidget(list_widget)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        open_btn = QPushButton("Öffnen")
        open_btn.setObjectName("primary")
        clear_btn = QPushButton("Liste löschen")
        clear_btn.setObjectName("danger")
        cancel_btn = QPushButton("Abbrechen")
        cancel_btn.setObjectName("secondary")
        
        btn_layout.addWidget(open_btn)
        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(cancel_btn)
        layout.addLayout(btn_layout)
        
        # Button handlers
        def open_selected():
            selected_items = list_widget.selectedItems()
            if selected_items:
                container_path = selected_items[0].data(Qt.ItemDataRole.UserRole)
                if container_path and os.path.exists(container_path):
                    self.container_path = container_path
                    self.container_label.setText(container_path)
                    self.open_container()
                    dialog.accept()
                else:
                    QMessageBox.warning(dialog, "Fehler", "Container existiert nicht mehr.")
        
        def clear_recent():
            if QMessageBox.question(
                dialog, "Bestätigen", 
                "Möchten Sie die Liste der kürzlich genutzten Container wirklich leeren?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            ) == QMessageBox.StandardButton.Yes:
                save_recent_containers([])
                list_widget.clear()
                list_widget.addItem(QListWidgetItem("Liste geleert"))
        
        def reject_dialog():
            dialog.reject()
        
        open_btn.clicked.connect(open_selected)
        clear_btn.clicked.connect(clear_recent)
        cancel_btn.clicked.connect(reject_dialog)
        
        # Double-click to open
        list_widget.itemDoubleClicked.connect(lambda item: open_selected())
        
        dialog.exec()


    def change_container_password_dialog(self):
            """Show password change dialog for current container"""
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
        if not self.meta.get("files", ""):
            self.container_path = path
            self.container_label.setText(path or "")
            if path is None:
                self.status.setText("Tresor-Pfad zurückgesetzt")
            else:
                self.status.setText(f"Tresor-Pfad gesetzt: {path}")

    # ------------------------------------------------------

    def apply_settings(self):
        try:
            s = load_settings()
            
            # 1. Theme sofort anwenden
            self.apply_theme(s.get("theme", "Standard-dark"))
            
            # 2. Shortcuts aktualisieren
            self.apply_shortcuts(s)
            
            # 3. Verhaltens-Einstellungen aktualisieren
            self.apply_behavior_settings(s)
            
        except Exception as e:
            print("[SETTINGS] Fehler beim Anwenden der Einstellungen:", e)
    
    def apply_theme(self, theme_name):
        """Theme sofort ohne Neustart anwenden"""
        try:
            base_path = os.path.dirname(os.path.abspath(sys.argv[0]))
            THEMES = {
                "Standard-dark": "utilities/themes/standard-dark.css",
                "Standard-White": "utilities/themes/standard-white.css",
            }
            
            css_file = THEMES.get(theme_name, "utilities/themes/standard-dark.css")
            css_path = os.path.join(base_path, css_file)
            
            if os.path.exists(css_path):
                with open(css_path, "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
                print(f"[SETTINGS] Theme '{theme_name}' angewendet")
            else:
                print(f"[SETTINGS] Theme-Datei nicht gefunden: {css_path}")
        except Exception as e:
            print(f"[SETTINGS] Theme-Fehler: {e}")
    
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
            print("[SETTINGS] Verhaltens-Einstellungen aktualisiert")
        except Exception as e:
            print(f"[SETTINGS] Verhaltens-Fehler: {e}")
    
    def on_settings_changed(self, path):
        """Wird aufgerufen wenn settings.json geändert wird"""
        try:
            print(f"[SETTINGS] Settings-Datei geändert: {path}")
            # Kleine Verzögerung um sicherzustellen dass Datei komplett geschrieben ist
            QTimer.singleShot(100, self.apply_settings)
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

    def open_container_with_password(self, container_path: str, password: str):
        """Öffnet einen bestehenden Container mit dem angegebenen Passwort"""
        
        # Use provided path and password
        self.container_path = container_path
        pwd = password

        # Add to recent containers on successful open
        add_recent_container(self.container_path)

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

                # 4b. Master-Key ableiten
                master = derive_master_key(
                    pwd,
                    salt,
                    bool(flags & FLAG_DEVICE),
                    load_device_key() if (flags & FLAG_DEVICE) else None,
                )
                if master is None:
                    raise ValueError("Master-Key konnte nicht abgeleitet werden.")

                # 4c. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4d. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Nach dem Schließen der Datei: Meta entschlüsseln
            # ------------------------------------------------------------------
            meta = decrypt_meta(meta_blob, master)
            if meta is None:
                raise ValueError("Metadaten konnten nicht entschlüsselt werden.")

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags

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
            self.file_list.enabled = True
            self.refresh_list()

        except Exception as e:
            error_msg = str(e)
            raise e

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

        # Add to recent containers on successful open
        add_recent_container(self.container_path)

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

                # 4b. Master-Key ableiten
                master = derive_master_key(
                    pwd,
                    salt,
                    bool(flags & FLAG_DEVICE),
                    load_device_key() if (flags & FLAG_DEVICE) else None,
                )
                if master is None:
                    raise ValueError("Master-Key konnte nicht abgeleitet werden.")

                # 4c. Meta-Länge aus Dateiende lesen
                file_size = os.path.getsize(self.container_path)
                fh.seek(file_size - META_LEN_SIZE, os.SEEK_SET)

                meta_len_bytes = fh.read(META_LEN_SIZE)
                if len(meta_len_bytes) != META_LEN_SIZE:
                    raise ValueError("Meta-Länge konnte nicht gelesen werden.")

                meta_len = struct.unpack("<Q", meta_len_bytes)[0]
                if meta_len <= 0:
                    raise ValueError("Meta-Länge ungültig.")

                # 4d. Meta-Blob lesen
                meta_pos = file_size - META_LEN_SIZE - meta_len
                fh.seek(meta_pos, os.SEEK_SET)

                meta_blob = fh.read(meta_len)
                if not meta_blob:
                    raise ValueError("Meta-Blob konnte nicht gelesen werden.")

            # ------------------------------------------------------------------
            # 5. Nach dem Schließen der Datei: Meta entschlüsseln
            # ------------------------------------------------------------------
            meta = decrypt_meta(meta_blob, master)
            if meta is None:
                raise ValueError("Metadaten konnten nicht entschlüsselt werden.")

            # ------------------------------------------------------------------
            # 6. Werte speichern
            # ------------------------------------------------------------------
            self.pwd = pwd
            self.master_key = master
            self.meta = meta
            self.flags = flags

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
            self.file_list.enabled = True
            self.refresh_list()

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

        self.status.setText("Container erstellt.")
        self.append_log("Container created.")

    def delete_container(self):
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

            # 3. Physisches Überschreiben (Die gesamte Datei)
            file_size = os.path.getsize(c_path)
            with open(c_path, "rb+") as fh:
                self._secure_overwrite(fh, 0, file_size)

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

    # ------------------ registrierten Key laden ------------------
    def load_device_key(self):
        if not os.path.exists(CONFIG_FILE):
            return None
        try:
            with open(CONFIG_FILE, "r") as f:
                js = json.load(f)
            v = js.get("device_key_hex", "")
            if not v:
                return None
            return bytes.fromhex(v)
        except Exception:
            return None

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
        self.file_list.enabled = False
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

        # Frisches Stop‑Event für diesen Add‑Vorgang,
        # damit ein vorheriger Abbruch (preview/export) neue Adds nicht blockiert.
        self.stop_event = threading.Event()

        # Master‑Key ggf. auf 32 Byte auffüllen
        v2 = self.master_key
        if len(v2) not in (16, 24, 32):
            v2 = (v2 + b"\x00" * 32)[:32]

        worker = AddWorker(
            self.container_path, files, v2, self.flags, stop_event=self.stop_event
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
        self.progress.canceled.connect(self.cancel_current)
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
    def queueing(self):
        while self.exporting:
            time.sleep(0.2)

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
        self.stop_event = threading.Event()
        worker = PreviewDecryptWorker(
            self.container_path,
            entry,
            self.master_key,
            stop_event=self.stop_event,
            max_bytes=self._preview_max_file_bytes,
        )
        thread = QThread()
        worker.moveToThread(thread)

        # UI: Fortschrittsdialog
        self.progress = QProgressDialog(
            "Nehme Änderungen am Tresor vor...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(self.cancel_current)
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
        self.stop_event = threading.Event()
        entry_copy = dict(entry)
        entry_copy["__save_to"] = save_to
        worker = ExportWorker(
            self.container_path, entry_copy, self.master_key, stop_event=self.stop_event
        )
        thread = QThread()
        worker.moveToThread(thread)
        worker.finished.connect(lambda p: self._export_finished(p, thread, worker))
        worker.error.connect(lambda e: self._worker_error(e, thread, worker))
        thread.started.connect(worker.run)
        thread.start()

    def _start_batch_export(self, entries: list[dict], target_dir: str):
        self.exporting = True
        self.stop_event = threading.Event()
        worker = ExportBatchWorker(
            self.container_path,
            entries,
            self.master_key,
            target_dir,
            stop_event=self.stop_event,
        )
        thread = QThread()
        worker.moveToThread(thread)

        self.progress = QProgressDialog(
            "Exportiere Dateien...", "Abbrechen", 0, 100, self
        )
        self.progress.setWindowTitle(f"ANCORATE {edition}")
        self.progress.canceled.connect(self.cancel_current)
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
                if hasattr(self, "progress") and self.progress:
                    prog = int((total_written / total_work) * 100)
                    self.progress.setValue(prog)

                QApplication.processEvents()  # UI am Leben halten

            # Puffer erzwingen
            file_handle.flush()
            os.fsync(file_handle.fileno())

    def delete_selected(self):
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

        # 1. Datei-Metadaten abgreifen
        target = self.meta["files"][int(idx)]
        f_offset = target["offset"]
        f_length = target["length"]
        f_name = target["name"]

        try:
            with open(self.container_path, "rb+") as fh:
                # --- SCHRITT A: DATEN ÜBERSCHREIBEN ---
                print("starting")
                self._secure_overwrite(fh, f_offset, f_length)

                # --- SCHRITT B: CONTAINER KOMPAKTIEREN ---
                print("squeezing")
                fh.seek(-8, os.SEEK_END)  # 8 = META_LEN_SIZE
                old_meta_len = struct.unpack("<Q", fh.read(8))[0]
                total_size = os.path.getsize(self.container_path)

                data_end = total_size - old_meta_len - 8
                next_data_start = f_offset + f_length
                bytes_to_move = data_end - next_data_start

                if bytes_to_move > 0:
                    self.append_log("Entferne Überreste...")
                    fh.seek(next_data_start)
                    chunk = fh.read(bytes_to_move)
                    fh.seek(f_offset)
                    fh.write(chunk)

                # --- SCHRITT C: METADATEN AKTUALISIEREN ---
                print("editing meta")
                # Datei aus Liste löschen
                self.meta["files"].pop(int(idx))

                # Offsets aller nachfolgenden Dateien korrigieren
                for f in self.meta["files"]:
                    if f["offset"] > f_offset:
                        f["offset"] -= f_length

                # Container am Ende kürzen
                new_size = f_offset + bytes_to_move
                fh.truncate(new_size)

                # Neue Metadaten ans Ende hängen
                fh.seek(0, os.SEEK_END)
                new_meta_blob = encrypt_meta(self.meta, self.master_key)
                fh.write(new_meta_blob)
                fh.write(struct.pack("<Q", len(new_meta_blob)))

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

    def cancel_current(self):
        if hasattr(self, "stop_event") and self.stop_event:
            self.stop_event.set()
            self.append_log("Abbruch angefordert.")

    def append_log(self, txt):
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {txt}")
        self.status.setText(txt)

    def closeEvent(self, event):
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

        # Cleanup VaultBridge USB monitoring
        if hasattr(self, 'usb_detector') and self.usb_detector:
            try:
                self.usb_detector.stop_monitoring()
                print("[VAULTBRIDGE] USB monitoring stopped")
            except Exception as e:
                print(f"[VAULTBRIDGE] Error stopping USB monitoring: {e}")

        event.accept()

    # ------------------ Worker Callbacks ------------------
    def _on_progress(self, v):
        """Aktualisiert den Fortschrittsbalken."""
        try:
            # 'self.progress' in __init__ initialisieren, damit es immer existiert
            self.progress.setValue(v)
        except Exception as e:
            print(f"Fehler beim Update des Progressbars: {e}")

    def _on_finished(self):
        """Wird aufgerufen, wenn der Worker fertig ist."""
        self.progress.setValue(0)
        self.append_log("Vorgang abgeschlossen.")
        self.refresh_list()

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
    def refresh_list(self, searching: bool = False, intelligence_results=None):
        if getattr(self.file_list, "isEnabled", lambda: True)():
            self.file_list.clear()
            files = self.meta.get("files", [])
            result_mapping = {}
            if intelligence_results:
                for result in intelligence_results:
                    if result.get("filename"):
                        result_mapping[result["filename"]] = result
                    result_mapping[result["document_name"]] = result

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
                elif size >= 1024**4:
                    size_text = f"{size / 1024**4:.2f} TB"
                else:
                    size_text = f"{size / 1024**5:.2f} PB"

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
                    display_text = f"{name} — {size_text}"
                else:
                    display_text = f"{name} — {size_text}"

                item = QListWidgetItem(display_text)
                item.setData(Qt.ItemDataRole.UserRole, idx)
                self.file_list.addItem(item)


