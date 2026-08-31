import json
import os
import shutil
import sys
import tempfile
import platform

import requests
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

from .sos_delete import SaltScannerUI

# --- Setup Pfade & Konstanten ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# VUpdater Import versuchen
try:
    from updater import EncryptHomeUpdater
except ImportError:
    EncryptHomeUpdater = None

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ancorate")
os.makedirs(CONFIG_DIR, exist_ok=True)
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")

VERSION_YEAR = "26"
VERSION_FULL = "26.2"


def get_app_icon():
    """
    Lädt das passende Icon-Format für die aktuelle Plattform.
    """
    import platform
    system = platform.system()
    
    # Verschiedene Icon-Formate versuchen
    icon_paths = []
    
    if system == "Windows":
        icon_paths = [
            os.path.join(BASE_DIR, "icon.ico"),
            os.path.join(BASE_DIR, "icon.png"),
        ]
    else:
        icon_paths = [
            os.path.join(BASE_DIR, "icon.png"),
            os.path.join(BASE_DIR, "icon_64x64.png"),
            os.path.join(BASE_DIR, "icon_48x48.png"),
            os.path.join(BASE_DIR, "icon_32x32.png"),
        ]
    
    # Erstes existierendes Icon zurückgeben
    for path in icon_paths:
        if os.path.exists(path):
            return QIcon(path)
    
    # Fallback: Leeres Icon
    return QIcon()
UPDATE_URL = "https://ancorate.github.io/latest/EncryptHome/latest.json"

DEFAULT_SETTINGS = {
    # --- Hotkeys (alt Defaults) ---
    "o_seq": "Ctrl+E",
    "del_seq": "Del",
    "add_seq": "Ctrl++",
    "vault_o_seq": "Ctrl+O",
    "o_all_seq": "Alt+E",
    "search_seq": "Return",
    "crea_vault_seq": "Ctrl+N",
    "del_vault_seq": "Alt+Del",
    # --- Design ---
    "theme": "Standard-dark",
    # --- Updater (alte Defaults) ---
    "update_url": UPDATE_URL,
    # --- NEU: System & Verhalten ---
    "confirm_exit": True,
    "del_source_added": False,
    # --- NEU: Sicherheit & Pfade ---
    "deletion_method": "Standard",  # Standard, DoD, Gutmann
}

# ------------------ Settings laden / speichern ------------------

VALID_THEMES = ("Standard-dark", "Standard-White")


def load_settings():
    path = SETTINGS_FILE
    if not os.path.exists(path):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return DEFAULT_SETTINGS.copy()

    # Fehlende Keys ergänzen
    for k, v in DEFAULT_SETTINGS.items():
        if k not in data:
            data[k] = v

    # Alte/entfernte Theme-Werte sicher auf einen gültigen migrieren
    if data.get("theme") not in VALID_THEMES:
        data["theme"] = DEFAULT_SETTINGS["theme"]
    return data


def save_settings(settings: dict):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4)
    except Exception as e:
        print(f"Fehler beim Speichern: {e}")


# ------------------ Worker Thread für Changelog ------------------
class ChangelogWorker(QThread):
    """Lädt den Changelog im Hintergrund, damit die GUI nicht einfriert."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def run(self):
        try:
            from updater import validate_latest_json

            response = requests.get(UPDATE_URL, timeout=5)
            if response.status_code != 200:
                raise ConnectionError(f"HTTP {response.status_code}")
            data = validate_latest_json(response.json())
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))


# ------------------ Settings Dialog ------------------


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"ANCORATE EncryptHome {VERSION_YEAR} – Einstellungen")
        self.setWindowIcon(get_app_icon())
        self.resize(1100, 700)
        self.setMinimumSize(900, 500)  # Allow user to resize but not too small
        self.resize(1100, 700)
        self.data = load_settings()

        # UI initialisieren
        self.init_ui()

        # Changelog automatisch laden (im Hintergrund)
        self.start_changelog_fetch()

    def init_ui(self):
        # --- Hauptlayout ---
        self.main_layout = QHBoxLayout()
        self.setLayout(self.main_layout)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(15)

        # --- Linke Sidebar (Navigation) ---
        self.category_list = QListWidget()
        # Icons könnten hier optional hinzugefügt werden
        self.category_list.addItems([
            "Allgemein",
            "Kurzbefehle",
            "Design",
            "Updates",
        ])
        self.category_list.setFixedWidth(180)
        self.category_list.currentRowChanged.connect(self.display_category)

        # Styling für Sidebar
        self.category_list.setStyleSheet("""
            QListWidget { font-size: 14px; padding: 5px; }
            QListWidget::item { padding: 8px; }
        """)

        self.main_layout.addWidget(self.category_list)

        # --- Rechte Seite: Container & Buttons ---
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Stacked Widget für die Tabs
        self.stack = QStackedWidget()

        # Tabs erstellen
        self.create_general_tab()
        self.create_shortcuts_tab()
        self.create_design_tab()
        self.create_updates_tab()  # Neuer separater Tab

        right_layout.addWidget(self.stack, 1)  # 1 = Stretch factor

        # Trennlinie
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        right_layout.addWidget(line)

        # Buttons unten
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()  # Schiebt Buttons nach rechts

        save_btn = QPushButton("Speichern")
        save_btn.setObjectName("primary")
        save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        save_btn.clicked.connect(self.save)

        cancel_btn = QPushButton("Abbrechen")
        cancel_btn.setObjectName("secondary")
        cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)

        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(cancel_btn)
        right_layout.addLayout(btn_layout)

        self.main_layout.addWidget(right_container, 1)

        # Standardmäßig erste Kategorie wählen
        self.category_list.setCurrentRow(0)

    # ------------------ Tab Erstellung ------------------

    def create_general_tab(self):
        # widget = QWidget()
        # ScrollArea, falls das Fenster klein ist und der Inhalt lang wird
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(20)

        # --- Titel ---
        title = QLabel("Allgemeine Systemeinstellungen")
        title.setStyleSheet("font-weight: bold; font-size: 18px;")
        layout.addWidget(title)

        # --- Sektion 1: Programmverhalten (QGroupBox) ---
        group_behavior = QGroupBox("Verhalten")
        gb_layout = QVBoxLayout()

        self.cb_confirm_exit = QCheckBox("Bestätigung beim Beenden anfordern")
        self.cb_confirm_exit.setChecked(self.data.get("confirm_exit", True))
        self.cb_confirm_exit.stateChanged.connect(self._save_immediate)
        gb_layout.addWidget(self.cb_confirm_exit)

        self.cb_del_source_added = QCheckBox(
            "Originaldatei nach erfolgreicher Verschlüsselung automatisch löschen"
        )
        self.cb_del_source_added.setChecked(self.data.get("del_source_added", False))
        self.cb_del_source_added.stateChanged.connect(self._save_immediate)
        gb_layout.addWidget(self.cb_del_source_added)

        group_behavior.setLayout(gb_layout)
        layout.addWidget(group_behavior)

        # --- Sektion 2: Sicherheit & Datenschutz ---
        group_security = QGroupBox("Sicherheit")
        form_sec = QFormLayout()
        form_sec.setSpacing(10)

        self.combo_deletion = QComboBox()
        self.combo_deletion.addItems(
            [
                "Standard (Schnell)",
                "DoD 5220.22-M (3x)",
                "Gutmann (35x)",
                "ANCORATE Vaporizer 1 (100x)",
                "ANCORATE Furnace Max (200x, grosse Dateien)",
                "ANCORATE Shatterer Ultra (300x, ⚠️ Do not use with HDD!)",
            ]
        )

        # Aktuellen Wert setzen
        current_method = self.data.get("deletion_method", "Standard")
        index = self.combo_deletion.findText(
            current_method, Qt.MatchFlag.MatchStartsWith
        )
        if index >= 0:
            self.combo_deletion.setCurrentIndex(index)

        # --- ÄNDERUNG: SIGNAL ZUM SPEICHERN VERBINDEN ---
        self.combo_deletion.currentTextChanged.connect(self._save_deletion_method)
        # -----------------------------------------------

        lbl_del = QLabel("Sicheres Löschen:")
        lbl_del.setToolTip(
            "Methode zum unwiderruflichen Vernichten von Originaldateien."
        )
        form_sec.addRow(lbl_del, self.combo_deletion)

        group_security.setLayout(form_sec)
        layout.addWidget(group_security)

        # --- Sektion 4: Wartung ---
        group_maint = QGroupBox("Wartung")
        maint_layout = QHBoxLayout()
        maint_layout.setSpacing(12)  # optischer Abstand

        clear_cache_btn = QPushButton("Temporären Cache leeren")
        clear_cache_btn.setObjectName("secondary")
        clear_cache_btn.setIcon(QIcon.fromTheme("edit-clear"))
        clear_cache_btn.clicked.connect(self.clear_temp_cache)

        kill_btn = QPushButton("Anwendung sofort beenden")
        kill_btn.setObjectName("danger")
        kill_btn.setIcon(QIcon.fromTheme("system-restart"))
        kill_btn.clicked.connect(self.kill_app)

        delete_vaults_btn = QPushButton("Alle Tresore löschen")
        delete_vaults_btn.setObjectName("danger")
        delete_vaults_btn.setIcon(QIcon.fromTheme("edit-delete"))
        delete_vaults_btn.clicked.connect(self.open_salt_scanner)

        maint_layout.addWidget(clear_cache_btn)
        maint_layout.addWidget(kill_btn)
        maint_layout.addWidget(delete_vaults_btn)

        group_maint.setLayout(maint_layout)
        layout.addWidget(group_maint)

        # --- Footer: Systeminfo Button ---
        layout.addSpacing(10)
        about_btn = QPushButton(f"Informationen zu dieser Installation von EncryptHome")
        about_btn.setMinimumHeight(35)
        about_btn.clicked.connect(self.show_about_dialog)
        layout.addWidget(about_btn)

        layout.addStretch()

        # Widget in ScrollArea setzen
        scroll.setWidget(content_widget)

        self.stack.addWidget(scroll)

    def open_salt_scanner(self):
        self.salt_window = SaltScannerUI()
        self.salt_window.show()

    def kill_app(self):
        sys.exit(0)

    # Hilfsmethode für den Browse-Button
    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(
            self, "Zielordner wählen", self.path_input.text()
        )
        if folder:
            self.path_input.setText(folder)

    def create_shortcuts_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        title = QLabel("Tastaturkürzel")
        title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(title)
        layout.addSpacing(20)

        # Form Layout für saubere Ausrichtung
        form_layout = QFormLayout()
        form_layout.setSpacing(15)

        # Shortcuts
        self.add_input = QKeySequenceEdit()
        self.add_input.setKeySequence(QKeySequence(self.data["add_seq"]))
        self.add_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Datei(en) hinzufügen", self.add_input)

        self.create_vault_key_input = QKeySequenceEdit()
        self.create_vault_key_input.setKeySequence(
            QKeySequence(self.data["crea_vault_seq"])
        )
        self.create_vault_key_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Tresor erstellen:", self.create_vault_key_input)

        self.open_vault_key_input = QKeySequenceEdit()
        self.open_vault_key_input.setKeySequence(QKeySequence(self.data["vault_o_seq"]))
        self.open_vault_key_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Tresor öffnen:", self.open_vault_key_input)

        self.open_key_input = QKeySequenceEdit()
        self.open_key_input.setKeySequence(QKeySequence(self.data["o_seq"]))
        self.open_key_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Datei exportieren:", self.open_key_input)

        self.delete_key_input = QKeySequenceEdit()
        self.delete_key_input.setKeySequence(QKeySequence(self.data["del_seq"]))
        self.delete_key_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Datei löschen:", self.delete_key_input)

        self.del_vault_input = QKeySequenceEdit()
        self.del_vault_input.setKeySequence(QKeySequence(self.data["del_vault_seq"]))
        self.del_vault_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Tresor löschen", self.del_vault_input)

        self.export_all_input = QKeySequenceEdit()
        self.export_all_input.setKeySequence(
            QKeySequence(self.data.get("o_all_seq", ""))
        )
        self.export_all_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Alles exportieren", self.export_all_input)

        self.search_input = QKeySequenceEdit()
        self.search_input.setKeySequence(QKeySequence(self.data["search_seq"]))
        self.search_input.keySequenceChanged.connect(self._save_shortcuts)
        form_layout.addRow("Suchen:", self.search_input)

        layout.addLayout(form_layout)
        layout.addStretch()
        widget.setLayout(layout)
        self.stack.addWidget(widget)

    def create_design_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        title = QLabel("Design & Erscheinungsbild")
        title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(title)
        layout.addSpacing(20)

        lbl = QLabel("Wählen Sie ein Design-Theme:")
        layout.addWidget(lbl)

        self.theme_combo = QComboBox()
        self.theme_combo.addItems(
            [
                "Standard-dark",
                "Standard-White",
            ]
        )
        self.theme_combo.setCurrentText(self.data.get("theme", "Standard-dark"))
        self.theme_combo.currentTextChanged.connect(self._save_theme)
        layout.addWidget(self.theme_combo)

        layout.addStretch()
        widget.setLayout(layout)
        self.stack.addWidget(widget)

    def create_updates_tab(self):
        """Erstellt den separierten Update-Tab."""
        widget = QWidget()
        layout = QVBoxLayout()

        title = QLabel("Software-updates & -upgrades")
        title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(title)

        # Changelog Bereich
        self.changelog_group = QGroupBox(f"Änderungen in Version {VERSION_FULL}")
        group_layout = QVBoxLayout()

        self.changelog_text = QTextEdit()
        self.changelog_text.setReadOnly(True)
        self.changelog_text.setPlaceholderText("Lade Informationen...")
        group_layout.addWidget(self.changelog_text)

        self.changelog_group.setLayout(group_layout)
        layout.addWidget(self.changelog_group, 1)  # Expandiert

        self.update_status_label = QLabel("Update-Status: noch nicht geprüft")
        self.update_status_label.setObjectName("ReqInfo")
        layout.addWidget(self.update_status_label)

        # Update Buttons
        btn_row = QHBoxLayout()

        self.check_update_btn = QPushButton("Auf Updates prüfen")
        self.check_update_btn.clicked.connect(self.check_updates_manual)
        btn_row.addWidget(self.check_update_btn)

        self.install_update_btn = QPushButton("Update installieren")
        self.install_update_btn.setObjectName("primary")
        self.install_update_btn.setEnabled(False)
        self.install_update_btn.clicked.connect(self.install_update)
        btn_row.addWidget(self.install_update_btn)

        upgrade_btn = QPushButton("Upgrade auf EncryptPro (coming soon)")
        btn_row.addWidget(upgrade_btn)

        layout.addLayout(btn_row)

        widget.setLayout(layout)
        self.stack.addWidget(widget)

    # ------------------ Logik ------------------

    def clear_temp_cache(self):
        try:
            temp_dirs = [
                tempfile.gettempdir(),  # System-Temp
                os.path.join(os.getcwd(), "cache"),  # App-Cache (falls vorhanden)
            ]

            cleared = False

            for path in temp_dirs:
                if os.path.exists(path):
                    for item in os.listdir(path):
                        item_path = os.path.join(path, item)
                        try:
                            if os.path.isfile(item_path) or os.path.islink(item_path):
                                os.unlink(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                            cleared = True
                        except Exception:
                            pass  # absichtlich still – keine Abbrüche

            QMessageBox.information(
                self,
                "Cache geleert",
                "Der temporäre Cache wurde erfolgreich geleert."
                if cleared
                else "Es war kein temporärer Cache vorhanden.",
            )

        except Exception as e:
            QMessageBox.critical(
                self, "Fehler", f"Cache konnte nicht geleert werden:\n{e}"
            )

    def display_category(self, index: int):
        self.stack.setCurrentIndex(index)

    def start_changelog_fetch(self):
        """Startet den Worker-Thread."""
        self.changelog_text.setText("Verbinde mit Server und lade Changelog...")

        self.worker = ChangelogWorker()
        self.worker.finished.connect(self.on_changelog_loaded)
        self.worker.error.connect(self.on_changelog_error)
        self.worker.start()

    def on_changelog_loaded(self, data):
        """Wird aufgerufen, wenn der Worker erfolgreich war."""
        version_str = data.get("version", "Unbekannt")
        changelog = data.get("changelog", "Keine Details verfügbar.")

        # Titel der GroupBox aktualisieren
        self.changelog_group.setTitle(f"Details zur neuesten Version: {version_str}")

        # Text formatieren
        display_text = f"<h3>Version {version_str}</h3><hr><pre>{changelog}</pre>"
        self.changelog_text.setHtml(display_text)

    def on_changelog_error(self, error_msg):
        """Wird aufgerufen, wenn der Worker fehlschlägt."""
        if "errno 11001" in error_msg.lower():
            self.changelog_text.setText(
                f"Fehler bei der Verbindung zum Update-Server (DNS-Resolve fehlgeschlagen).\nBitte prüfen Sie Ihre Internetverbindung."
            )
        else:
            self.changelog_text.setText(
                f"Fehler beim Laden:\n{error_msg}\n\nBitte prüfen Sie Ihre Internetverbindung."
            )

    def ensure_admin(self) -> bool:
        """
        Prüft Admin-/Root-Rechte.
        Falls nicht vorhanden, wird eine Rechteanfrage ausgelöst.
        Gibt True zurück, wenn danach Adminrechte vorliegen.
        """
        try:
            if sys.platform == "win32":
                import ctypes

                if ctypes.windll.shell32.IsUserAnAdmin():
                    return True

                # --- Windows: UAC Prompt ---
                params = " ".join(f'"{arg}"' for arg in sys.argv)
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",  # erzwingt UAC
                    sys.executable,
                    params,
                    None,
                    1,
                )
                sys.exit(0)

            else:
                # --- Unix / Linux / macOS ---
                if os.geteuid() == 0:
                    return True

                # Neustart mit sudo
                QMessageBox.information(
                    self,
                    "Administrator-Rechte erforderlich",
                    "Für Updates wird Root-Zugriff benötigt.\n"
                    "Die Anwendung wird nun mit sudo neu gestartet.",
                )

                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

        except Exception as e:
            QMessageBox.critical(
                self,
                "Rechtefehler",
                f"Administratorrechte konnten nicht angefordert werden:\n{e}",
            )
            return False

    def check_updates_manual(self):
        if EncryptHomeUpdater is None:
            QMessageBox.critical(
                self, "Fehler", "Das Modul 'updater.py' wurde nicht gefunden."
            )
            return

        from updater import parse_version, UpdateCheckCache

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

        try:
            updater = EncryptHomeUpdater(
                current_version=VERSION_FULL,
                update_json_url=self.data.get("update_url", UPDATE_URL),
            )

            # Smart: Innerhalb des Cooldowns das letzte Ergebnis nutzen,
            # statt den Server erneut zu kontaktieren.
            cache = UpdateCheckCache(updater.update_dir, cooldown_seconds=1800)
            cached = cache.load()
            if cache.is_fresh() and cached and cached.get("status") in (
                "NO_UPDATE",
                "UPDATE_AVAILABLE",
            ):
                status = cached["status"]
                data = cached.get("data") or {}
            else:
                result = updater.run()
                status = result.get("status")
                data = result.get("data", {})
                cache.store(status, data)

            if status == "NO_UPDATE":
                self.update_status_label.setText("Update-Status: Keine neue Version verfügbar.")
                self.install_update_btn.setEnabled(False)
                QMessageBox.information(
                    self,
                    "Keine Updates verfügbar",
                    "EncryptHome ist auf dem neuesten Stand.",
                )
                return

            if status != "UPDATE_AVAILABLE":
                QMessageBox.warning(self, "Updater", f"Unbekannter Status: {status}")
                return

            current_v = parse_version(VERSION_FULL)
            new_v = parse_version(data.get("version", "0.0.0"))

            # Update-Typ bestimmen
            if new_v[0] > current_v[0]:
                update_type = "MAJOR"
                title = "Versionsupdate verfügbar"
                intro = (
                    "⚠️ Es handelt sich um ein Major-Update.\n\n"
                    "Dieses Update kann grundlegende Änderungen enthalten.\n"
                    "Ein Backup Ihrer Daten wird dringend empfohlen.\n\n"
                )

            elif new_v[1] > current_v[1]:
                update_type = "MINOR"
                title = "Funktionsupdate verfügbar"
                intro = (
                    "✨ Ein Funktionsupdate ist verfügbar.\n\n"
                    "Neue Features und Verbesserungen wurden hinzugefügt.\n\n"
                )

            else:
                update_type = "PATCH"
                title = "Stabilitätsupdate verfügbar"
                intro = "🔧 Ein Stabilitäts- oder Sicherheits-Update ist verfügbar.\n\n"

            info_text = (
                f"{intro}"
                f"Aktuelle Version: {VERSION_FULL}\n"
                f"Neue Version: {data.get('version')}\n"
            )

            if "size_mb" in data:
                info_text += f"Downloadgröße: {data['size_mb']} MB\n"

            info_text += "\nKlicken Sie auf 'Update installieren', um den Installer zu starten."

            self.update_status_label.setText(
                f"Update verfügbar: v{data.get('version')} ({update_type})"
            )
            self.install_update_btn.setEnabled(True)

            QMessageBox.information(self, title, info_text)

        except Exception as e:
            from updater import is_network_reachable

            error_msg = str(e).lower()
            if isinstance(e, ConnectionError) or (
                "errno 11001" in error_msg or "no response" in error_msg
            ):
                if not is_network_reachable():
                    QMessageBox.critical(
                        self,
                        "Update-Fehler",
                        "Es besteht keine Verbindung zum Internet.\n"
                        "Bitte prüfen Sie Ihre Netzwerkverbindung.",
                    )
                else:
                    QMessageBox.critical(
                        self,
                        "Update-Fehler",
                        "Der Update-Server ist aktuell nicht erreichbar.\n"
                        "Bitte versuchen Sie es später erneut.",
                    )
            elif isinstance(e, ValueError):
                QMessageBox.warning(
                    self,
                    "Update-Fehler",
                    f"Die Update-Informationen sind ungültig:\n{e}",
                )
            elif isinstance(e, requests.RequestException):
                QMessageBox.critical(
                    self,
                    "Update-Fehler",
                    f"Netzwerkfehler beim Update-Check:\n{e}",
                )
            else:
                QMessageBox.critical(
                    self,
                    "Update-Fehler",
                    f"Update konnte nicht durchgeführt werden:\n{e}",
                )

        finally:
            QApplication.restoreOverrideCursor()

    def install_update(self):
        if EncryptHomeUpdater is None:
            QMessageBox.critical(
                self, "Fehler", "Das Modul 'updater.py' wurde nicht gefunden."
            )
            return

        updater = EncryptHomeUpdater(
            current_version=VERSION_FULL,
            update_json_url=self.data.get("update_url", UPDATE_URL),
        )

        reply = QMessageBox.question(
            self,
            "Update installieren",
            "Das Update wird nun heruntergeladen und der Installer gestartet.\n"
            "Die Anwendung wird danach geschlossen.\n\n"
            "Möchten Sie fortfahren?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            updater = EncryptHomeUpdater(
                current_version=VERSION_FULL,
                update_json_url=self.data.get("update_url", UPDATE_URL),
            )
            try:
                manifest = updater.fetch_manifest()
            except Exception as e:
                raise ValueError(f"Update-Manifest konnte nicht geladen werden:\n{e}")

            # Integritätsangabe aus dem validierten Manifest übernehmen
            expected = manifest.get("sha256") or ""

            updater.start_update(expected_sha256=expected)
        except Exception as e:
            QMessageBox.critical(
                self, "Update-Fehler", f"Update konnte nicht gestartet werden:\n{e}"
            )
        finally:
            QApplication.restoreOverrideCursor()

    def show_about_dialog(self):
        try:
            from main import AboutDialog

            dlg = AboutDialog(self)
            dlg.exec()
        except ImportError:
            QMessageBox.information(
                self,
                "Info",
                f"EncryptHome Version {VERSION_FULL}\n(About-Dialog nicht gefunden)",
            )
        except Exception as e:
            QMessageBox.warning(
                self, "Fehler", f"About-Dialog konnte nicht geöffnet werden:\n{e}"
            )

    # ------------------ Immediate Save Functions ------------------
    
    def _save_immediate(self):
        """Speichert Checkbox-Einstellungen sofort"""
        self.data["confirm_exit"] = self.cb_confirm_exit.isChecked()
        self.data["del_source_added"] = self.cb_del_source_added.isChecked()
        save_settings(self.data)
    
    def _save_deletion_method(self, text):
        """Speichert Deletion-Methode sofort"""
        self.data["deletion_method"] = text
        save_settings(self.data)
    
    def _save_theme(self, theme):
        """Speichert Theme sofort"""
        self.data["theme"] = theme
        save_settings(self.data)

    def _save_shortcuts(self):
        """Speichert alle Shortcuts sofort"""
        self.data["o_seq"] = self.open_key_input.keySequence().toString()
        self.data["del_seq"] = self.delete_key_input.keySequence().toString()
        self.data["add_seq"] = self.add_input.keySequence().toString()
        self.data["o_all_seq"] = self.export_all_input.keySequence().toString()
        self.data["vault_o_seq"] = self.open_vault_key_input.keySequence().toString()
        self.data["crea_vault_seq"] = self.create_vault_key_input.keySequence().toString()
        self.data["del_vault_seq"] = self.del_vault_input.keySequence().toString()
        self.data["search_seq"] = self.search_input.keySequence().toString()
        save_settings(self.data)
    
    def save(self):
        """Speichern-Button - jetzt nur noch Dialog schließen"""
        self.accept()
