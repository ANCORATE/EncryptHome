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
    "encrypt_intelligence_enabled": False,
    "encrypt_intelligence_search_integration": False,
    "encrypt_intelligence_model_path": "EncryptIntelligence-v1.gguf",
    # --- NEU: Sicherheit & Pfade ---
    "deletion_method": "Standard",  # Standard, DoD, Gutmann
}

# ------------------ Settings laden / speichern ------------------


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
            response = requests.get(UPDATE_URL, timeout=5)
            response.raise_for_status()
            data = response.json()
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))


# ------------------ Settings Dialog ------------------


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"ANCORATE EncryptHome {VERSION_YEAR} – Einstellungen")
        self.setWindowIcon(get_app_icon())
        self.resize(950, 700)
        self.setMinimumSize(750, 500)  # Allow user to resize but not too small
        self.resize(950, 700)
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
            "EncryptIntelligence",
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
        self.create_intelligence_tab()
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
        title.setStyleSheet("font-weight: bold; font-size: 18px; color: #ffffff;")
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
                "Standard-light",
                "Quantum",
                "Precision-light",
                "Precision-dark",
                "Hacker's-dark",
                "Cyber-blue",
            ]
        )
        self.theme_combo.setCurrentText(self.data.get("theme", "Standard-dark"))
        self.theme_combo.currentTextChanged.connect(self._save_theme)
        layout.addWidget(self.theme_combo)

        layout.addStretch()
        widget.setLayout(layout)
        self.stack.addWidget(widget)

    def create_intelligence_tab(self):
        # Scroll-Area, damit Inhalt nie abgeschnitten wird
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        title = QLabel("EncryptIntelligence")
        title.setStyleSheet("font-weight: bold; font-size: 18px; color: #ffffff;")
        layout.addWidget(title)

        description = QLabel(
            "EncryptIntelligence hilft dir, verschlüsselte Dokumente schnell zu durchsuchen."
        )

        description.setWordWrap(True)
        layout.addWidget(description)

        layout.addSpacing(8)

        # --- Enable/Disable ---
        self.cb_intelligence_enabled = QCheckBox("EncryptIntelligence aktivieren")
        self.cb_intelligence_enabled.setChecked(
            self.data.get("encrypt_intelligence_enabled", False)
        )
        self.cb_intelligence_enabled.stateChanged.connect(
            self._on_intelligence_enabled_changed
        )
        layout.addWidget(self.cb_intelligence_enabled)

        # --- Search Integration ---
        self.cb_search_integration = QCheckBox(
            "Normale Suche um lokale Dokumenteninhalte erweitern"
        )
        self.cb_search_integration.setChecked(
            self.data.get("encrypt_intelligence_search_integration", False)
        )
        self.cb_search_integration.stateChanged.connect(
            self._save_intelligence_settings
        )
        self.cb_search_integration.setToolTip(
            "Wenn aktiviert, werden Suchanfragen auch gegen den lokalen EncryptIntelligence-Index ausgeführt."
        )
        layout.addWidget(self.cb_search_integration)

        layout.addSpacing(8)

        # --- Model Selection ---
        self.model_group = QGroupBox("Modell auswählen und herunterladen")
        self.model_group.setStyleSheet("QGroupBox { font-weight: bold; font-size: 13px; margin-top: 12px; } QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; }")
        model_group_layout = QVBoxLayout()
        model_group_layout.setContentsMargins(16, 20, 16, 16)
        model_group_layout.setSpacing(10)

        self.tier_radios = []
        self.tier_labels = []
        from intelligence.core import AVAILABLE_TIERS, get_model_info, resolve_model_path
        current_tier = self.data.get("encrypt_intelligence_model_tier", AVAILABLE_TIERS[0])
        for idx, tier in enumerate(AVAILABLE_TIERS):
            info = get_model_info(tier)

            tier_box = QWidget()
            tier_layout = QVBoxLayout(tier_box)
            tier_layout.setContentsMargins(0, 0, 0, 0)
            tier_layout.setSpacing(2)

            radio = QRadioButton(tier)
            radio.setChecked(tier == current_tier)
            radio.toggled.connect(self._save_intelligence_settings)
            self.tier_radios.append(radio)
            tier_layout.addWidget(radio)

            desc_lbl = QLabel(info["description"])
            desc_lbl.setWordWrap(True)
            desc_lbl.setStyleSheet("color: #c0c0c0; font-size: 12px; padding-left: 24px;")
            tier_layout.addWidget(desc_lbl)

            status_lbl = QLabel()
            status_lbl.setStyleSheet("font-size: 12px; padding-left: 24px;")
            tier_layout.addWidget(status_lbl)
            self.tier_labels.append(status_lbl)

            if idx < len(AVAILABLE_TIERS) - 1:
                sep = QFrame()
                sep.setFrameShape(QFrame.Shape.HLine)
                sep.setStyleSheet("color: #333;")
                tier_layout.addWidget(sep)

            model_group_layout.addWidget(tier_box)

        self._update_tier_status_labels()

        model_group_layout.addSpacing(6)

        dl_row = QWidget()
        dl_row_layout = QHBoxLayout(dl_row)
        dl_row_layout.setContentsMargins(0, 0, 0, 0)
        dl_row_layout.setSpacing(8)

        self.dl_progress = QProgressBar()
        self.dl_progress.setVisible(False)
        self.dl_progress.setFixedHeight(24)
        dl_row_layout.addWidget(self.dl_progress, 1)

        self.dl_status_label = QLabel("")
        self.dl_status_label.setStyleSheet("color: #c0c0c0;")
        dl_row_layout.addWidget(self.dl_status_label)

        model_group_layout.addWidget(dl_row)

        self.dl_button = QPushButton("Herunterladen")
        self.dl_button.setFixedHeight(32)
        self.dl_button.clicked.connect(self._download_selected_model)
        model_group_layout.addWidget(self.dl_button)

        self.model_group.setLayout(model_group_layout)
        layout.addWidget(self.model_group)
        self.model_group.setVisible(self.cb_intelligence_enabled.isChecked())

        layout.addSpacing(12)

        # --- Status ---
        status_title = QLabel("Status")
        status_title.setStyleSheet("font-weight: bold; font-size: 14px; color: #ffffff;")
        layout.addWidget(status_title)

        status_group = QGroupBox()
        status_group_layout = QVBoxLayout()
        status_group_layout.setContentsMargins(12, 12, 12, 12)
        status_group_layout.setSpacing(6)

        self._status_labels = {}
        for key, label in [
            ("llm", "LLM-Backend"),
            ("search", "Keyword-Suche"),
            ("pdf", "PDF-Unterstützung"),
            ("ocr", "OCR (Bilder)"),
        ]:
            row = QHBoxLayout()
            row.addWidget(QLabel(label + ":"))
            lbl = QLabel("?")
            lbl.setStyleSheet("color: #c0c0c0;")
            self._status_labels[key] = lbl
            row.addWidget(lbl)
            row.addStretch()
            status_group_layout.addLayout(row)

        status_group.setLayout(status_group_layout)
        layout.addWidget(status_group)

        self._refresh_status_btn = QPushButton("Status aktualisieren")
        self._refresh_status_btn.setFixedHeight(32)
        self._refresh_status_btn.clicked.connect(self._refresh_intelligence_status)
        layout.addWidget(self._refresh_status_btn)

        layout.addSpacing(8)

        hint = QLabel(
            "Hinweis: Die Suche verwendet verschlüsselte Dokumente aus deinem aktuellen Tresor."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #c0c0c0; font-size: 12px;")
        layout.addWidget(hint)

        layout.addStretch()

        scroll.setWidget(widget)
        self.stack.addWidget(scroll)

    def _on_intelligence_enabled_changed(self):
        enabled = self.cb_intelligence_enabled.isChecked()
        self.model_group.setVisible(enabled)
        self._save_intelligence_settings()
        if enabled:
            self._refresh_intelligence_status()

    def _update_tier_status_labels(self):
        from intelligence.core import resolve_model_path
        for i, radio in enumerate(self.tier_radios):
            path = resolve_model_path(radio.text())
            exists = path and path.exists()
            if exists:
                size_mb = path.stat().st_size / (1024 * 1024)
                self.tier_labels[i].setText(f"✅ {size_mb:.0f} MB – heruntergeladen")
                self.tier_labels[i].setStyleSheet("color: #4caf50; font-size: 12px; padding-left: 20px;")
            else:
                info_size = self._get_tier_info(radio.text()).get("filesize", 0)
                size_mb = info_size / (1024 * 1024)
                self.tier_labels[i].setText(f"↻ {size_mb:.0f} MB – noch nicht heruntergeladen")
                self.tier_labels[i].setStyleSheet("color: #ff9800; font-size: 12px; padding-left: 20px;")

    def _get_tier_info(self, tier):
        from intelligence.core import get_model_info
        return get_model_info(tier) or {}

    def _get_selected_tier(self):
        for radio in self.tier_radios:
            if radio.isChecked():
                return radio.text()
        return self.tier_radios[0].text() if self.tier_radios else ""

    def _download_selected_model(self):
        tier = self._get_selected_tier()
        if not tier:
            return

        self.dl_button.setEnabled(False)
        self.dl_progress.setVisible(True)
        self.dl_progress.setValue(0)
        self.dl_status_label.setText("Starte Download...")

        from intelligence.core import download_model

        class _DlSignals(QObject):
            done = pyqtSignal()
            error = pyqtSignal(str)
            progress = pyqtSignal(int, int)

        _sig = _DlSignals()
        _sig.done.connect(lambda: self.dl_status_label.setText("✅ Download abgeschlossen"))
        _sig.done.connect(self._update_tier_status_labels)
        _sig.done.connect(self._refresh_intelligence_status)
        _sig.done.connect(lambda: self.dl_button.setEnabled(True))
        _sig.error.connect(lambda e: self.dl_status_label.setText(f"❌ Fehler: {e}"))
        _sig.error.connect(lambda: self.dl_button.setEnabled(True))
        _sig.progress.connect(lambda c, t: self.dl_progress.setValue(int(c * 100 / t)) if t > 0 else None)
        _sig.progress.connect(lambda c, t: self.dl_status_label.setText(
            f"{c / (1024*1024):.0f} / {t / (1024*1024):.0f} MB"
        ) if t > 0 else None)

        def _run():
            try:
                download_model(tier, progress_callback=lambda c, t: _sig.progress.emit(c, t))
                _sig.done.emit()
            except Exception as e:
                _sig.error.emit(str(e))

        import threading
        threading.Thread(target=_run, daemon=True).start()

    def _refresh_intelligence_status(self):
        try:
            from intelligence.core import EncryptIntelligenceManager, EncryptIntelligenceConfig
            tier = self.data.get("encrypt_intelligence_model_tier", "EncryptIntelligence Light")
            config = EncryptIntelligenceConfig(model_tier=tier)
            mgr = EncryptIntelligenceManager(config)
            caps = mgr.capability_status()
        except Exception as e:
            for lbl in self._status_labels.values():
                lbl.setText("Fehler")
                lbl.setStyleSheet("color: #ff4444;")
            self._status_labels["llm"].setText(str(e)[:80])
            return
        self._status_labels["llm"].setText(
            "✅ " + caps["llm_backend"] if caps["llm"] else "❌ nicht verfügbar"
        )
        self._status_labels["llm"].setStyleSheet(
            "color: #4caf50;" if caps["llm"] else "color: #ff9800;"
        )
        self._status_labels["search"].setText("✅ immer verfügbar")
        self._status_labels["search"].setStyleSheet("color: #4caf50;")
        self._status_labels["pdf"].setText("✅ ja" if caps["pdf"] else "❌ nein (PyMuPDF/pypdf fehlt)")
        self._status_labels["pdf"].setStyleSheet("color: #4caf50;" if caps["pdf"] else "color: #ff4444;")
        self._status_labels["ocr"].setText("✅ ja" if caps["ocr"] else "❌ nein (easyocr fehlt)")
        self._status_labels["ocr"].setStyleSheet("color: #4caf50;" if caps["ocr"] else "color: #ff9800;")

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
        self.changelog_text.setStyleSheet(
            "background-color: #2b2b2b; color: #e0e0e0; border: 1px solid #555;"
        )
        group_layout.addWidget(self.changelog_text)

        self.changelog_group.setLayout(group_layout)
        layout.addWidget(self.changelog_group, 1)  # Expandiert

        self.update_status_label = QLabel("Update-Status: noch nicht geprüft")
        self.update_status_label.setStyleSheet("color: #c0c0c0; font-size: 13px;")
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

        def parse_version(v: str):
            parts = v.split(".")
            # auf 3 Stellen auffüllen
            while len(parts) < 3:
                parts.append("0")
            return tuple(int(p) for p in parts[:3])

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

        try:
            updater = EncryptHomeUpdater(
                current_version=VERSION_FULL,
                update_json_url=self.data.get("update_url", UPDATE_URL),
            )

            result = updater.run()
            status = result.get("status")
            data = result.get("data", {})

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
            error_msg = str(e)
            if "errno 11001" in error_msg.lower():
                QMessageBox.critical(
                    self, "Update-Fehler", f"Es besteht keine Verbindung zum Internet."
                )
            else:
                QMessageBox.critical(
                    self, "Update-Fehler", f"Update konnte nicht durchgeführt werden:\n{e}"
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
            updater.start_update()
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

    def _save_intelligence_settings(self):
        """Speichert EncryptIntelligence-Einstellungen sofort"""
        self.data["encrypt_intelligence_enabled"] = self.cb_intelligence_enabled.isChecked()
        self.data["encrypt_intelligence_search_integration"] = (
            self.cb_search_integration.isChecked()
        )
        self.data["encrypt_intelligence_model_tier"] = self._get_selected_tier()
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
