# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import json
import os
import shutil
import sys
import platform
import hashlib
import tempfile
import time
import weakref

import requests
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWidgets import *

from .sos_delete import SaltScannerUI
from . import get_app_icon

# --- Setup Pfade & Konstanten ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from .updater import EncryptHomeUpdater
except ImportError:
    EncryptHomeUpdater = None

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".ancorate")
try:
    os.makedirs(CONFIG_DIR, exist_ok=True)
except OSError:
    pass
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings.json")

# --- Einstellungs-Verschlüsselung (Datei wird am Gerät gebunden verschlüsselt) ---
# Format: MAGIC || encrypt_meta(dict, settings_key)
# encrypt_meta liefert: nonce(12) || ct+tag || hmac(32)
_SETTINGS_MAGIC = b"ANC_STG\x01"
_SETTINGS_SALT = b"ENC_HOME_SETTINGS_V1"
_SETTINGS_INFO = "ancorate-settings-v1"
# Stabiler Key-Derivations-Info: domain-separiert vom alten Schlüssel.
_STABLE_SETTINGS_INFO = "ancorate-settings-v2-stable"
_MIGRATED = False  # einmalige Migration alter Klartext-Dateien pro Prozess

from version import VERSION as VERSION_FULL, VERSION_YEAR


UPDATE_URL = "https://api.github.com/repos/ANCORATE/EncryptHome/releases/latest"

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
    "ui_accent": "",  # leer = Theme-Standard, sonst Hex wie "#ff8800"
    "ui_density": "Mittel",  # Kompakt, Mittel, Komfortabel
    # --- Design: Dateilisten-Ansicht ---
    "list_view_mode": "list",  # list, compact, grid
    "list_show_size": True,
    "list_show_date": True,
    "list_sort": "Keine",  # Keine, Name
    # --- Updater (alte Defaults) ---
    "update_url": UPDATE_URL,
    "update_channel": "stable",
    # --- NEU: System & Verhalten ---
    "confirm_exit": True,
    "del_source_added": False,
    # --- Auto-Lock (in Minuten; 0 = deaktiviert) ---
    "auto_lock_minutes": 5,
    # --- NEU: Sicherheit & Pfade ---
    "deletion_method": "Standard",  # Standard, DoD, Gutmann
    "screenshot_protection": True,
}

# ------------------ Settings laden / speichern ------------------

VALID_THEMES = ("Standard-dark", "Standard-White", "High-Contrast", "Midnight Blue")
VALID_DENSITIES = ("Kompakt", "Mittel", "Komfortabel")
VALID_LIST_VIEW_MODES = ("list", "compact", "grid")
VALID_LIST_SORTS = ("Keine", "Name")

# Vordefinierte Akzentfarben für den Design-Tab. Leer = Theme-Standard.
ACCENT_PRESETS = [
    ("Theme-Standard", ""),
    ("Blau", "#2f7cf6"),
    ("Grün", "#10b981"),
    ("Rot", "#ef4444"),
    ("Orange", "#f97316"),
    ("Lila", "#8b5cf6"),
    ("Gold", "#eab308"),
    ("Türkis", "#14b8a6"),
]


def _settings_keys():
    """VERALTET - nur noch als Migrations-Fallback.

    Die frühere Ableitung lief über das Laufzeit-Device-Fingerprinting
    (generate_device_key -> CIM/WMI-Abfragen via Subprozess mit 3s-Timeouts).
    Deren Ergebnis konnte je nach Kontext bzw. Zeitüberschreitung wechseln,
    wodurch eine gespeicherte settings.json beim nächsten Start nicht mehr
    entschlüsselt werden konnte („korrupte“ Einstellungen).

    Für neue Writes wird `_stable_settings_key` verwendet. Diese Funktion
    liefert ALLE deterministischen Varianten des alten Schemas, damit bereits
    mit dem alten Schlüssel verschlüsselte Daten einmalig gelesen und
    migriert werden können.
    """
    try:
        from app.core import legacy_device_key_variants
        variants = legacy_device_key_variants()
        keys = []
        from base import derive_subkey
        for dev in variants:
            if not isinstance(dev, bytes) or len(dev) not in (16, 24, 32):
                continue
            keys.append(derive_subkey(dev, _SETTINGS_SALT, _SETTINGS_INFO))
        return keys or None
    except Exception as e:
        print(f"[WARN] Settings key derivation failed: {e}")
        return None


def _settings_key():
    """Migrations-Fallback: primäre Variante des alten Schlüssel-Schemas."""
    try:
        keys = _settings_keys()
        return keys[0] if keys else None
    except Exception:
        return None


def _stable_machine_id() -> bytes:
    """Stabile, subprocess-unabhängige Maschinen-ID.

    Bevorzugt die Windows MachineGuid aus der Registry (schnell, ohne
    Subprozess, identisch bei jedem Start). Fallbacks: MAC-Adresse,
    dann Hostname+Plattform.
    """
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as key:
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            if guid and isinstance(guid, str):
                return guid.encode("utf-8")
    except Exception:
        pass
    try:
        import uuid
        mac = uuid.getnode()
        if mac:
            return int(mac).to_bytes(6, "big", signed=False)
    except Exception:
        pass
    return hashlib.sha256(
        f"{platform.node()}|{platform.system()}".encode("utf-8")
    ).digest()


def _stable_settings_key():
    """Gerätegebundener, STABILER Schlüssel für Einstellungen.

    Wird aus einer stabilen Maschinen-ID abgeleitet (Domain-Separation via
    HKDF), damit die Einstellungen nicht bei jedem Start „korrupt“ erscheinen.
    """
    try:
        machine_id = _stable_machine_id()
        if not machine_id:
            return None
        from base import derive_subkey
        return derive_subkey(machine_id, _SETTINGS_SALT, _STABLE_SETTINGS_INFO)
    except Exception as e:
        print(f"[WARN] Stable settings key derivation failed: {e}")
        return None


def _write_encrypted(settings: dict):
    """Schreibt Einstellungen verschlüsselt (atomar über os.replace)."""
    key = _stable_settings_key()
    if not key:
        # Fallback zur alten Ableitung - verhindert einen komplett
        # unbrauchbaren Zustand, falls die stabile ID unverfügbar ist.
        key = _settings_key()
    if not key:
        raise RuntimeError(
            "Kein Geräteschlüssel verfügbar - Verschlüsselung der Einstellungen nicht möglich."
        )
    from encrypt import encrypt_meta

    blob = encrypt_meta(settings, key)
    # Einzigartiger Temp-Name: verhindert Verfälschungen durch parallele
    # Schreiber (mehrere Prozesse nutzten vorher dieselbe .tmp-Datei).
    tmp_fd, tmp = tempfile.mkstemp(
        dir=CONFIG_DIR, prefix=".settings-", suffix=".tmp"
    )
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            f.write(_SETTINGS_MAGIC)
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, SETTINGS_FILE)
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _read_settings_raw() -> dict | None:
    """Liest Einstellungen - verschlüsselt oder (Migration) altes Klartext-JSON."""
    try:
        with open(SETTINGS_FILE, "rb") as f:
            raw = f.read()
    except Exception:
        return None

    if raw.startswith(_SETTINGS_MAGIC):
        blob = raw[len(_SETTINGS_MAGIC):]

        # 1) Stabiler Schlüssel - der neue, zuverlässige Pfad.
        key = _stable_settings_key()
        if key:
            try:
                from decrypt import decrypt_meta
                return decrypt_meta(blob, key)
            except Exception:
                pass  # evtl. noch mit altem Schlüssel verschlüsselt

        # 2) Alter Laufzeit-Fingerprint-Schlüssel: Daten sichern und auf den
        #    stabilen Schlüssel migrieren (einmalig), falls der zutrifft.
        legacy_keys = _settings_keys()
        if legacy_keys:
            data = None
            for legacy_key in legacy_keys:
                try:
                    from decrypt import decrypt_meta
                    data = decrypt_meta(blob, legacy_key)
                    if data is not None:
                        break
                except Exception:
                    continue
            if data is None:
                print("[ERROR] Settings decryption failed: kein passender Schlüssel verfügbar")
                return None
            try:
                _write_encrypted(data)
                print("[Info] Settings auf stabilen Geräteschlüssel migriert.")
            except Exception as e:
                print(f"[WARN] Settings-Migration auf stabilen Schlüssel fehlgeschlagen: {e}")
            return data
        print("[ERROR] Settings decryption failed: kein passender Schlüssel verfügbar")
        return None

    # Legacy: unverschlüsselte Dump-Datei aus früheren Versionen
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _migrate_encrypted(data: dict):
    """Einmalige Migration einer noch im Klartext vorliegenden settings.json."""
    global _MIGRATED
    if _MIGRATED:
        return
    _MIGRATED = True
    try:
        _write_encrypted(data)
        print("[Info] Settings erfolgreich auf verschlüsseltes Format migriert.")
    except Exception as e:
        print(f"[WARN] Settings-Migration auf verschlüsseltes Format fehlgeschlagen: {e}")


def _cleanup_stale_settings_tmp():
    """Entfernt verwaiste Temp-Dateien abgestürzter Schreibvorgänge.

    Das alte Fix-Format war `settings.json.tmp` (Kollisions- und
    Truncation-Ursache bei parallelen Schreibern); neue Writes verwenden
    eindeutige `.settings-*.tmp`-Dateien. Nur Dateien, die älter als eine
    Minute sind, werden entfernt - ein parallel laufender weiterer
    App-Prozess schreibt seine Temp-Datei in Millisekunden.
    """
    try:
        now = time.time()
        stale = []
        for name in os.listdir(CONFIG_DIR):
            if name == "settings.json.tmp" or (
                name.startswith(".settings-") and name.endswith(".tmp")
            ):
                stale.append(os.path.join(CONFIG_DIR, name))
        for tmp in stale:
            try:
                if os.path.isfile(tmp) and now - os.path.getmtime(tmp) > 60:
                    os.remove(tmp)
            except OSError:
                pass
    except Exception:
        pass


def load_settings():
    path = SETTINGS_FILE
    _cleanup_stale_settings_tmp()
    if not os.path.exists(path):
        return DEFAULT_SETTINGS.copy()
    try:
        with open(path, "rb") as f:
            is_encrypted = f.read(len(_SETTINGS_MAGIC)) == _SETTINGS_MAGIC
    except Exception:
        is_encrypted = False

    data = _read_settings_raw()
    if data is None:
        return DEFAULT_SETTINGS.copy()
    if not isinstance(data, dict):
        return DEFAULT_SETTINGS.copy()

    if not is_encrypted:
        # Alte Klartext-Datei: sofort verschlüsseln, der Bestand bleibt nutzbar.
        _migrate_encrypted(data)

    # Fehlende Keys ergänzen
    for k, v in DEFAULT_SETTINGS.items():
        if k not in data:
            data[k] = v

    # Alte/entfernte Theme-Werte sicher auf einen gültigen migrieren
    if data.get("theme") not in VALID_THEMES:
        data["theme"] = DEFAULT_SETTINGS["theme"]
    if data.get("ui_density") not in VALID_DENSITIES:
        data["ui_density"] = DEFAULT_SETTINGS["ui_density"]
    if data.get("list_view_mode") not in VALID_LIST_VIEW_MODES:
        data["list_view_mode"] = DEFAULT_SETTINGS["list_view_mode"]
    if data.get("list_sort") not in VALID_LIST_SORTS:
        data["list_sort"] = DEFAULT_SETTINGS["list_sort"]
    accent = data.get("ui_accent", "")
    if not isinstance(accent, str) or not (
        not accent or (accent.startswith("#") and len(accent) in (4, 7))
    ):
        data["ui_accent"] = DEFAULT_SETTINGS["ui_accent"]
    for bool_key in ("list_show_size", "list_show_date"):
        if not isinstance(data.get(bool_key), bool):
            data[bool_key] = DEFAULT_SETTINGS[bool_key]
    return data


def save_settings(settings: dict):
    try:
        _write_encrypted(settings)
        _notify_settings_changed()
    except Exception as e:
        print(f"Fehler beim Speichern der Einstellungen: {e}")


# ------------------ Settings-Änderungen sofort melden ------------------

# In-Prozess-Listener: Ersetzt die unzuverlässige QFileSystemWatcher-Kette,
# da atomare Writes (os.replace) den Watch nach dem ersten Ereignis beenden.
_SETTINGS_LISTENERS: list = []


def register_settings_listener(callback):
    """Registriert einen Callback, der nach jedem erfolgreichen Speichern läuft."""
    if callback not in _SETTINGS_LISTENERS:
        _SETTINGS_LISTENERS.append(callback)


def unregister_settings_listener(callback):
    if callback in _SETTINGS_LISTENERS:
        _SETTINGS_LISTENERS.remove(callback)


def _notify_settings_changed():
    for callback in list(_SETTINGS_LISTENERS):
        try:
            callback()
        except Exception:
            pass


# ------------------ Sanfter Theme-Wechsel (Fade-Überblendung) ------------------
# Qt-Stylesheets lassen sich nicht nativ animieren. Beim Wechsel des Themes
# (z. B. dunkel nach hell) wird die Opazität der Top-Level-Fenster kurz
# abgesenkt, das neue Stylesheet angewendet und wieder eingeblendet – ein
# weicher Übergang statt eines harten Umschaltens. Akzent-/Dichte-Änderungen
# im selben Theme und der allererste Aufruf (Programmstart) werden ohne Fade
# übernommen.

_FADE_OUT_MS = 150
_FADE_IN_MS = 220
_FADE_MIN_OPACITY = 0.1

_last_applied_theme = None
_main_window_ref = None
_theme_fade_anims = []
_theme_fade_generation = 0

# Plattformen, auf denen Qt native Fenster-Opazität (setWindowOpacity) wirklich
# unterstützt. Wayland/offscreen/minimal etc. können das nicht und würden sonst
# pro Fade-Schritt "This plugin does not support setting window opacity"
# ausgeben – dort wird der Fade übersprungen (sofortiger, sauberer Wechsel).
_OPACITY_SUPPORTED_PLATFORMS = {"windows", "cocoa", "xcb"}


def _window_opacity_supported() -> bool:
    """True, wenn die aktuelle Qt-Plattform windowOpacity unterstützt."""
    try:
        name = (QGuiApplication.platformName() or "").lower()
        return name in _OPACITY_SUPPORTED_PLATFORMS
    except Exception:
        return False


def register_main_window(window):
    """Meldet das Hauptfenster an, damit Theme-Wechsel per Fade animiert werden."""
    global _main_window_ref
    _main_window_ref = weakref.ref(window) if window is not None else None


def _stop_theme_fade():
    """Bricht eine laufende Überblendung ab und stellt volle Opazität her."""
    global _theme_fade_anims
    anims, _theme_fade_anims = _theme_fade_anims, []
    for anim in anims:
        try:
            anim.stop()
            target = anim.targetObject()
            if target is not None:
                target.setWindowOpacity(1.0)
        except Exception:
            pass


def fade_theme_swap(swap_fn, theme_name, extra_windows=()):
    """Wendet swap_fn mit sanfter Überblendung an, wenn sich das Theme ändert.

    :param swap_fn: Callable, das das neue Stylesheet setzt.
    :param theme_name: Name des neuen Themes (nur ein tatsächlicher Theme-Wechsel fadet).
    :param extra_windows: Weitere sichtbare Top-Level-Fenster, die mit überblendet
                          werden (z. B. der offene Einstellungs-Dialog).
    """
    global _last_applied_theme, _theme_fade_generation
    if theme_name == _last_applied_theme:
        return swap_fn()

    windows = []
    main_win = _main_window_ref() if _main_window_ref is not None else None
    if main_win is not None and main_win.isVisible():
        windows.append(main_win)
    for w in extra_windows:
        if w is not None and w.isVisible() and w not in windows:
            windows.append(w)

    is_first = _last_applied_theme is None
    _last_applied_theme = theme_name
    if not windows or is_first or not _window_opacity_supported():
        return swap_fn()

    _stop_theme_fade()
    _theme_fade_generation += 1
    gen = _theme_fade_generation
    remaining = [len(windows)]

    def _on_fade_out_done():
        if gen != _theme_fade_generation:
            return
        remaining[0] -= 1
        if remaining[0] <= 0:
            _theme_swap_mid(windows, swap_fn, gen)

    for w in windows:
        anim = QPropertyAnimation(w, b"windowOpacity")
        anim.setDuration(_FADE_OUT_MS)
        anim.setStartValue(1.0)
        anim.setEndValue(_FADE_MIN_OPACITY)
        anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
        anim.finished.connect(_on_fade_out_done)
        _theme_fade_anims.append(anim)
        anim.start()


def _theme_swap_mid(windows, swap_fn, gen):
    """Tauscht das Stylesheet am tiefsten Opazitätspunkt und blendet ein."""
    global _theme_fade_anims
    try:
        swap_fn()
    finally:
        remaining = [len(windows)]

        def _on_fade_in_done():
            global _theme_fade_anims
            if gen != _theme_fade_generation:
                return
            remaining[0] -= 1
            if remaining[0] <= 0:
                _theme_fade_anims = []

        fade_in = []
        for w in windows:
            anim = QPropertyAnimation(w, b"windowOpacity")
            anim.setDuration(_FADE_IN_MS)
            anim.setStartValue(w.windowOpacity())
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.Type.InOutQuad)
            anim.finished.connect(_on_fade_in_done)
            fade_in.append(anim)
            anim.start()
        _theme_fade_anims = fade_in


# ------------------ Worker Thread für Changelog ------------------
class ChangelogWorker(QThread):
    """Lädt den Changelog im Hintergrund, damit die GUI nicht einfriert."""

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, channel: str = "stable"):
        super().__init__()
        self.channel = (channel or "stable").lower()

    def run(self):
        try:
            from .updater import EncryptHomeUpdater

            updater = EncryptHomeUpdater(
                current_version=VERSION_FULL,
                update_json_url=UPDATE_URL,
                channel=self.channel,
            )
            data = updater.fetch_manifest(timeout=5)
            self.finished.emit(data)
        except Exception as e:
            self.error.emit(str(e))


# ------------------ Settings Dialog ------------------


class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("SettingsDialog")
        self.setWindowTitle(f"ANCORATE EncryptHome {VERSION_YEAR} – Einstellungen")
        self.setWindowIcon(get_app_icon())
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

        # Auto-Lock
        lock_row = QHBoxLayout()
        lock_row.setSpacing(8)
        lock_lbl = QLabel("Automatisch sperren nach:")
        self.spin_auto_lock = QSpinBox()
        self.spin_auto_lock.setRange(0, 480)
        self.spin_auto_lock.setSuffix(" Min.")
        self.spin_auto_lock.setSpecialValueText("Aus")
        self.spin_auto_lock.setValue(int(self.data.get("auto_lock_minutes", 5)))
        self.spin_auto_lock.setToolTip(
            "Der Tresor wird nach dieser Zeit der Inaktivität automatisch gesperrt "
            "(Passwort wird erneut benötigt). 0 = Aus."
        )
        self.spin_auto_lock.valueChanged.connect(self._save_auto_lock)
        lock_row.addWidget(lock_lbl)
        lock_row.addWidget(self.spin_auto_lock)
        lock_row.addStretch()
        gb_layout.addLayout(lock_row)

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

        self.cb_screenshot_protection = QCheckBox(
            "Bildschirmaufnahmen blockieren (Windows)"
        )
        self.cb_screenshot_protection.setToolTip(
            "Schützt das Fenster vor Aufzeichnung durch Bildschirmaufnahme-Tools."
        )
        self.cb_screenshot_protection.setChecked(
            self.data.get("screenshot_protection", True)
        )
        self.cb_screenshot_protection.stateChanged.connect(self._save_immediate)
        form_sec.addRow(self.cb_screenshot_protection)

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
        about_btn = QPushButton("Informationen zu dieser Installation von EncryptHome")
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
        reply = QMessageBox.question(
            self,
            "Anwendung sofort beenden",
            "Soll die Anwendung wirklich sofort beendet werden?\n\n"
            "Nicht gespeicherte In-Tresor-Bearbeitungen werden nicht automatisch in den Tresor "
            "zurückgeschrieben. Möchten Sie fortsetzen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            sys.exit(0)

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
        # ScrollArea wie im Allgemein-Tab, damit der Inhalt bei kleinen Fenstern bleibt
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content_widget = QWidget()
        layout = QVBoxLayout(content_widget)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.setSpacing(20)

        # --- Titel ---
        title = QLabel("Design & Erscheinungsbild")
        title.setStyleSheet("font-weight: bold; font-size: 16px;")
        layout.addWidget(title)

        # --- Sektion: Erscheinungsbild (QGroupBox) ---
        group_appearance = QGroupBox("Erscheinungsbild")
        form_appearance = QFormLayout()
        form_appearance.setSpacing(10)
        form_appearance.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )

        # Design-Theme
        theme_lbl = QLabel("Design-Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(list(VALID_THEMES))
        self.theme_combo.setCurrentText(self.data.get("theme", "Standard-dark"))
        self.theme_combo.currentTextChanged.connect(self._save_theme)
        form_appearance.addRow(theme_lbl, self.theme_combo)

        # Schriftgröße / Dichte
        density_lbl = QLabel("Schriftgröße / Dichte:")
        self.density_combo = QComboBox()
        self.density_combo.addItems(list(VALID_DENSITIES))
        self.density_combo.setCurrentText(self.data.get("ui_density", "Mittel"))
        self.density_combo.currentTextChanged.connect(self._save_density)
        form_appearance.addRow(density_lbl, self.density_combo)

        # Akzentfarbe
        accent_lbl = QLabel("Akzentfarbe:")
        self.accent_combo = QComboBox()
        for label, value in ACCENT_PRESETS:
            self.accent_combo.addItem(label, value)
        current_accent = str(self.data.get("ui_accent") or "")
        accent_index = self.accent_combo.findData(current_accent)
        if accent_index < 0:
            self.accent_combo.addItem(
                f"Eigene: {current_accent}" if current_accent else "Standard",
                current_accent)
            accent_index = self.accent_combo.count() - 1
        self.accent_combo.setCurrentIndex(accent_index)
        self.accent_combo.currentIndexChanged.connect(self._on_accent_index_changed)

        self.accent_pick_btn = QPushButton("Eigene...")
        self.accent_pick_btn.clicked.connect(self._pick_accent)

        accent_row = QHBoxLayout()
        accent_row.setSpacing(8)
        accent_row.addWidget(self.accent_combo, 1)
        accent_row.addWidget(self.accent_pick_btn)
        form_appearance.addRow(accent_lbl, accent_row)

        group_appearance.setLayout(form_appearance)
        layout.addWidget(group_appearance)

        # --- Sektion: Dateiliste (QGroupBox) ---
        list_group = QGroupBox("Dateiliste")
        form_list = QFormLayout()
        form_list.setSpacing(10)
        form_list.setFieldGrowthPolicy(
            QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow
        )

        mode_lbl = QLabel("Layout:")
        self.list_mode_combo = QComboBox()
        self.list_mode_combo.addItem("Liste", "list")
        self.list_mode_combo.addItem("Kompakt", "compact")
        self.list_mode_combo.addItem("Raster", "grid")
        mode_index = self.list_mode_combo.findData(
            self.data.get("list_view_mode", "list")
        )
        self.list_mode_combo.setCurrentIndex(max(0, mode_index))
        self.list_mode_combo.currentIndexChanged.connect(self._save_list_mode)
        form_list.addRow(mode_lbl, self.list_mode_combo)

        sort_lbl = QLabel("Sortierung:")
        self.list_sort_combo = QComboBox()
        self.list_sort_combo.addItems(list(VALID_LIST_SORTS))
        self.list_sort_combo.setCurrentText(self.data.get("list_sort", "Keine"))
        self.list_sort_combo.currentTextChanged.connect(self._save_list_sort)
        form_list.addRow(sort_lbl, self.list_sort_combo)

        self.cb_show_size = QCheckBox("Dateigröße anzeigen")
        self.cb_show_size.setChecked(bool(self.data.get("list_show_size", True)))
        self.cb_show_size.toggled.connect(self._save_list_show_size)
        form_list.addRow(self.cb_show_size)

        self.cb_show_date = QCheckBox("Datum anzeigen")
        self.cb_show_date.setChecked(bool(self.data.get("list_show_date", True)))
        self.cb_show_date.toggled.connect(self._save_list_show_date)
        form_list.addRow(self.cb_show_date)

        list_group.setLayout(form_list)
        layout.addWidget(list_group)

        layout.addStretch()

        scroll.setWidget(content_widget)
        self.stack.addWidget(scroll)

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

        channel_row = QHBoxLayout()
        channel_row.addWidget(QLabel("Update-Kanal:"))
        self.channel_combo = QComboBox()
        self.channel_combo.addItems(["stable", "beta"])
        self.channel_combo.setCurrentText(self.data.get("update_channel", "stable"))
        self.channel_combo.currentTextChanged.connect(self._save_update_channel)
        channel_row.addWidget(self.channel_combo)
        channel_row.addStretch()
        layout.addLayout(channel_row)

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

        layout.addLayout(btn_row)

        widget.setLayout(layout)
        self.stack.addWidget(widget)

    # ------------------ Logik ------------------

    def clear_temp_cache(self):
        try:
            # Der Updater legt Downloads im Verzeichnis der Anwendung ab
            # (analog zu EncryptHomeUpdater.update_dir); BASE_DIR bleibt als
            # Legacy-Ort erhalten.
            app_base = os.path.dirname(os.path.abspath(sys.argv[0]))
            temp_dirs = [
                os.path.join(app_base, "update_temp"),  # heruntergeladene Updates
                os.path.join(BASE_DIR, "update_temp"),  # Legacy-Ort
                os.path.join(os.getcwd(), "cache"),  # App-Cache (falls vorhanden)
            ]
            if EncryptHomeUpdater is not None:
                temp_dirs.insert(0, EncryptHomeUpdater._user_update_dir())

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

        self.worker = ChangelogWorker(channel=self.data.get("update_channel", "stable"))
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
                "Fehler bei der Verbindung zum Update-Server (DNS-Resolve fehlgeschlagen).\nBitte prüfen Sie Ihre Internetverbindung."
            )
        else:
            self.changelog_text.setText(
                f"Fehler beim Laden:\n{error_msg}\n\nBitte prüfen Sie Ihre Internetverbindung."
            )

    def check_updates_manual(self):
        if EncryptHomeUpdater is None:
            QMessageBox.critical(
                self, "Fehler", "Das Modul 'updater.py' wurde nicht gefunden."
            )
            return

        from .updater import parse_version, UpdateCheckCache

        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

        try:
            updater = EncryptHomeUpdater(
                current_version=VERSION_FULL,
                update_json_url=self.data.get("update_url", UPDATE_URL),
                channel=self.data.get("update_channel", "stable"),
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
            from .updater import is_network_reachable

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
                channel=self.data.get("update_channel", "stable"),
            )
            # Der Updater wählt passend zum Installationsort (beschreibbar vs.
            # schreibgeschützt) das portable Binary bzw. den Installer aus und
            # prüft dessen Integrität selbst.
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
        self.data["screenshot_protection"] = self.cb_screenshot_protection.isChecked()
        save_settings(self.data)
    
    def _save_deletion_method(self, text):
        """Speichert Deletion-Methode sofort"""
        self.data["deletion_method"] = text
        save_settings(self.data)
    
    def _save_auto_lock(self, minutes):
        """Speichert Auto-Lock-Timeout sofort (Minuten, 0 = aus)."""
        self.data["auto_lock_minutes"] = int(minutes)
        save_settings(self.data)
    
    def _save_theme(self, theme):
        """Speichert Theme sofort"""
        self.data["theme"] = theme
        save_settings(self.data)
        self._apply_theme_now()

    def _save_density(self, density):
        """Speichert Dichte sofort"""
        self.data["ui_density"] = density
        save_settings(self.data)
        self._apply_theme_now()

    def _save_accent(self, accent):
        """Speichert Akzentfarbe sofort ("" = Theme-Standard)"""
        self.data["ui_accent"] = str(accent or "")
        save_settings(self.data)
        self._apply_theme_now()

    def _on_accent_index_changed(self):
        self._save_accent(self.accent_combo.currentData())

    def _pick_accent(self):
        """Eigene Akzentfarbe über QColorDialog wählen."""
        cur = self.data.get("ui_accent") or ""
        initial = QColor(cur) if cur else QColor("#2f7cf6")
        color = QColorDialog.getColor(initial, self, "Akzentfarbe wählen")
        if not color.isValid():
            return
        accent = color.name()
        self.data["ui_accent"] = accent
        accent_index = self.accent_combo.findData(accent)
        if accent_index < 0:
            self.accent_combo.addItem(f"Eigene: {accent}", accent)
            accent_index = self.accent_combo.count() - 1
        self.accent_combo.setCurrentIndex(accent_index)
        save_settings(self.data)
        self._apply_theme_now()

    def _save_list_mode(self):
        """Speichert das Layout (Liste/Kompakt/Raster) sofort."""
        self.data["list_view_mode"] = str(
            self.list_mode_combo.currentData() or "list")
        save_settings(self.data)

    def _save_list_sort(self, text):
        """Speichert Sortierung der Dateiliste sofort"""
        self.data["list_sort"] = text
        save_settings(self.data)

    def _save_list_show_size(self, checked):
        self.data["list_show_size"] = bool(checked)
        save_settings(self.data)

    def _save_list_show_date(self, checked):
        self.data["list_show_date"] = bool(checked)
        save_settings(self.data)

    def _save_update_channel(self, channel):
        self.data["update_channel"] = (channel or "stable").lower()
        save_settings(self.data)

    def _apply_theme_now(self):
        """Wendet Theme + Akzentfarbe + Dichte sofort app-weit an.

        Bei einem tatsächlichen Theme-Wechsel wird das Stylesheet über eine
        kurze Fade-Überblendung getauscht (Hauptfenster + dieser Dialog).

        Lazy import, um zirkuläre Imports zu vermeiden.
        """
        try:
            from .theme_engine import build_stylesheet
            app = QApplication.instance()
            if app is None:
                return
            theme_name = self.data.get("theme", "Standard-dark")
            accent = str(self.data.get("ui_accent", "") or "")
            density = str(self.data.get("ui_density", "Mittel") or "Mittel")

            def _swap():
                app.setStyleSheet(build_stylesheet(theme_name, accent, density))

            fade_theme_swap(_swap, theme_name, extra_windows=(self,))
        except Exception as e:
            print(f"[SETTINGS] Live-Theme-Fehler: {e}")

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
