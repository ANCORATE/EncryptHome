# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# -*- coding: utf-8 -*-
"""Theme-Engine fuer ANCORATE EncryptHome.

Erzeugt aus Theme-Name, optionaler Akzentfarbe und Dichte-Einstellung
das fertige Qt-Stylesheet (QSS).

Konzept:
  - Jedes Theme besitzt eine Grundpalette (Token -> Farbwert).
  - Die Theme-CSS-Dateien verwenden Platzhalter wie {{accent}} / {{bg}}.
  - build_stylesheet() ersetzt die Platzhalter und skaliert optional die
    Schriftgroessen (Dichte). Kein Qt-Import noetig.
"""

import os
import re

THEMES_DIR = os.path.dirname(os.path.abspath(__file__))
THEME_DIR = os.path.join(THEMES_DIR, "themes")

THEME_FILES = {
    "Standard-dark": "standard-dark.css",
    "Standard-White": "standard-white.css",
    "High-Contrast": "high-contrast.css",
    "Midnight Blue": "midnight-blue.css",
}

DENSITY = {
    "Kompakt": 0.88,
    "Mittel": 1.0,
    "Komfortabel": 1.12,
}
DEFAULT_DENSITY = "Mittel"

PALETTES = {
    "Standard-dark": {
        "bg": "#0b0f16",
        "surface": "#0f1522",
        "surface-2": "#111827",
        "surface-soft": "#1a1f2e",
        "surface-hover": "#121a2b",
        "surface-hover-2": "#252b3d",
        "surface-pressed": "#0b1220",
        "surface-pressed-2": "#121622",
        "surface-focus": "#13203a",
        "menu-bg": "rgba(11,15,22,0.98)",
        "dialog-bg": "rgba(15,18,25,0.96)",
        "text": "#e6eef8",
        "text-dim": "#9fb0d8",
        "text-mid": "#cfd8ea",
        "text-faint": "#8a8f98",
        "text-disabled": "#3a4152",
        "accent": "#2f7cf6",
        "accent-hover": "#3f8cff",
        "accent-pressed": "#2265d1",
        "accent-soft": "#163a73",
        "on-soft": "#ffffff",
        "accent-focus": "#2a78ff",
        "on-accent": "#ffffff",
        "link": "#2f7cf6",
        "danger": "#dc2626",
        "danger-hover": "#ef4444",
        "danger-pressed": "#b91c1c",
        "success": "#10b981",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "border": "rgba(255,255,255,0.08)",
        "border-soft": "rgba(255,255,255,0.06)",
        "border-mid": "rgba(255,255,255,0.1)",
        "border-strong": "rgba(255,255,255,0.2)",
        "border-disabled": "#1a1f2a",
        "scroll-handle": "rgba(255,255,255,0.15)",
        "scroll-handle-hover": "rgba(255,255,255,0.3)",
        "menu-text": "#dcdcdc",
        "menu-selected": "#1f4fa3",
        "req-ok": "#6ee7b7",
        "welcome-title": "#1e88e5",
        "item-hover": "rgba(255,255,255,0.04)",
        "menu-sep": "rgba(255,255,255,0.08)",
        "welcome-sub": "rgba(200,215,235,0.71)",
        "border-dialog": "rgba(255,255,255,0.07)",
    },
    "Standard-White": {
        "bg": "#f4f6fa",
        "surface": "#ffffff",
        "surface-2": "#ffffff",
        "surface-soft": "#e8ecf1",
        "surface-hover": "#eef3ff",
        "surface-hover-2": "#dce0e6",
        "surface-pressed": "#e1eaff",
        "surface-pressed-2": "#ced3d9",
        "surface-focus": "#f7faff",
        "menu-bg": "#ffffff",
        "dialog-bg": "#ffffff",
        "text": "#1c2430",
        "text-dim": "#5c6a85",
        "text-mid": "#4a5568",
        "text-faint": "#8a8f98",
        "text-disabled": "#a0a6b2",
        "accent": "#2f7cf6",
        "accent-hover": "#3f8cff",
        "accent-pressed": "#2265d1",
        "accent-soft": "#dbe7ff",
        "on-soft": "#0f1e3a",
        "accent-focus": "#2a78ff",
        "on-accent": "#ffffff",
        "link": "#2f7cf6",
        "danger": "#dc2626",
        "danger-hover": "#ef4444",
        "danger-pressed": "#b91c1c",
        "success": "#059669",
        "warning": "#d97706",
        "error": "#dc2626",
        "border": "rgba(0,0,0,0.12)",
        "border-soft": "rgba(0,0,0,0.12)",
        "border-mid": "rgba(0,0,0,0.1)",
        "border-strong": "rgba(0,0,0,0.25)",
        "border-disabled": "#d0d4dc",
        "scroll-handle": "rgba(0,0,0,0.15)",
        "scroll-handle-hover": "rgba(0,0,0,0.3)",
        "item-hover": "rgba(0,0,0,0.04)",
        "menu-sep": "#d0d6e0",
        "welcome-sub": "rgba(70,90,120,1.0)",
        "menu-text": "#1c2430",
        "menu-selected": "#dbe7ff",
        "req-ok": "#16a34a",
        "welcome-title": "#2f7cf6",
        "border-dialog": "rgba(0,0,0,0.12)",
    },
    "High-Contrast": {
        "bg": "#000000",
        "surface": "#0a0a0a",
        "surface-2": "#141414",
        "surface-soft": "#1f1f1f",
        "surface-hover": "#1a1a1a",
        "surface-hover-2": "#262626",
        "surface-pressed": "#000000",
        "surface-pressed-2": "#101010",
        "surface-focus": "#1a1a1a",
        "menu-bg": "#000000",
        "dialog-bg": "#000000",
        "text": "#ffffff",
        "text-dim": "#dddddd",
        "text-mid": "#eeeeee",
        "text-faint": "#bbbbbb",
        "text-disabled": "#888888",
        "accent": "#ffd028",
        "accent-hover": "#ffdf5e",
        "accent-pressed": "#c9a600",
        "accent-soft": "#4a3a00",
        # Schwarz auf #4a3a00 ergibt nur 1.9:1 und macht ausgewaehlte Zeilen
        # und Menueeintraege unlesbar. Weiss erreicht 8.6:1.
        "on-soft": "#ffffff",
        "accent-focus": "#ffd028",
        "on-accent": "#000000",
        "link": "#ffd028",
        "danger": "#ff3b30",
        "danger-hover": "#ff6a5f",
        "danger-pressed": "#c4180f",
        "success": "#34c759",
        "warning": "#ffcc00",
        "error": "#ff3b30",
        "border": "rgba(255,255,255,0.4)",
        "border-soft": "rgba(255,255,255,0.3)",
        "border-mid": "rgba(255,255,255,0.5)",
        "border-strong": "rgba(255,255,255,0.8)",
        "border-disabled": "#555555",
        "scroll-handle": "rgba(255,255,255,0.4)",
        "scroll-handle-hover": "rgba(255,255,255,0.7)",
        "item-hover": "rgba(255,255,255,0.15)",
        "menu-sep": "rgba(255,255,255,0.4)",
        "welcome-sub": "rgba(255,255,255,0.75)",
        "menu-text": "#ffffff",
        "menu-selected": "#4a3a00",
        "req-ok": "#9dff6e",
        "welcome-title": "#ffd028",
        "border-dialog": "rgba(255,255,255,0.4)",
    },
    "Midnight Blue": {
        "bg": "#071224",
        "surface": "#0b1a33",
        "surface-2": "#0e2140",
        "surface-soft": "#132a4d",
        "surface-hover": "#10213d",
        "surface-hover-2": "#1a3358",
        "surface-pressed": "#0a1626",
        "surface-pressed-2": "#12213a",
        "surface-focus": "#122b4f",
        "menu-bg": "#0a1626",
        "dialog-bg": "#0a1626",
        "text": "#e6edf7",
        "text-dim": "#8ba3c9",
        "text-mid": "#b7c6de",
        "text-faint": "#7f91ad",
        "text-disabled": "#4a5a78",
        "accent": "#3b82f6",
        "accent-hover": "#60a5fa",
        "accent-pressed": "#2563eb",
        "accent-soft": "#1e3a8a",
        "on-soft": "#ffffff",
        "accent-focus": "#3b82f6",
        "on-accent": "#ffffff",
        "link": "#3b82f6",
        "danger": "#ef4444",
        "danger-hover": "#f87171",
        "danger-pressed": "#b91c1c",
        "success": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "border": "rgba(148,163,184,0.2)",
        "border-soft": "rgba(148,163,184,0.15)",
        "border-mid": "rgba(148,163,184,0.25)",
        "border-strong": "rgba(148,163,184,0.4)",
        "border-disabled": "#33415c",
        "scroll-handle": "rgba(148,163,184,0.3)",
        "scroll-handle-hover": "rgba(148,163,184,0.5)",
        "item-hover": "rgba(148,163,184,0.12)",
        "menu-sep": "rgba(148,163,184,0.2)",
        "welcome-sub": "rgba(160,180,215,0.6)",
        "menu-text": "#b7c6de",
        "menu-selected": "#1e3a8a",
        "req-ok": "#6ee7b7",
        "welcome-title": "#3b82f6",
        "border-dialog": "rgba(148,163,184,0.2)",
    },
}


def get_theme_names() -> list:
    return list(THEME_FILES)


def _hex_to_rgb(color: str) -> tuple:
    c = color.strip().lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    if len(c) != 6:
        raise ValueError(f"Ungueltige Hex-Farbe: {color}")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb: tuple) -> str:
    return "#" + "".join(f"{max(0, min(255, round(ch))):02x}" for ch in rgb)


def is_valid_accent(color: str) -> bool:
    if not isinstance(color, str) or not color.strip():
        return False
    c = color.strip().lstrip("#")
    if len(c) == 3:
        c = "".join(ch * 2 for ch in c)
    if len(c) != 6:
        return False
    try:
        int(c, 16)
        return True
    except ValueError:
        return False


def mix(c1: tuple, c2: tuple, t: float) -> tuple:
    return tuple(round(a + (b - a) * t) for a, b in zip(c1, c2))


def _apply_accent(palette: dict, accent: str) -> dict:
    """Ueberlagert die Akzentfarbe samt abgeleiteter Varianten."""
    p = dict(palette)
    if not is_valid_accent(accent):
        return p
    base = _hex_to_rgb(accent)
    white = (255, 255, 255)
    black = (0, 0, 0)
    surface_rgb = _hex_to_rgb(p["surface"])
    p["accent"] = _rgb_to_hex(base)
    p["accent-hover"] = _rgb_to_hex(mix(base, white, 0.15))
    p["accent-pressed"] = _rgb_to_hex(mix(base, black, 0.14))
    p["accent-soft"] = _rgb_to_hex(mix(base, surface_rgb, 0.30))
    p["accent-focus"] = _rgb_to_hex(mix(base, white, 0.06))
    p["link"] = _rgb_to_hex(base)
    return p


_FONT_RE = re.compile(r"(font-size:\s*)([\d.]+)(pt\b)")

# Haken-Bild fuer aktivierte Checkboxen. Qt kann keine Data-URIs in
# Stylesheets laden, daher werden kleine PNGs neben den CSS-Dateien gelegt
# und ueber {{check-image}} referenziert. Die Haekenfarbe richtet sich nach
# der Kontrastfarbe auf Akzentgrund (on-accent) des jeweiligen Themes.
_CHECK_IMAGES = {
    "black": "check-black.png",
    "white": "check-white.png",
}


def check_image_value(on_accent: str) -> str:
    """Liefert den url()-Wert fuer das Haken-Bild passend zur on-accent-Farbe."""
    try:
        r, g, b = _hex_to_rgb(on_accent)
    except Exception:
        r, g, b = 255, 255, 255
    name = _CHECK_IMAGES["black" if (r + g + b) / 3 < 128 else "white"]
    return 'url("%s")' % os.path.join(THEME_DIR, name).replace("\\", "/")


def scale_fonts(css: str, factor: float) -> str:
    """Skaliert alle pt-Schriftgroessen im Stylesheet um den Dichte-Faktor."""
    if abs(factor - 1.0) < 1e-9:
        return css

    def _rep(match):
        scaled = round(float(match.group(2)) * factor, 2)
        if scaled == int(scaled):
            scaled = int(scaled)
        return f"{match.group(1)}{scaled}{match.group(3)}"

    return _FONT_RE.sub(_rep, css)


def resolve_palette(theme_name: str = "Standard-dark", accent: str = "") -> dict:
    """Effektive Palette eines Themes inkl. benutzerdefinierter Akzentfarbe.

    Dieselbe Quelle speist das QSS (build_stylesheet) und die UI-Icons
    (utilities.ui_icons), damit beide exakt dieselben Farbtoken verwenden.
    """
    if theme_name not in THEME_FILES:
        theme_name = "Standard-dark"
    return _apply_accent(PALETTES.get(theme_name, PALETTES["Standard-dark"]),
                         accent)


def build_stylesheet(theme_name: str = "Standard-dark", accent: str = "",
                     density: str = DEFAULT_DENSITY) -> str:
    """Erzeugt das finale QSS fuer Theme + Akzentfarbe + Dichte."""
    if theme_name not in THEME_FILES:
        theme_name = "Standard-dark"
    palette = resolve_palette(theme_name, accent)
    css_path = os.path.join(THEME_DIR, THEME_FILES[theme_name])
    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()
    for key, value in palette.items():
        css = css.replace("{{" + key + "}}", value)
    css = css.replace("{{check-image}}", check_image_value(palette.get("on-accent", "#ffffff")))
    factor = DENSITY.get(density, DENSITY[DEFAULT_DENSITY])
    return scale_fonts(css, factor)