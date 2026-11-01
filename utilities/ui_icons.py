# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# -*- coding: utf-8 -*-
"""Themenabhaengige UI-Icons fuer ANCORATE EncryptHome.

Die Glyphen liegen als 24x24-SVGs in ``utilities/assets/ui`` und verwenden den
Platzhalter ``{{color}}``. Dieser Loader ersetzt ihn durch eine Farbe aus der
Theme-Palette und rendert die Glyphe ueber QSvgRenderer auf eine QPixmap.
QSS und Icons speisen sich damit aus derselben Palette
(``theme_engine.resolve_palette``), sodass Theme-, Akzent- und
Dichtewechsel die Icons ohne Codeaenderung mitziehen.

Jedes QIcon liefert die Zustandsvarianten fuer (Mode, State): Normal/Off,
Normal/On, Disabled/Off und Disabled/On. QToolButton fragt State.On ab, sobald
seine Aktion geprueft ist, und Mode.Disabled bei deaktivierter Aktion - so
bleibt der aktive Ansichtsmodus auch als Icon erkennbar und nicht nur als
Hintergrundfarbe des Stylesheets.

Warum eigene Glyphen statt QStyle-Standardpixmaps: die Standardpalette
kennt kein "Datei hinzufuegen", keine "Vorschau" und kein "Export" - dort
wurden fachlich falsche Icons (Pfeil "eine Ebene hoeher", Info-"i",
Speichern) eingesetzt.
"""

import os

from PyQt6.QtCore import QByteArray, QRectF, QSize, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPixmap
from PyQt6.QtGui import QGuiApplication

from .theme_engine import DEFAULT_DENSITY, DENSITY, resolve_palette

try:
    from PyQt6.QtSvg import QSvgRenderer
    _SVG_AVAILABLE = True
except ImportError:  # pragma: no cover - nur in defekten Installationen
    QSvgRenderer = None
    _SVG_AVAILABLE = False

ICONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "assets", "ui")

# Platzhalter, den jede Glyphe in ihren Attributen (stroke/fill) benutzt.
_COLOR_TOKEN = "{{color}}"

# Basisgroesse der Toolbar-Glyphen in logischen Pixeln; die Dichte skaliert.
BASE_ICON_SIZE = 18

ICON_NAMES = (
    "vault-new",
    "vault-open",
    "add-file",
    "preview",
    "export",
    "trash",
    "more",
    "view-list",
    "view-compact",
    "view-grid",
    # Zustandsglyphen der Kopfzeile. Keine Aktionssymbole wie die Gruppe
    # darueber: sie zeigen, ob eine Sitzung geoeffnet ist.
    "lock-closed",
    "lock-open",
)

_source_cache: dict = {}
_pixmap_cache: dict = {}
_theme_state = {"theme": "Standard-dark", "accent": "", "density": DEFAULT_DENSITY}
_missing_reported: set = set()

# Upper bound fuer die Pixmap-Caches. Jeder Theme-/Akzentwechsel liefert neue
# Farbschluessel; ohne Deckel wuerden die alten Eintraege stehen bleiben.
_CACHE_LIMIT = 256


def icon_size(density: str = DEFAULT_DENSITY) -> int:
    """Icon-Kantenlaenge in logischen Pixeln fuer die gewaehlte Dichte."""
    factor = DENSITY.get(density, DENSITY[DEFAULT_DENSITY])
    return max(14, int(round(BASE_ICON_SIZE * factor)))


def set_active_ui_theme(theme_name: str, accent: str = "",
                        density: str = DEFAULT_DENSITY) -> None:
    """Setzt Theme/Akzent/Dichte fuer nachfolgende Icon-Aufrufe.

    Wird bei jedem Themewechsel zusammen mit dem QSS-Aufbau ausgefuehrt, damit
    Icons und Stylesheet nie auseinanderlaufen.
    """
    changed = (theme_name, accent, density) != (
        _theme_state["theme"], _theme_state["accent"], _theme_state["density"]
    )
    _theme_state.update(theme=theme_name, accent=accent, density=density)
    if changed:
        _pixmap_cache.clear()


def active_icon_colors() -> dict:
    """Die drei Iconfarben (normal / aktiv / deaktiviert) des aktiven Themes.

    "on" ist bewusst ``on-soft`` und nicht ``accent``: der aktive Knopf der
    Segment-Control bekommt ``accent-soft`` als Hintergrund, und ``on-soft``
    ist exakt die Textfarbe, die das Stylesheet dort schon fuer
    ausgewaehlte Zeilen (QTreeWidget/QListWidget) verwendet. So ist der
    Kontrast identisch und die Iconfarbe weicht nicht vom Text ab.
    """
    palette = resolve_palette(_theme_state["theme"], _theme_state["accent"])
    return {
        "normal": palette.get("text", "#e6eef8"),
        "on": palette.get("on-soft", "#ffffff"),
        "disabled": palette.get("text-disabled", "#3a4152"),
    }


def icon_size_for_active_theme() -> int:
    """Icon-Kantenlaenge passend zur Dichte des aktiven Themes."""
    return icon_size(_theme_state["density"])


def has_icon(name: str) -> bool:
    """True, wenn die Glyphe vorhanden und renderbar ist."""
    return bool(_load_source(name))


def ui_icon(name: str, size: int | None = None) -> QIcon:
    """QIcon einer Glyphe mit Normal-, On- und Disabled-Pixmap."""
    icon = QIcon()
    if not _SVG_AVAILABLE or name not in ICON_NAMES:
        _report_missing(name)
        return icon
    px = int(size) if size else icon_size_for_active_theme()
    colors = active_icon_colors()
    # Qt 6 waehlt die Pixmap nach (Mode, State): ein gepruefter ToolButton
    # fragt State.On ab, ein deaktivierter Mode.Disabled. QIcon.Mode.On gibt
    # es seit Qt 6 nicht mehr.
    states = (
        (QIcon.Mode.Normal, QIcon.State.Off, colors["normal"]),
        (QIcon.Mode.Normal, QIcon.State.On, colors["on"]),
        (QIcon.Mode.Disabled, QIcon.State.Off, colors["disabled"]),
        (QIcon.Mode.Disabled, QIcon.State.On, colors["disabled"]),
    )
    for mode, state, color in states:
        pixmap = render_pixmap(name, color, px)
        if not pixmap.isNull():
            icon.addPixmap(pixmap, mode, state)
    return icon


def render_pixmap(name: str, color: str, size: int) -> QPixmap:
    """Rendert eine Glyphe in der Farbe ``color`` auf eine transparente Pixmap."""
    if not _SVG_AVAILABLE:
        return QPixmap()
    ratio = _device_pixel_ratio()
    key = (name, color.lower(), int(size), ratio)
    cached = _pixmap_cache.get(key)
    if cached is not None:
        return cached

    source = _load_source(name)
    if not source:
        return QPixmap()

    tint = color if QColor(color).isValid() else "#e6eef8"
    renderer = QSvgRenderer(
        QByteArray(source.replace(_COLOR_TOKEN, tint).encode("utf-8"))
    )
    if not renderer.isValid():
        _report_missing(name)
        return QPixmap()

    edge = max(1, int(round(size * ratio)))
    pixmap = QPixmap(edge, edge)
    pixmap.setDevicePixelRatio(ratio)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    # Wichtig: render(painter) allein benutzt painter.window(), also die
    # logarithmische Groesse der Pixmap (edge / ratio). Die viewBox wird dann
    # in zu kleine Koordinaten gesetzt und die Glyphe skaliert zu gross - sie
    # reicht bis in den letzten Randpixel und wirkt angeschnitten. Der
    # explizite Zielrechteck in logischen Koordinaten ist die korrekte
    # Angabe; der DPR-Faktor steckt bereits in der Pixmap.
    renderer.render(painter, QRectF(0.0, 0.0, float(size), float(size)))
    painter.end()

    if len(_pixmap_cache) >= _CACHE_LIMIT:
        _pixmap_cache.clear()
    _pixmap_cache[key] = pixmap
    return pixmap


def icon_size_hint(size: int | None = None) -> QSize:
    """QSize der Icon-Kantenlaenge (fuer setIconSize)."""
    px = int(size) if size else icon_size_for_active_theme()
    return QSize(px, px)


def clear_icon_caches() -> None:
    """Verwirft Quell- und Pixmap-Cache (nur fuer Tests/Theme-Wechsel)."""
    _source_cache.clear()
    _pixmap_cache.clear()
    _missing_reported.clear()


def _load_source(name: str) -> str:
    source = _source_cache.get(name)
    if source is not None:
        return source
    path = os.path.join(ICONS_DIR, f"{name}.svg")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError:
        _report_missing(name)
        return ""
    if _COLOR_TOKEN not in raw:
        _report_missing(name)
        return ""
    _source_cache[name] = raw
    return raw


def _report_missing(name: str) -> None:
    """Meldet eine fehlende Glyphe genau einmal pro Prozess."""
    if name in _missing_reported:
        return
    _missing_reported.add(name)
    if not _SVG_AVAILABLE:
        print("[ICONS] PyQt6.QtSvg fehlt - Toolbar-Icons deaktiviert")
    else:
        print(f"[ICONS] Glyphe fehlt oder ist ungueltig: {name}")


def _device_pixel_ratio() -> float:
    try:
        screen = QGuiApplication.primaryScreen()
        if screen is None:
            return 1.0
        return float(screen.devicePixelRatio()) or 1.0
    except Exception:
        return 1.0
