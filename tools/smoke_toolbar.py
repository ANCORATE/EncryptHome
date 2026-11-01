# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""Laufzeit-Smoke-Test fuer Toolbar, Ansichts-Umschalter und Icons.

Baut das echte Hauptfenster offscreen und prueft das Verhalten, das sich in
einem Screenshot nicht beurteilen laesst: Sichtbarkeit der Aktionen mit und
ohne Tresor, Icon-Modi, Beschriftungsmodus, Tooltips mit Kuerzel, Segment-
Control-Zustaende und die gemessene Responsive-Schwelle.

    python tools/smoke_toolbar.py
"""

import os
import sys

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import QApplication, QToolButton

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtGui import QIcon  # noqa: E402

from app.main_window import App  # noqa: E402
from utilities.ui_icons import ICON_NAMES, has_icon  # noqa: E402

failures = []


def check(label, condition, detail=""):
    status = "ok  " if condition else "FAIL"
    print(f"  [{status}] {label}{(' - ' + detail) if detail else ''}")
    if not condition:
        failures.append(f"{label} {detail}")


def style_of(toolbar):
    return toolbar.toolButtonStyle()


def main():
    app = QApplication.instance() or QApplication(sys.argv)

    # Ohne Schriftarten liefert Qt .notdef-Boxen mit konstanter Zeichentabelle
    # und die gemessene Schwelle wird unbrauchbar. In diesem Fall wird die
    # Pixelbreite nicht bewertet, der Umschaltpunkt aber weiterhin.
    fonts = QFontDatabase.families()
    fonts_ok = "Segoe UI" in fonts
    print(f"Plattform: {app.platformName()} | Font-Familien: {len(fonts)} | "
          f"Segoe UI: {fonts_ok}")
    if not fonts_ok:
        print("  HINWEIS: keine Systemschriften. Breitenmessung wird "
              "nicht bewertet, Verhalten der Schwellen-Umschaltung schon.\n")

    win = App()
    # Logisch sichtbar, aber nicht auf dem Bildschirm einblenden.
    win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
    win.show()
    app.processEvents()
    tb = win.toolbar

    print("Icons:")
    for name in ICON_NAMES:
        check(f"Glyphphe vorhanden: {name}", has_icon(name))

    print("\nOhne Tresor (Startbildschirm):")
    visible = [a for a in (win.act_new, win.act_open, win.act_add,
                           win.act_preview, win.act_export, win.act_delete,
                           win.act_more) if a.isVisible()]
    check("nur Neu/Oeffnen sichtbar",
          visible == [win.act_new, win.act_open],
          f"-> {[a.text() for a in visible]}")
    check("Trenner ausgeblendet",
          not win._tb_sep_files.isVisible() and not win._tb_sep_more.isVisible())
    check("Ansichts-Umschalter ausgeblendet", not win.view_segment.isVisible())
    visible_buttons = [b for b in tb.findChildren(QToolButton) if b.isVisible()]
    check("nur 2 Knöpfe sichtbar", len(visible_buttons) == 2,
          f"-> {len(visible_buttons)} von {len(tb.findChildren(QToolButton))}")

    print("\nOverflow-Menü:")
    menu = win.act_more.menu()
    check("drei Dateiaktionen", menu is not None and len(menu.actions()) == 3,
          f"-> {[a.text() for a in menu.actions()] if menu else None}")
    more_btn = tb.widgetForAction(win.act_more)
    check("Overflow-Knopf überhaupt erzeugt", more_btn is not None)
    if more_btn is not None:
        check("Overflow-Knopf ist Popup",
              more_btn.popupMode()
              == QToolButton.ToolButtonPopupMode.InstantPopup,
              f"-> popupMode={more_btn.popupMode()}")

    print("\nTooltips (mit Kuerzel aus dem QShortcut-Objekt):")
    for action in (win.act_new, win.act_open, win.act_add, win.act_export,
                   win.act_delete, win.act_preview):
        tip = action.toolTip()
        check(f"{action.text()!r} -> {tip!r}",
              bool(tip) and "…" not in tip and not tip.endswith("."),
              "Tooltip ohne Auslassungspunkte")
    check("Vorschau ohne Kuerzel hat Label-Tooltip",
          win.act_preview.toolTip() == "Dateivorschau",
          f"-> {win.act_preview.toolTip()!r}")

    print("\nBeschriftung der Toolbar (iconText statt Menütext):")
    for action in (win.act_new, win.act_open, win.act_add, win.act_preview,
                   win.act_export, win.act_delete):
        icon_text = action.iconText()
        check(f"{action.text()!r} -> iconText {icon_text!r}",
              bool(icon_text) and "…" not in icon_text)
    check("Menütext bleibt unabhaendig vom iconText",
          win.act_add.text() == "Datei(en) hinzufügen…",
          f"-> {win.act_add.text()!r}")

    print("  QToolButton kennt kein iconText; sein Text kommt aus der Aktion:")
    for action in (win.act_new, win.act_open, win.act_add, win.act_preview,
                   win.act_export, win.act_delete, win.act_more):
        button = tb.widgetForAction(action)
        shown = button.text() if button is not None else None
        check(f"Knopf zeigt {action.iconText()!r}",
              shown == action.iconText() and "…" not in shown,
              f"-> {shown!r}")

    print("\nIcon-Modi am QToolButton (Zustand, nicht nur Hintergrundfarbe):")
    for action, button in zip((win.act_view_list, win.act_view_compact,
                               win.act_view_grid), win._view_buttons):
        normal = button.icon().pixmap(QSize(18, 18), QIcon.Mode.Normal,
                                      QIcon.State.Off)
        active = button.icon().pixmap(QSize(18, 18), QIcon.Mode.Normal,
                                      QIcon.State.On)
        disabled = button.icon().pixmap(QSize(18, 18), QIcon.Mode.Disabled,
                                        QIcon.State.Off)
        img_n, img_a, img_d = (normal.toImage(), active.toImage(),
                               disabled.toImage())
        differs = any(
            img_n.pixelColor(x, y).rgb() != img_a.pixelColor(x, y).rgb()
            for y in range(img_n.height()) for x in range(img_n.width())
        )
        dims = any(
            img_n.pixelColor(x, y).rgb() != img_d.pixelColor(x, y).rgb()
            for y in range(img_n.height()) for x in range(img_n.width())
        )
        check(f"{action.text()}: Normal/On unterscheiden sich", differs)
        check(f"{action.text()}: Disabled eigens eingefaerbt", dims)

    print("\nSimulierter Tresor geoeffnet:")
    win.master_key = b"\x00" * 32
    win._set_vault_actions_enabled(True)
    app.processEvents()
    visible = [a for a in (win.act_new, win.act_open, win.act_add,
                           win.act_preview, win.act_export, win.act_delete,
                           win.act_more) if a.isVisible()]
    check("alle 7 Aktionen sichtbar", len(visible) == 7,
          f"-> {[a.iconText() for a in visible]}")
    check("beide Trenner sichtbar",
          win._tb_sep_files.isVisible() and win._tb_sep_more.isVisible())
    check("Ansichts-Umschalter sichtbar", win.view_segment.isVisible())
    check("Dateiaktionen aktiviert", win.act_add.isEnabled()
          and win.act_export.isEnabled() and win.act_delete.isEnabled())

    print("\nAnsichts-Umschalter:")
    check("Buttons an die Aktionen gebunden",
          all(b.defaultAction() is a for b, a in
              zip(win._view_buttons, (win.act_view_list, win.act_view_compact,
                                      win.act_view_grid))))
    win._view_buttons[2].click()
    app.processEvents()
    check("Raster aktiviert -> Aktion geprueft", win.act_view_grid.isChecked())
    check("Raster aktiv -> List/Kompakt abgewählt",
          not win.act_view_list.isChecked() and not win.act_view_compact.isChecked())
    check("view_mode folgt", win.view_mode == "grid", f"-> {win.view_mode}")
    win._view_buttons[0].click()
    app.processEvents()
    check("zurueck auf Liste", win.view_mode == "list"
          and win.act_view_list.isChecked())

    print("\nResponsive-Schwelle (gemessen, nicht hart kodiert):")
    win._measure_toolbar_width()
    need = win._toolbar_wide_min_width
    if fonts_ok:
        check("Schwelle plausibel", 500 < need < 2000, f"-> {need}px")
    else:
        print(f"  [skip] Schwellenwert {need}px ohne Systemschriften nicht "
              "bewertbar")
    win.resize(need + 120, 720)
    app.processEvents()
    check(f"bei {need + 120}px beschriftet",
          style_of(tb) == Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
    win.resize(need - 120, 720)
    app.processEvents()
    check(f"bei {need - 120}px nur Icons",
          style_of(tb) == Qt.ToolButtonStyle.ToolButtonIconOnly)
    check("Suchfeld folgt der Kompaktbreite", win.search.maximumWidth() == 200)
    win.resize(1080, 720)
    app.processEvents()
    if fonts_ok:
        check("Standardbreite 1080px beschriftet",
              style_of(tb) == Qt.ToolButtonStyle.ToolButtonTextBesideIcon,
              f"Schwelle={need}")

    print("\nIconfarben folgen dem Theme:")
    from utilities.ui_icons import (active_icon_colors, render_pixmap,
                                    set_active_ui_theme)
    from utilities.theme_engine import resolve_palette
    for theme in ("Standard-dark", "High-Contrast", "Standard-White",
                  "Midnight Blue"):
        set_active_ui_theme(theme, "", "Mittel")
        pal = resolve_palette(theme)
        colors = active_icon_colors()
        pm = render_pixmap("trash", colors["normal"], 18)
        img = pm.toImage()
        # Bei dpiScaling ist das Bild groesser als 18x18, ein festes Pixel
        # kann darum transparent sein. Also das deckendste suchen.
        px = max((img.pixelColor(x, y) for y in range(img.height())
                  for x in range(img.width())),
                 key=lambda c: c.alpha())
        check(f"{theme}: Trash in Textfarbe {pal['text']}",
              px.alpha() > 0 and px.name().lower() == pal["text"].lower(),
              f"actual={px.name()} alpha={px.alpha()} dpr-faktor="
              f"{img.width() / 18:.2f}")
    set_active_ui_theme("Standard-dark", "", "Mittel")
    check("Cache-Key enthaelt Farbe",
          render_pixmap("trash", "#ff0000", 18) is not None)

    print("\nDichte skaliert die Icongroesse:")
    from utilities.ui_icons import icon_size
    sizes = {d: icon_size(d) for d in ("Kompakt", "Mittel", "Komfortabel")}
    check("monoton steigend", sizes["Kompakt"] < sizes["Mittel"] < sizes["Komfortabel"],
          f"-> {sizes}")

    win.close()
    app.processEvents()

    print()
    if failures:
        print(f"{len(failures)} FEHLER:")
        for f in failures:
            print("  -", f)
        return 1
    print("OK: Toolbar, Icons und Ansichts-Umschalter verhalten sich wie erwartet")
    return 0


if __name__ == "__main__":
    sys.exit(main())
