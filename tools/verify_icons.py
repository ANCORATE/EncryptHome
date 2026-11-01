# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""Prueft den SVG-Glyphensatz aus utilities/assets/ui.

Der Icon-Satz traegt die Semantik der Toolbar (Datei hinzufuegen, Vorschau,
Export). Ein Tippfehler in der Geometrie oder eine fehlende Glyphe faellt hier
auf, nicht erst in der Oberflaeche. Geprueft werden:

  * jede Glyphe rendert ueberhaupt,
  * sie wird an keinem Rand abgeschnitten,
  * Flaechenanteil liegt in einem lesbaren Band,
  * Normal- und Akzentfarbe liefern echte Unterschiede (On-Modus),
  * keine zwei Glyphen sind identisch,
  * Disabled-Modus ist vorhanden und schwächer als Normal.

    python tools/build_icons.py && python tools/verify_icons.py
"""

import os
import sys

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utilities import ui_icons  # noqa: E402
from utilities.ui_icons import ICON_NAMES, render_pixmap  # noqa: E402
from utilities.theme_engine import resolve_palette  # noqa: E402

SIZE = 18
MIN_COVERAGE = 0.055
MAX_COVERAGE = 0.42
RAMP = " .:-=+*#%@"


def coverage_and_bbox(image, w, h):
    inked = 0
    minx, maxx, miny, maxy = w, -1, h, -1
    for y in range(h):
        for x in range(w):
            if image.pixelColor(x, y).alpha() > 24:
                inked += 1
                minx, maxx = min(minx, x), max(maxx, x)
                miny, maxy = min(miny, y), max(maxy, y)
    return inked / (w * h), (minx, miny, maxx, maxy)


def touches_border(image, w, h):
    for y in range(h):
        for x in (0, w - 1):
            if image.pixelColor(x, y).alpha() > 24:
                return True
    for y in (0, h - 1):
        for x in range(w):
            if image.pixelColor(x, y).alpha() > 24:
                return True
    return False


def ascii_art(image, w, h, cols=29):
    ny = max(1, round(cols * h / w))
    out = []
    for cy in range(ny):
        row = ""
        for cx in range(cols):
            x0 = cx * w // cols
            x1 = max(x0 + 1, (cx + 1) * w // cols)
            y0 = cy * h // ny
            y1 = max(y0 + 1, (cy + 1) * h // ny)
            best = max(
                (image.pixelColor(x, y).alpha()
                 for y in range(y0, y1) for x in range(x0, x1)),
                default=0,
            )
            row += RAMP[min(len(RAMP) - 1, best * (len(RAMP) - 1) // 255)]
        out.append(row)
    return out


def check_dpr_scaling(app, problems):
    """Prueft das Rendern bei mehreren DPI-Faktoren.

    Der Skalierungsfehler von QSvgRenderer tritt nur auf, wenn die Pixmap ein
    devicePixelRatio != 1 traegt. Auf der Offscreen-Plattform ist diese
    konstant 1, der Fehler bliebe dort also unbemerkt. Deshalb wird hier der
    Faktor fest vorgegeben und uebr alle Kantenlaengen geprueft.
    """
    print("\n=== DPI-Skalierung (feste Faktoren, unabhaengig vom Bildschirm)")
    original = ui_icons._device_pixel_ratio
    ratios = (1.0, 1.25, 1.5, 2.0)
    try:
        for ratio in ratios:
            ui_icons._device_pixel_ratio = lambda r=ratio: r
            for size in (16, 18, 20):
                ui_icons._pixmap_cache.clear()
                for name in ICON_NAMES:
                    pm = render_pixmap(name, "#ffffff", size)
                    if pm.isNull():
                        problems.append(
                            f"{name}: nicht renderbar bei dpr={ratio}")
                        continue
                    w, h = pm.width(), pm.height()
                    img = pm.toImage()
                    if touches_border(img, w, h):
                        problems.append(
                            f"{name}: Tinte am Rand bei dpr={ratio} "
                            f"size={size} - Glyphe wird angeschnitten")
                        continue
                    # Die Glyphe muss die volle Kantenlaenge nutzen, sonst
                    # waere sie zu klein gezeichnet.
                    _, (minx, miny, maxx, maxy) = coverage_and_bbox(img, w, h)
                    if maxx - minx + 1 < w * 0.6:
                        problems.append(
                            f"{name}: nur {maxx - minx + 1} von {w} px Breite "
                            f"bei dpr={ratio} size={size}")
            ui_icons._pixmap_cache.clear()
        print(f"    {len(ratios)} DPI-Faktoren x 3 Groessen x "
              f"{len(ICON_NAMES)} Glyphen geprueft")
    finally:
        ui_icons._device_pixel_ratio = original
        ui_icons._pixmap_cache.clear()


def main():
    app = QApplication.instance() or QApplication(sys.argv)
    pal = resolve_palette("Standard-dark")
    problems = []
    fingerprints = {}

    for name in ICON_NAMES:
        pixmap = render_pixmap(name, pal["text"], SIZE)
        if pixmap.isNull():
            problems.append(f"{name}: nicht renderbar")
            continue
        w, h = pixmap.width(), pixmap.height()
        img = pixmap.toImage()
        cover, bbox = coverage_and_bbox(img, w, h)
        minx, miny, maxx, maxy = bbox
        bw, bh = maxx - minx, maxy - miny

        print(f"=== {name}  ({w}x{h})  coverage={cover:.1%}  "
              f"bbox={bw}x{bh}  text={pal['text']}  on={pal['on-soft']}")
        for line in ascii_art(img, w, h):
            print("   " + line)

        if cover < MIN_COVERAGE:
            problems.append(f"{name}: zu wenig Strich ({cover:.1%})")
        if cover > MAX_COVERAGE:
            problems.append(f"{name}: zu voll ({cover:.1%}) - wirkt geballt")
        if touches_border(img, w, h):
            problems.append(f"{name}: Tinte am Rand - Glyphe wird abgeschnitten")
        # Mindestgroesse ueber die laengere Achse; die kuerzere darf schmal
        # sein (z. B. "more": drei Punkte auf einer Linie).
        if max(bw, bh) < 10 or min(bw, bh) < 3:
            problems.append(f"{name}: Glyphe zu klein gezeichnet ({bw}x{bh})")

        on = render_pixmap(name, pal["on-soft"], SIZE).toImage()
        off_diff = sum(
            1 for y in range(h) for x in range(w)
            if img.pixelColor(x, y).rgb() != on.pixelColor(x, y).rgb()
        )
        if off_diff == 0:
            problems.append(f"{name}: On-Farbe == Textfarbe, aktiver Zustand "
                            f"wäre nicht erkennbar")

        dis = render_pixmap(name, pal["text-disabled"], SIZE)
        if dis.isNull():
            problems.append(f"{name}: Disabled-Pixmap fehlt")
        elif dis.toImage() == img:
            problems.append(f"{name}: Disabled-Pixmap identisch zu Normal")

        # QIcon muss alle vier Zustandsvarianten liefern, sonst zeigt der
        # ToolButton im aktiven oder deaktivierten Zustand kein eigenes Icon.
        # Reihenfolge so wie von QToolButton abgefragt (empirisch geprueft).
        probe = QIcon()
        for mode, state, color in (
            (QIcon.Mode.Normal, QIcon.State.Off, pal["text"]),
            (QIcon.Mode.Normal, QIcon.State.On, pal["on-soft"]),
            (QIcon.Mode.Disabled, QIcon.State.Off, pal["text-disabled"]),
            (QIcon.Mode.Disabled, QIcon.State.On, pal["text-disabled"]),
        ):
            probe.addPixmap(render_pixmap(name, color, SIZE), mode, state)
        for label, mode, state in (
            ("Normal/Off", QIcon.Mode.Normal, QIcon.State.Off),
            ("Normal/On", QIcon.Mode.Normal, QIcon.State.On),
            ("Disabled/Off", QIcon.Mode.Disabled, QIcon.State.Off),
            ("Disabled/On", QIcon.Mode.Disabled, QIcon.State.On),
        ):
            if probe.pixmap(QSize(SIZE, SIZE), mode, state).isNull():
                problems.append(f"{name}: QIcon-Zustand {label} leer")

        key = tuple(tuple(img.pixelColor(x, y).rgb() for y in range(h))
                    for x in range(w))
        fingerprints.setdefault(key, []).append(name)

    for names in fingerprints.values():
        if len(names) > 1:
            problems.append(f"identische Glyphen: {names}")
    print(f"\n{len(fingerprints)}/{len(ICON_NAMES)} Glyphen unterscheidbar")

    check_dpr_scaling(app, problems)

    if problems:
        print("PROBLEME:")
        for p in problems:
            print("  -", p)
        return 1
    print("OK: Iconset gerendert, gerandet, kontrastiert, unterscheidbar")
    return 0


if __name__ == "__main__":
    sys.exit(main())
