"""Misst Layout-Metriken der Oberflaeche, die man sonst nur im Bild sieht.

Prueft Dinge, die sich rechnen lassen: Einheitlichkeit von Abstaenden und
Radien, Ausrichtung auf Achsen, Kontraste, Ueberlaeufe, Hoehen, leere
Elemente. Bewusst ohne Urteil, nur Messwerte.

    python tools/layout_audit.py
"""

import os
import sys

ROOT = r"C:\Users\samue\OneDrive\Desktop\EncryptHome"
sys.path.insert(0, ROOT)
os.environ.setdefault("QT_QPA_PLATFORM", "windows")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from app.main_window import App  # noqa: E402
from utilities.theme_engine import (build_stylesheet,  # noqa: E402
                                    resolve_palette)

app = QApplication.instance() or QApplication(sys.argv)
win = App()
win.setAttribute(Qt.WidgetAttribute.WA_DontShowOnScreen, True)
win.show()
app.processEvents()
win.resize(1200, 720)
win.master_key = b"\x00" * 32
win._set_vault_actions_enabled(True)
app.processEvents()

print("=" * 72)
print("1. VERTIKALE RYTHMEN (alles in Fensterkoordinaten)")
print("=" * 72)
bands = [
    ("Menue", win.menuBar()),
    ("Toolbar", win.toolbar),
    ("Kopfzeile", win.header),
    ("Dateiliste", win.view_stack),
    ("Statusleiste", win.statusBar()),
]
prev_bottom = 0
for name, w in bands:
    top_left = w.mapTo(win, w.rect().topLeft())
    g = w.geometry()
    y = top_left.y()
    print(f"  {name:14} y={y:4} h={g.height():4} "
          f"Abstand davor={y - prev_bottom:3} "
          f"endet bei {y + g.height():4}")
    prev_bottom = y + g.height()

print()
print("=" * 72)
print("2. BESCHRIFTUNGEN UND IHRE BREITEN")
print("=" * 72)
for action in (win.act_new, win.act_open, win.act_add, win.act_preview,
               win.act_export, win.act_delete, win.act_more):
    b = win.toolbar.widgetForAction(action)
    if b is None:
        continue
    print(f"  {action.iconText():16} Knopf {b.width():4}x{b.height():3} "
          f"Textbreite {b.fontMetrics().horizontalAdvance(b.text()):4} "
          f"Icon {b.iconSize().width():3} "
          f"Tooltip {action.toolTip()!r}")

print()
print("=" * 72)
print("3. SEGMENT-CONTROL (rechts in der Kopfzeile)")
print("=" * 72)
seg = win.view_segment
print(f"  Segment      {seg.width()}x{seg.height()} pos=({seg.x()},{seg.y()})")
for b in win._view_buttons:
    print(f"    {b.text():10} {b.width():3}x{b.height():3} "
          f"geprueft={b.isChecked()}")
print(f"  Suchfeld     {win.search.width()}x{win.search.height()} "
      f"pos=({win.search.x()},{win.search.y()}) max={win.search.maximumWidth()}")
print(f"  Kopfzeile    {win.header.width()}x{win.header.height()}")
print(f"  Abstand Segment->Suchfeld: {win.search.x() - seg.x() - seg.width()}px")
print(f"  Segment liegt rechtsbuendig: "
      f"{seg.x() + seg.width() + (win.search.x() - seg.x() - seg.width())}")

print()
print("=" * 72)
print("4. KOPFZEILE: VERTIKALE AUSRICHTUNG")
print("=" * 72)
h = win.header
cy = h.height() / 2
for name, w in (("Icon", win.header_icon), ("Segment", seg),
                ("Suchfeld", win.search)):
    g = w.geometry()
    center = g.y() + g.height() / 2
    print(f"  {name:12} h={g.height():3} mitte={center:6.1f} "
          f"abweichung={center - cy:+.1f}px")

print()
print("=" * 72)
print("5. KONTRASTE (WCAG) NACH THEMA")
print("=" * 72)


def lum(c):
    def f(v):
        v = v / 255.0
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return (0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]))


def ratio(a, b):
    la, lb = lum(a), lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def rgb(hx):
    hx = hx.lstrip("#")
    return tuple(int(hx[i:i + 2], 16) for i in (0, 2, 4))


def flat(hx):
    """rgba(...)-Werte auf eine opake Naeherung bringen."""
    hx = hx.strip()
    if hx.startswith("rgba"):
        nums = hx[hx.find("(") + 1:hx.find(")")].split(",")
        r, g, b = (int(float(n)) for n in nums[:3])
        a = float(nums[3]) if len(nums) > 3 else 1.0
        return tuple(round(c + (0x0b0f16 if True else 0) * 0) for c in (r, g, b))
    return rgb(hx)


for theme in ("Standard-dark", "Standard-White", "High-Contrast",
              "Midnight Blue"):
    p = resolve_palette(theme)
    surf = p["surface"]
    tests = [
        ("Text auf Hintergrund", p["text"], p["bg"]),
        ("Text auf Surface", p["text"], surf),
        ("Text auf Surface-weich", p["text"], p["surface-soft"]),
        ("Text auf Akzent", p["on-accent"], p["accent"]),
        ("Text auf Akzent-weich", p["on-soft"], p["accent-soft"]),
        ("Akzent auf Surface", p["accent"], surf),
        ("Akzent auf Hintergrund", p["accent"], p["bg"]),
        ("Text-mid auf Surface", p["text-mid"], surf),
        ("Text-dim auf Surface", p["text-dim"], surf),
        ("Text-faint auf Surface", p["text-faint"], surf),
        ("Deaktiviert auf Surface", p["text-disabled"], surf),
        ("Fehler auf Surface", p["error"], surf),
        ("Warnung auf Surface", p["warning"], surf),
        ("Erfolg auf Surface", p["success"], surf),
        ("Gefahr auf Surface", p["danger"], surf),
        ("Link auf Hintergrund", p["link"], p["bg"]),
        ("Menütext auf Menü", p["menu-text"], p["menu-bg"]),
    ]
    print(f"\n  {theme}  bg={p['bg']} surface={surf} "
          f"accent={p['accent']} on-soft={p['on-soft']}")
    for label, fg, bgc in tests:
        try:
            r = ratio(flat(fg), flat(bgc))
        except Exception as exc:  # pragma: no cover
            print(f"    {label:26} UNLESBAR {fg} ({exc})")
            continue
        if r >= 4.5:
            note = "AA Text"
        elif r >= 3.0:
            note = "nur >=18px/Grafik"
        else:
            note = "ZU SCHWACH"
        print(f"    {label:26} {fg:>22} auf {bgc:<22} {r:5.2f}:1  {note}")

print()
print("=" * 72)
print("6. DUPLIZIERTE WERTE IM STYLESHEET (Wartbarkeit)")
print("=" * 72)
import re  # noqa: E402
for theme in ("standard-dark", "standard-white", "high-contrast",
              "midnight-blue"):
    css = open(os.path.join(ROOT, "utilities", "themes", f"{theme}.css"),
               encoding="utf-8").read()
    props = re.findall(r"^\s*([a-z-]+)\s*:\s*([^;]+);", css, re.M)
    seen = {}
    for k, v in props:
        seen.setdefault((k, v.strip()), 0)
        seen[(k, v.strip())] += 1
    dups = sum(c - 1 for c in seen.values())
    print(f"  {theme:18} {len(props):4} Deklarationen, "
          f"{len(seen):4} eindeutige, {dups:3} Wiederholungen")

print()
print("=" * 72)
print("7. ICON-GROESSEN GEGEN TEXT")
print("=" * 72)
for w, label in ((win.toolbar, "Toolbar-Knopf"),
                 (win.search, "Suchfeld")):
    b = w.widgetForAction(win.act_add) if label.startswith("Toolbar") else w
    fm = b.fontMetrics()
    print(f"  {label:14} Icon {b.iconSize().width() if hasattr(b,'iconSize') else '-'}px "
          f"vs. Textzeilenhoehe {fm.height()}px  "
          f"(Icon sollte ~{round(fm.height() * 0.72)}px sein)")

win.close()
