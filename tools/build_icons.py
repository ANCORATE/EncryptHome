"""Erzeugt den SVG-Glyphensatz in utilities/assets/ui.

Die Toolbar-Icons liegen als 24x24-SVGs mit dem Platzhalter {{color}} vor
(siehe utilities/ui_icons.py). Die Geometrie wird hier zentral gehalten, damit
alle Glyphen Strichstaerke, Radius und viewBox teilen. Nach jeder Aenderung:

    python tools/build_icons.py && python tools/verify_icons.py
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "utilities", "assets", "ui")

HEAD = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">\n'
    '  <g fill="none" stroke="{{color}}" stroke-width="1.7" '
    'stroke-linecap="round" stroke-linejoin="round">\n'
)
TAIL = "  </g>\n</svg>\n"

GLYPHS = {
    "vault-new": [
        '<rect x="4.2" y="4.2" width="15.6" height="15.6" rx="2.6"/>',
        '<path d="M9.4 12h5.2M12 9.4v5.2"/>',
    ],
    "vault-open": [
        '<rect x="4.2" y="4.2" width="15.6" height="15.6" rx="2.6"/>',
        '<path d="M12 8.2v6.8M9.2 11.8 12 14.6l2.8-2.8"/>',
    ],
    "add-file": [
        '<path d="M13.6 3.4H7.8A1.9 1.9 0 0 0 5.9 5.3v13.4a1.9 1.9 0 0 0 1.9 1.9h8.4'
        'a1.9 1.9 0 0 0 1.9-1.9V8.2z"/>',
        '<path d="M13.6 3.4v4.8h4.8"/>',
        '<path d="M12 11.6v5M9.5 14.1h5"/>',
    ],
    "preview": [
        '<path d="M2.6 12S6.1 6.4 12 6.4 21.4 12 21.4 12 17.9 17.6 12 17.6 2.6 12 2.6 12z"/>',
        '<circle cx="12" cy="12" r="2.7"/>',
    ],
    "export": [
        '<path d="M5.6 15.2v3.4a1.5 1.5 0 0 0 1.5 1.5h9.8a1.5 1.5 0 0 0 1.5-1.5v-3.4"/>',
        '<path d="M7.5 10.7 12 6.2l4.5 4.5"/>',
        '<path d="M12 6.6v9.2"/>',
    ],
    "trash": [
        '<path d="M4.4 6.9h15.2"/>',
        '<path d="M9.5 6.9V5.2a1.3 1.3 0 0 1 1.3-1.3h2.4a1.3 1.3 0 0 1 1.3 1.3v1.7"/>',
        '<path d="M6.4 6.9l.9 12.2a1.5 1.5 0 0 0 1.5 1.4h6.4a1.5 1.5 0 0 0 1.5-1.4'
        'l.9-12.2"/>',
        '<path d="M10.4 10.8v6.1M13.6 10.8v6.1"/>',
    ],
    "more": [
        '<circle cx="5.6" cy="12" r="1.9" fill="{{color}}" stroke="none"/>',
        '<circle cx="12" cy="12" r="1.9" fill="{{color}}" stroke="none"/>',
        '<circle cx="18.4" cy="12" r="1.9" fill="{{color}}" stroke="none"/>',
    ],
    "view-list": [
        '<path d="M4.2 6.6h15.6M4.2 12h15.6M4.2 17.4h15.6"/>',
    ],
    "view-compact": [
        '<path d="M4.2 8.6h15.6M4.2 15.4h15.6"/>',
    ],
    "view-grid": [
        '<rect x="4" y="4" width="6.1" height="6.1" rx="1.6"/>',
        '<rect x="13.9" y="4" width="6.1" height="6.1" rx="1.6"/>',
        '<rect x="4" y="13.9" width="6.1" height="6.1" rx="1.6"/>',
        '<rect x="13.9" y="13.9" width="6.1" height="6.1" rx="1.6"/>',
    ],
    # Zustandsglyphen fuer die Kopfzeile, keine Aktionsglyphen. "vault-new" und
    # "vault-open" stehen fuer Aktionen (Tresor anlegen / importieren), diese
    # beiden fuer den Zustand der Sitzung (verschlossen / offen). Beide teilen
    # den Koerper, nur der Buendel differsenziert - dadurch bleibt der
    # Wechsel auch bei 28 px eindeutig.
    "lock-closed": [
        '<rect x="5.2" y="10.5" width="13.6" height="10.1" rx="2.6"/>',
        '<path d="M8.4 10.3V7.9a3.6 3.6 0 0 1 7.2 0v2.4"/>',
        '<circle cx="12" cy="14.7" r="1.3"/>',
        '<path d="M12 16v2"/>',
    ],
    "lock-open": [
        '<rect x="5.2" y="10.5" width="13.6" height="10.1" rx="2.6"/>',
        '<path d="M9.7 10.3V7.9a3.6 3.6 0 0 1 6.9-1"/>',
        '<circle cx="12" cy="14.7" r="1.3"/>',
        '<path d="M12 16v2"/>',
    ],
}

for name, body in GLYPHS.items():
    os.makedirs(OUT, exist_ok=True)
    lines = [HEAD.rstrip("\n")]
    lines.extend("    " + line for line in body)
    lines.append(TAIL.rstrip("\n"))
    with open(os.path.join(OUT, name + ".svg"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote", os.path.join("utilities", "assets", "ui", name + ".svg"))
