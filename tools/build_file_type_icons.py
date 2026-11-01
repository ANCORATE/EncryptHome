# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""Generate the custom SVG icons used for vault file types."""

import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "utilities", "assets", "file_types")

ICONS = {
    "document": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#eaf2ff" stroke="#3574d4" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#cfe0ff" stroke="#3574d4" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M16 22h13M16 27h13M16 32h9M16 37h7" fill="none" stroke="#3574d4" stroke-width="2.4" stroke-linecap="round"/>''',
    "spreadsheet": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#e9f8ef" stroke="#23834d" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#c9efd7" stroke="#23834d" stroke-width="2.5" stroke-linejoin="round"/>
<rect x="14.5" y="20" width="17" height="15" rx="1.5" fill="#fff" stroke="#23834d" stroke-width="2"/>
<path d="M14.5 25h17M14.5 30h17M20.2 20v15M25.8 20v15" fill="none" stroke="#23834d" stroke-width="1.7"/>''',
    "presentation": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#fff0e8" stroke="#dc6b34" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#ffdcc8" stroke="#dc6b34" stroke-width="2.5" stroke-linejoin="round"/>
<rect x="14.5" y="21" width="17" height="12" rx="1.6" fill="#fff" stroke="#dc6b34" stroke-width="2"/>
<path d="M20 38h6M23 33v5M18 29l3-3 2.5 2 4-4" fill="none" stroke="#dc6b34" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>''',
    "pdf": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#fff0f0" stroke="#c74444" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#ffdada" stroke="#c74444" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M15 25h17M15 30h17M15 35h12" fill="none" stroke="#c74444" stroke-width="2.1" stroke-linecap="round"/>
<path d="M15 20h9" fill="none" stroke="#c74444" stroke-width="3" stroke-linecap="round"/>''',
    "video": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#fff0ef" stroke="#d34d46" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#ffd9d6" stroke="#d34d46" stroke-width="2.5" stroke-linejoin="round"/>
<rect x="13.5" y="20" width="19" height="14" rx="3" fill="#d34d46"/>
<path d="m21 23.5 6 3.5-6 3.5z" fill="#fff"/>''',
    "image": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#eaf8f6" stroke="#21877c" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#cdeee8" stroke="#21877c" stroke-width="2.5" stroke-linejoin="round"/>
<rect x="13.5" y="20" width="19" height="14" rx="2" fill="#fff" stroke="#21877c" stroke-width="2"/>
<circle cx="27.5" cy="24.5" r="2" fill="#e7ad46"/>
<path d="m15.5 31 5.5-5 3.5 3 2.5-2 3.5 4" fill="none" stroke="#21877c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>''',
    "audio": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#fff6e8" stroke="#bc7619" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#ffebc9" stroke="#bc7619" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M25 20v12.5a3.5 3.5 0 1 1-2-3.2V22l10-2v10.5a3.5 3.5 0 1 1-2-3.2V18z" fill="#bc7619"/>''',
    "archive": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#f4efff" stroke="#7351a8" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#e3d8f7" stroke="#7351a8" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M16 20h13v14H16z" fill="#fff" stroke="#7351a8" stroke-width="2" stroke-linejoin="round"/>
<path d="M19 20v3h3v3h-3v3h3v5M29 23h4v11h-4" fill="none" stroke="#7351a8" stroke-width="2" stroke-linejoin="round"/>''',
    "code": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#edf4f7" stroke="#496f82" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#d6e7ee" stroke="#496f82" stroke-width="2.5" stroke-linejoin="round"/>
<path d="m20 22-4 4 4 4M27 22l4 4-4 4M25 20l-3 12" fill="none" stroke="#496f82" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>''',
    "database": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#edf3ff" stroke="#4967a7" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#d9e4ff" stroke="#4967a7" stroke-width="2.5" stroke-linejoin="round"/>
<ellipse cx="23" cy="22" rx="7.5" ry="3.2" fill="#fff" stroke="#4967a7" stroke-width="2"/>
<path d="M15.5 22v10c0 1.8 3.4 3.2 7.5 3.2s7.5-1.4 7.5-3.2V22M15.5 27c0 1.8 3.4 3.2 7.5 3.2s7.5-1.4 7.5-3.2" fill="none" stroke="#4967a7" stroke-width="2"/>''',
    "model": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#f1f2f5" stroke="#606b7c" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#dfe2e8" stroke="#606b7c" stroke-width="2.5" stroke-linejoin="round"/>
<path d="m23 20 8 4.5v8L23 37l-8-4.5v-8z" fill="#fff" stroke="#606b7c" stroke-width="2" stroke-linejoin="round"/>
<path d="m15 24.5 8 4.6 8-4.6M23 29v8" fill="none" stroke="#606b7c" stroke-width="2" stroke-linejoin="round"/>''',
    "generic": '''<path d="M12 4.5h15l10 10v27H12a3 3 0 0 1-3-3v-31a3 3 0 0 1 3-3z" fill="#f1f3f5" stroke="#727b86" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M27 4.5v10h10" fill="#e0e4e8" stroke="#727b86" stroke-width="2.5" stroke-linejoin="round"/>
<path d="M17 23h14M17 28h14M17 33h9" fill="none" stroke="#727b86" stroke-width="2.5" stroke-linecap="round"/>''',
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, body in ICONS.items():
        source = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">\n'
            + "\n".join(f"  {line}" for line in body.splitlines())
            + "\n</svg>\n"
        )
        path = os.path.join(OUT, f"{name}.svg")
        with open(path, "w", encoding="utf-8", newline="\n") as svg_file:
            svg_file.write(source)
        print("wrote", os.path.relpath(path, ROOT))


if __name__ == "__main__":
    main()