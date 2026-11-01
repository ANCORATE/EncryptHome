#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# Shared utility functions for ANCORATE EncryptHome

import os
import platform

# Bild-Assets liegen gebuendelt unter utilities/assets. Die Icons der
# Oberflaeche (SVG-Glyphs) sind davon getrennt unter assets/ui.
ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "assets")


def get_app_icon():
    """
    Lädt das passende Icon-Format für die aktuelle Plattform.
    """
    from PyQt6.QtGui import QIcon

    system = platform.system()
    icon_dir = os.path.join(ASSETS_DIR, "app")
    icon_paths = []

    if system == "Windows":
        icon_paths = [
            os.path.join(icon_dir, "icon.ico"),
            os.path.join(icon_dir, "icon.png"),
        ]
    else:
        icon_paths = [
            os.path.join(icon_dir, "icon.png"),
            os.path.join(icon_dir, "icon_64x64.png"),
            os.path.join(icon_dir, "icon_48x48.png"),
            os.path.join(icon_dir, "icon_32x32.png"),
        ]

    for path in icon_paths:
        if os.path.exists(path):
            return QIcon(path)

    return QIcon()
