#!/usr/bin/env python3
# Shared utility functions for ANCORATE EncryptHome

import os
import platform


def get_app_icon():
    """
    Lädt das passende Icon-Format für die aktuelle Plattform.
    """
    from PyQt6.QtGui import QIcon

    system = platform.system()
    icon_paths = []
    base_dir = os.path.dirname(os.path.abspath(__file__))

    if system == "Windows":
        icon_paths = [
            os.path.join(base_dir, "icon.ico"),
            os.path.join(base_dir, "icon.png"),
        ]
    else:
        icon_paths = [
            os.path.join(base_dir, "icon.png"),
            os.path.join(base_dir, "icon_64x64.png"),
            os.path.join(base_dir, "icon_48x48.png"),
            os.path.join(base_dir, "icon_32x32.png"),
        ]

    for path in icon_paths:
        if os.path.exists(path):
            return QIcon(path)

    return QIcon()
