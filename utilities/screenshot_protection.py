# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""Optional screenshot/capture protection for EncryptHome Qt windows.

Windows-only implementation. On Linux and macOS this module is safe to
import and all public operations are no-ops. The vault and encryption code
are not involved.
"""

from __future__ import annotations

import platform
from typing import Any

from PyQt6.QtCore import QEvent, QObject


_WDA_EXCLUDEFROMCAPTURE = 0x00000011


def protect_window_from_capture(window: Any) -> bool:
    """Apply Windows capture exclusion to one Qt window when supported."""
    if platform.system() != "Windows":
        return False

    try:
        import ctypes

        hwnd = int(window.winId())
        if not hwnd:
            return False

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        set_window_display_affinity = user32.SetWindowDisplayAffinity
        set_window_display_affinity.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        set_window_display_affinity.restype = ctypes.c_bool
        return bool(
            set_window_display_affinity(
                ctypes.c_void_p(hwnd), _WDA_EXCLUDEFROMCAPTURE
            )
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return False


class _CaptureProtectionFilter(QObject):
    """Apply capture protection when EncryptHome creates/shows a Qt window."""

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Type.Show, QEvent.Type.WindowActivate):
            try:
                protect_window_from_capture(watched)
            except Exception:
                # Capture protection must never prevent a window from opening.
                pass
        return False


_capture_protection_filter: _CaptureProtectionFilter | None = None

_WDA_NONE = 0x00000000


def uninstall_screenshot_protection(application: Any) -> None:
    """Remove Windows capture protection from all EncryptHome windows."""
    global _capture_protection_filter

    if platform.system() != "Windows":
        return

    if _capture_protection_filter is not None:
        application.removeEventFilter(_capture_protection_filter)
        _capture_protection_filter = None

    for widget in application.topLevelWidgets():
        try:
            _remove_capture_protection(widget)
        except Exception:
            pass


def _remove_capture_protection(window: Any) -> bool:
    """Remove Windows capture exclusion from one Qt window."""
    if platform.system() != "Windows":
        return False

    try:
        import ctypes

        hwnd = int(window.winId())
        if not hwnd:
            return False

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        set_window_display_affinity = user32.SetWindowDisplayAffinity
        set_window_display_affinity.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        set_window_display_affinity.restype = ctypes.c_bool
        return bool(
            set_window_display_affinity(ctypes.c_void_p(hwnd), _WDA_NONE)
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def install_screenshot_protection(application: Any) -> None:
    """Install optional Windows capture protection for Qt top-level windows."""
    global _capture_protection_filter

    if platform.system() != "Windows":
        return

    if _capture_protection_filter is None:
        _capture_protection_filter = _CaptureProtectionFilter(application)
        application.installEventFilter(_capture_protection_filter)

    for widget in application.topLevelWidgets():
        try:
            protect_window_from_capture(widget)
        except Exception:
            pass
