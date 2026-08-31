"""Windows screenshot/capture protection for EncryptHome windows.

The helper is deliberately optional and dependency-free outside PyQt6. On
non-Windows platforms it is a no-op so existing cross-platform behavior is
preserved.
"""

from __future__ import annotations

import ctypes
import platform
from typing import Any

from PyQt6.QtCore import QEvent, QObject


_WDA_EXCLUDEFROMCAPTURE = 0x00000011


def protect_window_from_capture(window: Any) -> bool:
    """Exclude a native window from supported Windows screen capture APIs.

    Returns True when Windows accepted the requested affinity and False when
    protection is unavailable or could not be applied. On non-Windows
    platforms this function is intentionally a no-op and returns False.
    """
    if platform.system() != "Windows":
        return False

    try:
        hwnd = int(window.winId())
    except (AttributeError, TypeError, ValueError):
        return False

    if not hwnd:
        return False

    try:
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
        if event.type() in (
            QEvent.Type.Show,
            QEvent.Type.WindowActivate,
        ):
            try:
                protect_window_from_capture(watched)
            except Exception:
                # Capture protection must never prevent a window from opening.
                pass
        return False


_capture_protection_filter: _CaptureProtectionFilter | None = None


def install_screenshot_protection(application: Any) -> None:
    """Install capture protection for all Qt top-level windows.

    Installation is idempotent. On non-Windows platforms the function does
    nothing, preserving the existing behavior completely.
    """
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
