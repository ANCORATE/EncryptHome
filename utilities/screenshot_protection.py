"""Windows screenshot/capture protection for EncryptHome windows.

The helper is deliberately optional and dependency-free. On non-Windows
platforms it is a no-op so existing cross-platform behavior is preserved.
"""

from __future__ import annotations

import ctypes
import platform
from typing import Any


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
