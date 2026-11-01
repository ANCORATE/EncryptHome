# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

"""
Erkennung von System-Schlaf/Lock-Zyklen zur sofortigen Tresor-Sperrung.

Prinzip:
  - Suspend/Resume wird plattform-unabhängig über den "monotonic-Stall"
    erkannt: time.monotonic() läuft während des Suspend nicht weiter.
    Springt die Wanduhr nach dem Aufwachen deutlich vor, während die
    monotone Uhr stillstand, war das System im Schlaf.

  - Auf Linux wird zusätzlich (falls `gdbus` vorhanden) das
    org.freedesktop.ScreenSaver-Interface überwacht (GNOME/KDE), um ein
    aktives Sperrbildschirm-Ereignis ("ActiveChanged: true") zu melden.
    Das ist optional und schadet nicht, wenn `gdbus` fehlt.

Kein externes Paket erforderlich. Das Monitor-Objekt lebt im GUI-Thread
(QTimer); der optionale gdbus-Thread emittiert über eine Queued-Verbindung,
die von PyQt automatisch thread-sicher vermittelt wird.
"""

import platform
import subprocess
import threading
import time

from PyQt6.QtCore import QObject, QTimer, pyqtSignal


class PowerLockMonitor(QObject):
    """Beobachtet Schlaf-/Lock-Zustände und meldet sie via `lockRequested`."""

    lockRequested = pyqtSignal()

    def __init__(self, parent=None, interval_ms: int = 5000, min_gap_s: float = 10.0):
        super().__init__(parent)
        self._interval_ms = interval_ms
        self._min_gap_s = min_gap_s
        self._timer = QTimer(self)
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._poll)
        self._last_wall = None
        self._last_mono = None
        self._gdbus_proc = None
        self._running = False

    def start(self):
        if self._running:
            return
        self._running = True
        self._last_wall = time.time()
        self._last_mono = time.monotonic()
        self._timer.start()
        self._start_gdbus_monitor()

    def stop(self):
        self._running = False
        self._timer.stop()
        proc = self._gdbus_proc
        self._gdbus_proc = None
        if proc is not None:
            try:
                proc.terminate()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Suspend/Resume-Erkennung über den monotonic-Stall
    # ------------------------------------------------------------------
    def _poll(self):
        wall = time.time()
        mono = time.monotonic()
        dw = wall - (self._last_wall if self._last_wall is not None else wall)
        dm = mono - (self._last_mono if self._last_mono is not None else mono)
        self._last_wall = wall
        self._last_mono = mono
        # Plateformunabhängige Detektion: monotone Uhr steht während des
        # Suspend, die Wanduhr springt danach vor.
        if dw >= self._min_gap_s and dm <= 0.25 * (dw - self._min_gap_s):
            self.lockRequested.emit()

    # ------------------------------------------------------------------
    # Optionaler Linux-Screensaver-Monitor (gdbus, GNOME/KDE)
    # ------------------------------------------------------------------
    def _start_gdbus_monitor(self):
        if platform.system() != "Linux":
            return
        import shutil

        if shutil.which("gdbus") is None:
            return
        try:
            proc = subprocess.Popen(
                [
                    "gdbus",
                    "monitor",
                    "--session",
                    "--dest",
                    "org.freedesktop.ScreenSaver",
                    "--object-path",
                    "/org/freedesktop/ScreenSaver",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except Exception:
            return
        self._gdbus_proc = proc
        threading.Thread(target=self._read_gdbus, args=(proc,), daemon=True).start()

    def _read_gdbus(self, proc):
        try:
            out = proc.stdout
            if out is None:
                return
            in_active_changed = False
            for line in iter(out.readline, ""):
                if "member=ActiveChanged" in line:
                    in_active_changed = True
                    continue
                if in_active_changed:
                    stripped = line.strip().lower()
                    # gdbus druckt den Wert z.B. als "   boolean     true" –
                    # deshalb whitespace-tolerant auf das letzte Wort prüfen.
                    if stripped.endswith("true"):
                        self.lockRequested.emit()
                        in_active_changed = False
                    elif stripped.endswith("false"):
                        in_active_changed = False
                    elif not stripped:
                        continue
        except Exception:
            pass
        finally:
            try:
                proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass