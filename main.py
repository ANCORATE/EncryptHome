#!/usr/bin/env python3
# ANCORATE EncryptHome
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
# IF YOU ARE READING OR MODIFYING THIS CODE WITHOUT AUTHORIZATION, YOU ARE IN VIOLATION OF COPYRIGHT LAW.
# This code is part of the ANCORATE Encryption Suite. Unauthorized distribution or modification is prohibited.
# -------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------------------------------------------------------

# ============================================================
# Einstiegspunkt
# ============================================================
# main.py bleibt der Einstiegspunkt. Der gesamte Code wurde in
# das app-Paket mit logisch sortierten Modulen aufgeteilt:
#    - app/core.py           Konstanten + Standalone-Helfer
#    - app/passwords.py      Passwort-Dialoge
#    - app/workers.py        Worker-Threads + Export
#    - app/dialogs.py        Dialoge + Widgets
#    - app/main_window.py    Hauptfenster (App)
#
# Alle Symbole werden hier re-exportiert, damit bestehende
# Importe (z. B. "from main import ...") unveraendert funktionieren.
#

from app.core import *
from app.passwords import *
from app.workers import *
from app.dialogs import *
from app.main_window import App

# In app.dialogs definierte Symbole fuer Re-Export bereitstellen
from app.dialogs import (
    SetupDialog, LoginDialog, VaultEntry, FileDropList, FileTree, FileGrid,
    UpdateNewsDialog, DetailsDialog, AboutDialog,
    TermsOfServiceDialog, WelcomeOverlay, OnboardingDialog,
)

# In app.workers definierte Symbole fuer Re-Export bereitstellen
from app.workers import (
    AddWorker, ExportWorker, ExportBatchWorker,
    export_entry_to_path, StartupUpdateWorker,
)

# In app.passwords definierte Symbole fuer Re-Export bereitstellen
from app.passwords import get_password_with_requirements, change_container_password

# In app.core definierte Symbole (breiter Re-Export) - bereits via app importiert


def main():
    import sys
    import threading

    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QDialog, QMessageBox, QStyleFactory
    from utilities.screenshot_protection import install_screenshot_protection
    from utilities.settings import load_settings

    print(f"ANCORATE {edition} {version} - Initializing...", flush=True)

    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    app.setStyleSheet(APP_STYLE)

    # Protect EncryptHome-owned windows from supported Windows screen capture APIs.
    # The helper is a no-op on non-Windows platforms. Controlled by the
    # "Bildschirmaufnahmen blockieren" setting in the settings dialog.
    if load_settings().get("screenshot_protection", True):
        install_screenshot_protection(app)

    # =========================
    # Device registration check
    # =========================
    device_key = load_device_key()

    if not device_key:
        QMessageBox.critical(None, "ANCORATE", "Device fingerprint generation failed.\nPlease check your system configuration.")
        sys.exit(1)

    # No new setup required: device already registered, auto-login and skip
    # the startup animation, welcome, TOS and login dialogs.
    if is_device_registered():
        window = App()
        window.show()
        print("MAIN WINDOW SHOWN", flush=True)

        # Background update check (integrity) starts immediately in a worker thread
        QTimer.singleShot(0, window.start_update_check)

        # keep_search waits internally for the GUI to be ready, so start it now
        # instead of adding a fixed 2s startup delay.
        QTimer.singleShot(0, lambda: threading.Thread(target=window.keep_search, daemon=True).start())

        print("ENTER EVENT LOOP", flush=True)
        sys.exit(app.exec())

    # New device: show welcome dialog
    welcome = WelcomeOverlay()
    welcome.exec()

    # Erst-Start-Onboarding: Sicherheitsmodell & Gerätebindung erklären
    OnboardingDialog().exec()

    # Show TOS only for new devices
    tos = TermsOfServiceDialog()
    if tos.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    setup = SetupDialog()
    if setup.exec() != QDialog.DialogCode.Accepted:
        sys.exit(0)

    # Login with setup relaunch handling
    while True:
        login = LoginDialog()
        result = login.exec()

        if result == QDialog.DialogCode.Accepted:
            break  # Login successful, proceed
        elif hasattr(login, 'relaunch_setup') and login.relaunch_setup:
            # Setup was requested, show setup dialog
            setup = SetupDialog()
            if setup.exec() != QDialog.DialogCode.Accepted:
                sys.exit(0)
            # Continue loop to show login again
        else:
            sys.exit(0)  # User cancelled login

    print("LOGIN OK", flush=True)

    window = App()
    window.show()
    print("MAIN WINDOW SHOWN", flush=True)

    # Background update check (integrity) starts immediately in a worker thread
    QTimer.singleShot(0, window.start_update_check)

    # keep_search waits internally for the GUI to be ready, so start it now
    # instead of adding a fixed 2s startup delay.
    QTimer.singleShot(0, lambda: threading.Thread(target=window.keep_search, daemon=True).start())

    print("ENTER EVENT LOOP", flush=True)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()


# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved. Distribution without permission prohibited.
# This code is part of ANCORATE Encryption Software.
# Unauthorized copying of this file, via any medium is strictly prohibited.
# Proprietary and confidential.
# Written by Samuel J. Tirwa & Gabriel Leiria-Roussin.
# January 2026
# Version 27 Beta 1