#!/usr/bin/env python3
# ANCORATE EncryptHome - App-Paket
# (aus main.py extrahiert; Einstiegspunkt bleibt main.py)
# (c) 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
#
# Das app-Paket kapselt die aus main.py herausgeloesten Module in logische
# Ordnerstrukturen:
#    - app/core.py           Konstanten + Standalone-Helfer
#    - app/passwords.py      Passwort-Dialoge
#    - app/workers.py        Worker-Threads + Export
#    - app/dialogs.py        Dialoge + Widgets
#    - app/main_window.py    Hauptfenster (App)
#
# Der Einstiegspunkt (main.py) importiert die Module einzeln und re-exportiert
# alle Symbole. Dadurch funktionieren bestehende Importe wie
# "from main import ..." unveraendert weiter.

from app.core import *
from app.passwords import *
from app.workers import *
from app.dialogs import *
from app.main_window import App
