import sys
import os
import psutil
import threading
import time

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *


# -----------------------------
# Helper Functions
# -----------------------------

def get_app_icon():
    """
    Lädt das passende Icon-Format für die aktuelle Plattform.
    """
    import platform
    system = platform.system()
    
    # Verschiedene Icon-Formate versuchen
    icon_paths = []
    base_dir = os.path.dirname(__file__)
    
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
    
    # Erstes existierendes Icon zurückgeben
    for path in icon_paths:
        if os.path.exists(path):
            return QIcon(path)
    
    # Fallback: Leeres Icon
    return QIcon()


# -----------------------------
# Scanner Logic
# -----------------------------

def get_all_drives():
    drives = []
    for part in psutil.disk_partitions(all=False):
        if os.path.exists(part.device):
            drives.append(part.device)
    return drives


def search_salt_files(start_dir):
    found = []
    try:
        for root, _, files in os.walk(start_dir):
            for file in files:
                if file.lower().endswith(".salt"):
                    found.append(os.path.join(root, file))
    except (PermissionError, OSError):
        pass
    return found


# -----------------------------
# GUI
# -----------------------------

class SaltScannerUI(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("ANCORATE Emergency Data Wiper")
        self.setWindowIcon(get_app_icon())
        self.resize(720, 520)

        layout = QVBoxLayout(self)

        self.scan_button = QPushButton("Scan nach Tresoren auf allen Laufwerken (das kann eine Weile dauern)")
        self.scan_button.setObjectName("secondary")
        self.scan_button.clicked.connect(self.run_scan)

        self.emergency_button = QPushButton("EMERGENCY VAULT DATA WIPE")
        self.emergency_button.setObjectName("danger")
        self.emergency_button.clicked.connect(self.emergency_delete)

        self.list_widget = QListWidget()

        self.status_label = QLabel("Bereit")
        self.status_label.setObjectName("status")

        # Progress tracking
        self._scanning = False
        self._deleting = False
        self._scan_results = []
        self._current_drive = ""
        self._files_scanned = 0
        self._total_files = 0

        layout.addWidget(self.scan_button)
        layout.addWidget(self.emergency_button)
        layout.addWidget(self.list_widget)
        layout.addWidget(self.status_label)

        # Timer for UI updates
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._update_ui_progress)
        self.update_timer.start(100)  # Update every 100ms

    def run_scan(self):
        if self._scanning:
            return
            
        self._scanning = True
        self.list_widget.clear()
        self.scan_button.setEnabled(False)
        self.emergency_button.setEnabled(False)
        self._scan_results = []
        self._files_scanned = 0
        self._total_files = 0
        
        def scan_worker():
            try:
                drives = get_all_drives()
                self._total_files = len(drives)  # Use actual drive count
                
                for i, drive in enumerate(drives):
                    self._current_drive = drive
                    drive_results = search_salt_files(drive)
                    self._scan_results.extend(drive_results)
                    self._files_scanned = i + 1
                    time.sleep(0.1)  # Small delay to prevent UI blocking
                    
                # Update UI from main thread
                QTimer.singleShot(0, self._scan_complete)
            except Exception as e:
                QTimer.singleShot(0, lambda: self._scan_error(str(e)))
            finally:
                self._scanning = False
        
        # Start scan in background thread
        threading.Thread(target=scan_worker, daemon=True).start()
    
    def _update_ui_progress(self):
        if self._scanning:
            if self._total_files > 0:
                progress = (self._files_scanned / self._total_files) * 100
                self.status_label.setText(
                    f"Scanne {self._current_drive}... ({self._files_scanned}/{self._total_files} Laufwerke) - {progress:.0f}%"
                )
            else:
                self.status_label.setText(f"Scanne {self._current_drive}... (bereite Laufwerke vor)")
        elif self._deleting:
            self.status_label.setText("Lösche Tresore... Bitte warten")
    
    def _scan_complete(self):
        self.list_widget.clear()
        if self._scan_results:
            for path in self._scan_results:
                self.list_widget.addItem(path)
            self.status_label.setText(f"{len(self._scan_results)} Tresore gefunden - Scan abgeschlossen")
        else:
            self.status_label.setText("Keine Tresore gefunden - Scan abgeschlossen")
        
        self.scan_button.setEnabled(True)
        self.emergency_button.setEnabled(True)
        self._current_drive = ""
        self._files_scanned = 0
        self._total_files = 0
    
    def _scan_error(self, error_msg):
        self.status_label.setText(f"Scan-Fehler: {error_msg}")
        self.scan_button.setEnabled(True)
        self.emergency_button.setEnabled(True)
        self._scanning = False
        self._current_drive = ""
        self._files_scanned = 0
        self._total_files = 0

    def emergency_delete(self):
        if self.list_widget.count() == 0:
            self.status_label.setText("Keine Tresore zum Löschen")
            return

        reply = QMessageBox.critical(
            self,
            "NOTFALL‑LÖSCHUNG",
            "Alle gefundenen Tresore werden unwiderruflich gelöscht.\n\n"
            "Diesen Vorgang wirklich ausführen? Sie sind nicht wiederherstellbar.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply != QMessageBox.StandardButton.Yes:
            self.status_label.setText("Notfall‑Löschung abgebrochen")
            return
        
        if self._deleting:
            return
            
        self._deleting = True
        self.scan_button.setEnabled(False)
        self.emergency_button.setEnabled(False)
        
        # Get all paths before starting deletion
        paths_to_delete = []
        for i in range(self.list_widget.count()):
            paths_to_delete.append(self.list_widget.item(i).text())
        
        def delete_worker():
            deleted = 0
            total = len(paths_to_delete)
            
            for i, path in enumerate(paths_to_delete):
                try:
                    if os.path.exists(path):
                        os.remove(path)
                        deleted += 1
                    # Update progress
                    QTimer.singleShot(0, lambda d=deleted, t=total: self._update_delete_progress(d, t))
                    time.sleep(0.05)  # Small delay to prevent UI blocking
                except Exception:
                    pass
            
            # Complete deletion
            QTimer.singleShot(0, lambda: self._delete_complete(deleted, total))
            self._deleting = False
        
        # Start deletion in background thread
        threading.Thread(target=delete_worker, daemon=True).start()
    
    def _update_delete_progress(self, deleted, total):
        if self._deleting:
            self.status_label.setText(f"Lösche Tresore... {deleted}/{total} gelöscht")
    
    def _delete_complete(self, deleted, total):
        self.list_widget.clear()
        self.status_label.setText(f"{deleted} Tresore unwiderruflich gelöscht")
        self.scan_button.setEnabled(True)
        self.emergency_button.setEnabled(True)
        self._deleting = False


# -----------------------------
# App Bootstrap
# -----------------------------

def load_stylesheet(app):
    try:
        with open("themes/dark.css", "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print("running bare-metal")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    load_stylesheet(app)

    window = SaltScannerUI()
    window.show()

    sys.exit(app.exec())
