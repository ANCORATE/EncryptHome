#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

# ANCORATE EncryptHome - gesplittetes Modul
# (aus main.py extrahiert; Ausgangspunkt bleibt main.py)
#

from PyQt6.QtCore import *
from PyQt6.QtWidgets import *
from PyQt6.QtGui import *

from app.core import *
# ============================================================
# Passwort-Dialoge (aus main.py)
# ============================================================

def _set_requirement_label(label, ok: bool):
    """Stellt das Anforderungs-Label auf erfüllt/nicht erfüllt um.

    Die Farben kommen zentral aus der Theme-Datei (QLabel#Requirement),
    gesteuert über die dynamische Qt-Eigenschaft `ok`. Dadurch sind keine
    hartkodierten Farben im Dialogcode nötig.
    """
    label.setObjectName("Requirement")
    label.setProperty("ok", ok)
    style = label.style()
    style.unpolish(label)
    style.polish(label)


def _make_requirement_label(text: str):
    label = QLabel(f"◦ {text}")
    label.setObjectName("Requirement")
    label.setProperty("ok", False)
    return label

def change_container_password(container_path: str, current_master_key: bytes, current_meta: dict, current_password: str, current_flags: int, parent=None) -> tuple[bool, str | None]:
    """
    Change password for existing container
    Returns True if successful, False if cancelled
    """
    dialog = QDialog(parent)
    dialog.setObjectName("SecurityDialog")
    dialog.setWindowTitle("Passwort ändern")
    dialog.setWindowIcon(get_app_icon())
    dialog.setMinimumSize(560, 440)
    dialog.resize(560, 440)
    dialog.setModal(True)
    
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(30, 26, 30, 24)
    layout.setSpacing(18)
    
    title_label = QLabel("Passwort für den geöffneten Tresor ändern")
    title_label.setObjectName("DialogTitle")
    layout.addWidget(title_label)

    info_label = QLabel(
        "Der Tresorinhalt bleibt erhalten. Das Ändern des Passworts aktualisiert die Verschlüsselungskeys, um die Sicherheit zu verbessern. Das kann bei großen Tresoren einige Zeit dauern."
    )
    info_label.setWordWrap(True)
    info_label.setObjectName("ReqInfo")
    layout.addWidget(info_label)
    
    # Store result for returning the new password
    result = {'success': False, 'new_password': None}
    
    # New password with requirements
    new_group = QGroupBox("Neues Passwort")
    new_layout = QVBoxLayout()
    new_layout.setContentsMargins(16, 18, 16, 16)
    new_layout.setSpacing(10)

    new_pwd_input = QLineEdit()
    new_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    new_pwd_input.setPlaceholderText("Neues Passwort eingeben")
    new_pwd_input.setMinimumHeight(34)

    confirm_pwd_input = QLineEdit()
    confirm_pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    confirm_pwd_input.setPlaceholderText("Neues Passwort bestätigen")
    confirm_pwd_input.setMinimumHeight(34)

    form = QFormLayout()
    form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
    form.setFormAlignment(Qt.AlignmentFlag.AlignTop)
    form.setHorizontalSpacing(12)
    form.setVerticalSpacing(10)
    form.addRow("Neues Passwort", new_pwd_input)
    form.addRow("Bestätigen", confirm_pwd_input)
    new_layout.addLayout(form)

    req_group = QGroupBox("Anforderungen")
    req_group_layout = QGridLayout()
    req_group_layout.setContentsMargins(12, 14, 12, 12)
    req_group_layout.setHorizontalSpacing(18)
    req_group_layout.setVerticalSpacing(8)

    req_widgets = {}
    req_labels = [
        ("Mindestens 8 Zeichen", "length"),
        ("Mindestens 1 Großbuchstabe (A-Z)", "upper"),
        ("Mindestens 1 Kleinbuchstabe (a-z)", "lower"),
        ("Mindestens 1 Ziffer (0-9)", "digit"),
        ("Mindestens 1 Sonderzeichen (!@#$%^&*)", "special"),
    ]

    for idx, (text, key) in enumerate(req_labels):
        label = _make_requirement_label(text)
        req_widgets[key] = label
        req_group_layout.addWidget(label, idx // 2, idx % 2)

    req_group.setLayout(req_group_layout)
    new_group.setLayout(new_layout)
    layout.addWidget(new_group)
    layout.addWidget(req_group)

    # Update requirements as user types
    def update_requirements():
        password = new_pwd_input.text()

        ok_len = len(password) >= 8
        _set_requirement_label(req_widgets["length"], ok_len)
        req_widgets["length"].setText(
            f"{'✓' if ok_len else '◦'} Mindestens 8 Zeichen"
        )

        has_upper = any(c.isupper() for c in password)
        _set_requirement_label(req_widgets["upper"], has_upper)
        req_widgets["upper"].setText(
            f"{'✓' if has_upper else '◦'} Mindestens 1 Großbuchstabe (A-Z)"
        )

        has_lower = any(c.islower() for c in password)
        _set_requirement_label(req_widgets["lower"], has_lower)
        req_widgets["lower"].setText(
            f"{'✓' if has_lower else '◦'} Mindestens 1 Kleinbuchstabe (a-z)"
        )

        has_digit = any(c.isdigit() for c in password)
        _set_requirement_label(req_widgets["digit"], has_digit)
        req_widgets["digit"].setText(
            f"{'✓' if has_digit else '◦'} Mindestens 1 Ziffer (0-9)"
        )

        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        _set_requirement_label(req_widgets["special"], has_special)
        req_widgets["special"].setText(
            f"{'✓' if has_special else '◦'} Mindestens 1 Sonderzeichen (!@#$%^&*)"
        )

    new_pwd_input.textChanged.connect(update_requirements)
    update_requirements()

    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()

    change_btn = QPushButton("Passwort ändern")
    cancel_btn = QPushButton("Abbrechen")
    cancel_btn.setObjectName("secondary")
    change_btn.setDefault(True)
    change_btn.setMinimumWidth(150)
    cancel_btn.setMinimumWidth(120)
    change_btn.setObjectName("primary")

    btn_layout.addWidget(change_btn)
    btn_layout.addWidget(cancel_btn)
    layout.addLayout(btn_layout)

    # Button handlers
    def change_password():
        new_pwd = new_pwd_input.text()
        confirm_pwd = confirm_pwd_input.text()
        
        if new_pwd != confirm_pwd:
            QMessageBox.warning(dialog, "Fehler", "Neue Passwörter stimmen nicht überein.")
            return
        
        is_valid, error_msg = validate_password_strength(new_pwd)
        if not is_valid:
            QMessageBox.warning(dialog, "Ungültiges Passwort", error_msg)
            return
        
        try:
            rekey_container_password(container_path, current_meta, current_flags, current_master_key, new_pwd)
            result['success'] = True
            result['new_password'] = new_pwd
            
            QMessageBox.information(dialog, "Erfolg", "Passwort wurde erfolgreich geändert.")
            dialog.accept()
            
        except Exception as e:
            QMessageBox.critical(dialog, "Fehler", f"Passwortänderung fehlgeschlagen: {str(e)}")
    
    def reject_dialog():
        dialog.reject()
    
    change_btn.clicked.connect(change_password)
    cancel_btn.clicked.connect(reject_dialog)
    
    # Show dialog
    dialog_result = dialog.exec() == QDialog.DialogCode.Accepted
    if dialog_result and result['success']:
        # Return both success flag and new password
        return True, result['new_password']
    return False, None


def get_password_with_requirements(parent, title="Passwort eingeben") -> tuple[str, bool]:
    """
    Get password with visual requirements display
    Returns (password, was_cancelled)
    """
    dialog = QDialog(parent)
    dialog.setObjectName("SecurityDialog")
    dialog.setWindowTitle(title)
    dialog.setWindowIcon(get_app_icon())
    dialog.setMinimumSize(500, 360)
    dialog.resize(560, 400)
    dialog.setModal(True)
    
    layout = QVBoxLayout(dialog)
    layout.setContentsMargins(30, 26, 30, 24)
    layout.setSpacing(18)
    
    # Password input
    pwd_layout = QHBoxLayout()
    pwd_label = QLabel("Passwort:")
    pwd_label.setFixedWidth(80)
    pwd_input = QLineEdit()
    pwd_input.setEchoMode(QLineEdit.EchoMode.Password)
    pwd_input.setMinimumWidth(300)
    pwd_input.setSizePolicy(
        QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
    )
    pwd_layout.addWidget(pwd_label)
    pwd_layout.addWidget(pwd_input)
    layout.addLayout(pwd_layout)
    
    # Requirements display
    req_group = QGroupBox("Passwortanforderungen:")
    req_layout = QVBoxLayout()
    
    req_labels = [
        ("Mindestens 8 Zeichen", "length"),
        ("Mindestens 1 Großbuchstabe (A-Z)", "upper"),
        ("Mindestens 1 Kleinbuchstabe (a-z)", "lower"),
        ("Mindestens 1 Ziffer (0-9)", "digit"),
        ("Mindestens 1 Sonderzeichen (!@#$%^&*)", "special")
    ]
    
    req_widgets = {}
    for text, key in req_labels:
        label = _make_requirement_label(text)
        label.setIndent(10)
        req_widgets[key] = label
        req_layout.addWidget(label)
    
    req_group.setLayout(req_layout)
    layout.addWidget(req_group)
    
    # Update requirements display as user types
    def update_requirements():
        password = pwd_input.text()
        
        # Update visual indicators
        _set_requirement_label(req_widgets["length"], len(password) >= 8)
        req_widgets["length"].setText(
            f"{'✓' if len(password) >= 8 else '○'} Mindestens 8 Zeichen"
        )
        
        has_upper = any(c.isupper() for c in password)
        _set_requirement_label(req_widgets["upper"], has_upper)
        req_widgets["upper"].setText(
            f"{'✓' if has_upper else '○'} Mindestens 1 Großbuchstabe (A-Z)"
        )
        
        has_lower = any(c.islower() for c in password)
        _set_requirement_label(req_widgets["lower"], has_lower)
        req_widgets["lower"].setText(
            f"{'✓' if has_lower else '○'} Mindestens 1 Kleinbuchstabe (a-z)"
        )
        
        has_digit = any(c.isdigit() for c in password)
        _set_requirement_label(req_widgets["digit"], has_digit)
        req_widgets["digit"].setText(
            f"{'✓' if has_digit else '○'} Mindestens 1 Ziffer (0-9)"
        )
        
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        _set_requirement_label(req_widgets["special"], has_special)
        req_widgets["special"].setText(
            f"{'✓' if has_special else '○'} Mindestens 1 Sonderzeichen (!@#$%^&*)"
        )
    
    pwd_input.textChanged.connect(update_requirements)
    update_requirements()  # Initial state
    
    # Buttons
    btn_layout = QHBoxLayout()
    btn_layout.addStretch()
    
    ok_btn = QPushButton("OK")
    cancel_btn = QPushButton("Abbrechen")
    cancel_btn.setObjectName("secondary")

    btn_layout.addWidget(ok_btn)
    btn_layout.addWidget(cancel_btn)
    layout.addLayout(btn_layout)
    
    # Button handlers
    result_password = ""
    cancelled = True
    
    def accept_password():
        nonlocal result_password, cancelled
        password = pwd_input.text()
        is_valid, error_msg = validate_password_strength(password)
        
        if not is_valid:
            QMessageBox.warning(dialog, "Ungültiges Passwort", error_msg)
            return
        
        result_password = password
        cancelled = False
        dialog.accept()
    
    def reject_dialog():
        nonlocal cancelled
        cancelled = True
        dialog.reject()
    
    ok_btn.clicked.connect(accept_password)
    cancel_btn.clicked.connect(reject_dialog)
    pwd_input.returnPressed.connect(accept_password)
    
    # Show dialog
    dialog.exec()
    return result_password, cancelled
