"""UI-Komponenten für EncryptIntelligence.

Dieses Modul stellt die Benutzeroberfläche für Chat, Dokumentensuche, Erinnerungen und Einstellungen bereit.
"""

from typing import List
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QLineEdit,
    QMessageBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .core import EncryptIntelligenceManager


class EncryptIntelligenceDialog(QDialog):
    """Dialog für EncryptIntelligence mit mehreren Bereichen."""

    def __init__(self, parent=None, manager: EncryptIntelligenceManager | None = None):
        super().__init__(parent)
        self.setWindowTitle("EncryptIntelligence")
        self.resize(960, 680)
        self.setModal(True)

        self.manager = manager if manager is not None else EncryptIntelligenceManager()

        self.status_label = QLabel("Bereit")
        self.status_label.setObjectName("status")
        self.index_button = QPushButton("Aktuellen Tresor indexieren")
        self.index_button.clicked.connect(self._on_index_current_container)

        top_bar = QHBoxLayout()
        top_bar.addWidget(self.index_button)
        top_bar.addStretch()
        top_bar.addWidget(self.status_label)

        self.tabs = QTabWidget(self)
        self.tabs.addTab(self._create_search_tab(), "Dokumentensuche")
        self.tabs.addTab(self._create_chat_tab(), "Chat")
        self.tabs.addTab(self._create_reminders_tab(), "Erinnerungen")

        layout = QVBoxLayout(self)
        layout.addLayout(top_bar)
        layout.addWidget(self.tabs)

    def _create_chat_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)

        title = QLabel("Chat mit EncryptIntelligence")
        title.setStyleSheet("font-weight: bold; font-size: 18px;")
        layout.addWidget(title)

        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        self.chat_history.setPlaceholderText("Stellen Sie eine Frage zu Ihren indizierten Dokumenten...")
        layout.addWidget(self.chat_history, 1)

        self.chat_input = QTextEdit()
        self.chat_input.setFixedHeight(120)
        self.chat_input.setPlaceholderText("Zum Beispiel: 'Wann läuft mein Vertrag aus?'" )
        layout.addWidget(self.chat_input)

        send_row = QHBoxLayout()
        send_row.addStretch()
        self.send_button = QPushButton("Senden")
        self.send_button.clicked.connect(self._on_send_question)
        send_row.addWidget(self.send_button)
        layout.addLayout(send_row)

        return widget

    def _create_search_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)

        title = QLabel("Dokumentensuche")
        title.setStyleSheet("font-weight: bold; font-size: 18px;")
        layout.addWidget(title)

        query_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Suchbegriff oder Frage eingeben...")
        self.search_input.returnPressed.connect(self._on_search)
        self.search_input.setMinimumWidth(260)

        search_btn = QPushButton("Suchen")
        search_btn.clicked.connect(self._on_search)

        query_row.addWidget(self.search_input)
        query_row.addWidget(search_btn)
        layout.addLayout(query_row)

        self.search_status = QLabel("Keine Suche aktiv.")
        self.search_status.setObjectName("status")
        layout.addWidget(self.search_status)

        self.search_list = QListWidget()
        self.search_list.setSelectionMode(QListWidget.SelectionMode.SingleSelection)
        layout.addWidget(self.search_list, 1)

        self._refresh_document_list()
        return widget

    def _create_reminders_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)

        title = QLabel("Erinnerungen")
        title.setStyleSheet("font-weight: bold; font-size: 18px;")
        layout.addWidget(title)

        self.reminders_list = QListWidget()
        layout.addWidget(self.reminders_list, 1)

        self._refresh_reminders()
        return widget

    def _refresh_document_list(self) -> None:
        self.search_list.clear()
        docs = self.manager.list_documents()
        if not docs:
            self.search_list.addItem(QListWidgetItem("Keine Dokumente indiziert. Bitte indexieren."))
            return
        for name in docs:
            self.search_list.addItem(QListWidgetItem(name))

    def _refresh_reminders(self) -> None:
        self.reminders_list.clear()
        reminders = self.manager.get_reminders()
        if reminders:
            for reminder in reminders:
                label = f"{reminder.get('title')} — {reminder.get('date') or 'kein Datum'} ({reminder.get('source')})"
                self.reminders_list.addItem(QListWidgetItem(label))
        else:
            self.reminders_list.addItem(QListWidgetItem("Keine Erinnerungen gefunden."))

    def _on_send_question(self) -> None:
        question = self.chat_input.toPlainText().strip()
        if not question:
            return

        self.chat_history.append(f"Sie: {question}")
        answer = self.manager.answer_question(question)
        self.chat_history.append(f"EncryptIntelligence: {answer}\n")
        self.chat_input.clear()
        self._refresh_reminders()
        self.status_label.setText("Chat ausgeführt.")

    def _on_search(self) -> None:
        query = self.search_input.text().strip()
        if not query:
            self.search_status.setText("Bitte geben Sie einen Suchbegriff ein.")
            self._refresh_document_list()
            return

        results = self.manager.search_documents(query)
        self.search_list.clear()
        if not results:
            self.search_status.setText("Keine relevanten Dokumente gefunden.")
            return

        self.search_status.setText(f"{len(results)} Ergebnisse gefunden.")
        for entry in results:
            item = QListWidgetItem(
                f"{entry['document_name']} — {entry['score']:.2f}\n{entry['snippet']}"
            )
            self.search_list.addItem(item)

    def _on_index_current_container(self) -> None:
        parent = self.parent()
        if parent is None:
            QMessageBox.warning(self, "Fehler", "Kein übergeordnetes Fenster gefunden.")
            return

        container_path = getattr(parent, "container_path", None)
        master_key = getattr(parent, "master_key", None)
        meta = getattr(parent, "meta", None)

        if not container_path or not master_key or not meta:
            QMessageBox.warning(
                self,
                "Fehler",
                "Kein geöffneter Tresor gefunden. Öffnen Sie zuerst einen Tresor, bevor Sie indexieren.",
            )
            return

        try:
            indexed = self.manager.index_container(container_path, meta, master_key)
            self._refresh_document_list()
            self._refresh_reminders()
            self.status_label.setText(f"{len(indexed)} Dokument(e) indiziert.")
            QMessageBox.information(
                self,
                "Indexierung abgeschlossen",
                f"{len(indexed)} Dokument(e) wurden erfolgreich indiziert.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Indexierungsfehler", str(e))

    def _refresh_document_list(self) -> None:
        self.search_list.clear()
        for name in self.manager.list_documents():
            self.search_list.addItem(QListWidgetItem(name))

    def _refresh_reminders(self) -> None:
        self.reminders_list.clear()
        reminders = self.manager.get_reminders()
        if reminders:
            for reminder in reminders:
                label = f"{reminder.get('title')} - {reminder.get('date') or 'kein Datum'} ({reminder.get('source')})"
                self.reminders_list.addItem(QListWidgetItem(label))
        else:
            self.reminders_list.addItem(QListWidgetItem("Keine Erinnerungen gefunden."))

    def _on_send_question(self) -> None:
        question = self.chat_input.toPlainText().strip()
        if not question:
            return

        self.chat_history.append(f"Sie: {question}")
        answer = self.manager.answer_question(question)
        self.chat_history.append(f"EncryptIntelligence: {answer}\n")
        self.chat_input.clear()
        self._refresh_reminders()

    def _on_search(self) -> None:
        query = self.search_input.text().strip()
        if not query:
            self.search_status.setText("Sucheingabe ist leer.")
            self._refresh_document_list()
            return

        results = self.manager.search_documents(query)
        self.search_list.clear()
        if not results:
            self.search_status.setText("Keine Dokumente mit relevantem Inhalt gefunden.")
            return

        self.search_status.setText(f"{len(results)} Ergebnisse gefunden.")
        for entry in results:
            item = QListWidgetItem(
                f"{entry['document_name']} ({entry['score']:.2f})\n{entry['snippet']}"
            )
            self.search_list.addItem(item)

    def _on_index_current_container(self) -> None:
        parent = self.parent()
        if parent is None:
            QMessageBox.warning(self, "Fehler", "Kein übergeordnetes Fenster gefunden.")
            return

        container_path = getattr(parent, "container_path", None)
        master_key = getattr(parent, "master_key", None)
        meta = getattr(parent, "meta", None)

        if not container_path or not master_key or not meta:
            QMessageBox.warning(
                self,
                "Fehler",
                "Kein geöffneter Tresor gefunden. Öffnen Sie zuerst einen Tresor, bevor Sie indexieren.",
            )
            return

        try:
            indexed = self.manager.index_container(container_path, meta, master_key)
            self.search_status.setText(f"{len(indexed)} Dokument(e) aus dem Tresor indexiert.")
            self._refresh_document_list()
            self._refresh_reminders()
            QMessageBox.information(
                self,
                "Indexierung abgeschlossen",
                f"{len(indexed)} Dokument(e) wurden erfolgreich indexiert.",
            )
        except Exception as e:
            QMessageBox.critical(self, "Indexierungsfehler", str(e))
