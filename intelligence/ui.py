"""Minimalistisches Chat-UI für EncryptIntelligence mit LLM-Support.

ChatGPT-ähnliches Interface mit:
- Zentraler Chat-Bereich (Nachrichten-Fluss)
- Rechte Sidebar für Dokumenten-Suche und Status
- Loading-State während LLM antwortet
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    QTextEdit,
    QPushButton,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QLabel,
    QScrollArea,
    QMessageBox,
    QFrame,
)

from .core import EncryptIntelligenceManager


class EncryptIntelligenceDialog(QDialog):
    """Minimalistisches Chat-Interface für lokale Dokumentensuche mit LLM."""

    def __init__(self, parent=None, manager: EncryptIntelligenceManager | None = None):
        super().__init__(parent)
        self.setWindowTitle("EncryptIntelligence")
        self.resize(1200, 700)
        self.setMinimumSize(900, 500)
        self.setModal(False)

        self.manager = manager if manager is not None else EncryptIntelligenceManager()
        self._build_ui()
        self._refresh_sidebar()
        self._update_llm_status()

    def _build_ui(self) -> None:
        """Baue Hauptlayout: Chat-Bereich + Sidebar."""
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ===== Linker Bereich: Chat =====
        chat_area = QWidget()
        chat_layout = QVBoxLayout(chat_area)
        chat_layout.setContentsMargins(24, 24, 24, 24)
        chat_layout.setSpacing(12)

        # Chat-Header
        header = QLabel("EncryptIntelligence")
        header.setObjectName("eiChatHeader")
        chat_layout.addWidget(header)

        # Chat-Verlauf
        self.chat_display = QTextEdit()
        self.chat_display.setObjectName("eiChatDisplay")
        self.chat_display.setReadOnly(True)
        self.chat_display.setPlaceholderText("Stelle eine Frage zu deinen indizierten Dokumenten...")
        chat_layout.addWidget(self.chat_display, 1)

        # Input-Area
        input_row = QVBoxLayout()
        input_row.setSpacing(8)

        self.chat_input = QTextEdit()
        self.chat_input.setObjectName("eiChatInput")
        self.chat_input.setFixedHeight(72)
        self.chat_input.setPlaceholderText("Deine Frage...")
        self.chat_input.keyPressEvent = self._handle_chat_input_key

        self.send_button = QPushButton("Senden")
        self.send_button.setObjectName("eiSendButton")
        self.send_button.clicked.connect(self._on_send_question)

        input_row.addWidget(self.chat_input)
        input_row.addWidget(self.send_button)
        chat_layout.addLayout(input_row)

        # ===== Rechter Bereich: Sidebar =====
        sidebar = QFrame()
        sidebar.setObjectName("eiSidebar")
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(16, 24, 24, 24)
        sidebar_layout.setSpacing(16)

        # Status-Bereich
        status_header = QLabel("Status")
        status_header.setObjectName("eiSidebarHeader")
        sidebar_layout.addWidget(status_header)

        self.status_label = QLabel("Bereit")
        self.status_label.setObjectName("eiStatusText")
        sidebar_layout.addWidget(self.status_label)

        # LLM-Status
        self.llm_status = QLabel("LLM: Prüfe...")
        self.llm_status.setObjectName("eiStatusText")
        sidebar_layout.addWidget(self.llm_status)

        # Index-Button
        self.index_button = QPushButton("Tresor indexieren")
        self.index_button.setObjectName("eiIndexButton")
        self.index_button.clicked.connect(self._on_index_current_container)
        sidebar_layout.addWidget(self.index_button)

        # Dokument-Bereich
        docs_header = QLabel("Dokumente")
        docs_header.setObjectName("eiSidebarHeader")
        sidebar_layout.addWidget(docs_header)

        self.documents_list = QListWidget()
        self.documents_list.setObjectName("eiDocList")
        self.documents_list.setMaximumHeight(200)
        sidebar_layout.addWidget(self.documents_list)

        # Suche-Bereich
        search_header = QLabel("Suche")
        search_header.setObjectName("eiSidebarHeader")
        sidebar_layout.addWidget(search_header)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("eiSearchInput")
        self.search_input.setPlaceholderText("In Dokumenten suchen...")
        self.search_input.returnPressed.connect(self._on_search)
        sidebar_layout.addWidget(self.search_input)

        self.search_results = QListWidget()
        self.search_results.setObjectName("eiSearchList")
        self.search_results.itemClicked.connect(self._on_search_result_selected)
        sidebar_layout.addWidget(self.search_results, 1)

        # Stretch am Ende
        sidebar_layout.addStretch()

        # Zusammensetzen
        root.addWidget(chat_area, 1)
        root.addWidget(sidebar, 0)
        sidebar.setMaximumWidth(320)

        # Stylesheet
        self.setStyleSheet(self._stylesheet())

    def _handle_chat_input_key(self, event) -> None:
        """Handle Enter-Taste im Chat-Input (Shift+Enter = Newline)."""
        if event.key() == Qt.Key.Key_Return or event.key() == Qt.Key.Key_Enter:
            if event.modifiers() == Qt.KeyboardModifier.ShiftModifier:
                # Shift+Enter: Newline
                self.chat_input.insertPlainText("\n")
            else:
                # Enter: Senden
                self._on_send_question()
        else:
            QTextEdit.keyPressEvent(self.chat_input, event)

    def _update_llm_status(self) -> None:
        """Überprüfe LLM-Verfügbarkeit und aktualisiere Status."""
        if self.manager.llm.is_available():
            self.llm_status.setText(f"✓ LLM aktiv ({self.manager.config.ollama_model})")
            self.llm_status.setStyleSheet("color: #4ade80;")
        else:
            self.llm_status.setText("⚠ LLM offline (Fallback aktiv)")
            self.llm_status.setStyleSheet("color: #facc15;")

    def _on_send_question(self) -> None:
        """Verarbeite Chat-Nachricht."""
        question = self.chat_input.toPlainText().strip()
        if not question:
            return

        # Zeige Frage
        self.chat_display.append(f"Du: {question}\n")
        self.chat_input.clear()
        self.send_button.setEnabled(False)
        self.status_label.setText("Antworte...")

        # Generiere Antwort
        try:
            answer = self.manager.answer_question(question)
            self.chat_display.append(f"EncryptIntelligence:\n{answer}\n")
            self.status_label.setText("Bereit")
        except Exception as exc:
            self.chat_display.append(f"Fehler: {str(exc)}\n")
            self.status_label.setText("Fehler")
        finally:
            self.send_button.setEnabled(True)

        # Scroll zu Bottom
        self.chat_display.verticalScrollBar().setValue(
            self.chat_display.verticalScrollBar().maximum()
        )

        # Aktualisiere Reminders
        self._refresh_sidebar()

    def _on_search(self) -> None:
        """Durchsuche Dokumente nach Query."""
        query = self.search_input.text().strip()
        if not query:
            self.search_results.clear()
            return

        results = self.manager.search_documents(query)
        self.search_results.clear()

        if not results:
            item = QListWidgetItem("Keine Treffer")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.search_results.addItem(item)
            return

        for entry in results:
            snippet = entry['snippet'][:150] + ("..." if len(entry['snippet']) > 150 else "")
            display = f"{entry['document_name']}\n{snippet}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, entry['document_id'])
            self.search_results.addItem(item)

    def _on_search_result_selected(self, item: QListWidgetItem) -> None:
        """Zeige ausgewähltes Suchergebnis im Chat."""
        doc_id = item.data(Qt.ItemDataRole.UserRole)
        if not doc_id:
            return

        doc = self.manager.fetch_document(doc_id)
        if not doc:
            return

        # Zeige Dokument-Auszug im Chat
        snippet = doc['text'][:500] + ("..." if len(doc['text']) > 500 else "")
        self.chat_display.append(f"📄 {doc['display_name']}\n\n{snippet}\n")

    def _on_index_current_container(self) -> None:
        """Indexiere aktuellen Tresor."""
        parent = self.parent()
        if parent is None:
            QMessageBox.warning(self, "Fehler", "Kein Tresor-Fenster gefunden.")
            return

        container_path = getattr(parent, "container_path", None)
        master_key = getattr(parent, "master_key", None)
        meta = getattr(parent, "meta", None)

        if not container_path or not master_key or not meta:
            QMessageBox.warning(
                self,
                "Fehler",
                "Bitte öffne zuerst einen Tresor.",
            )
            return

        self.index_button.setEnabled(False)
        self.status_label.setText("Indiziere...")

        try:
            indexed = self.manager.index_container(container_path, meta, master_key)
        except Exception as exc:
            QMessageBox.critical(self, "Indexierungsfehler", str(exc))
            self.status_label.setText("Fehler beim Indexieren")
            self.index_button.setEnabled(True)
            return

        # Erfolg
        skipped = self.manager.last_index_report.get("skipped", [])
        self._refresh_sidebar()
        self.status_label.setText(f"✓ {len(indexed)} Dateien indexiert")
        self.send_button.setEnabled(True)

        # Info-Dialog
        detail = ""
        if skipped:
            detail = f"\n\nÜbersprungen ({len(skipped)}):\n"
            for item in skipped[:5]:
                detail += f"- {item['name']}: {item['reason']}\n"
            if len(skipped) > 5:
                detail += f"- weitere {len(skipped) - 5} Dateien"

        QMessageBox.information(
            self,
            "Indexierung abgeschlossen",
            f"{len(indexed)} Dokument(e) wurden indiziert.{detail}",
        )
        self.index_button.setEnabled(True)

    def _refresh_sidebar(self) -> None:
        """Aktualisiere Sidebar (Dokumente, Reminders)."""
        self._refresh_documents_list()
        self._refresh_reminders_status()

    def _refresh_documents_list(self) -> None:
        """Zeige indizierte Dokumente."""
        self.documents_list.clear()
        docs = self.manager.list_documents()

        if not docs:
            item = QListWidgetItem("Keine Dokumente")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.documents_list.addItem(item)
        else:
            for doc in docs[:10]:  # Zeige maximal 10
                self.documents_list.addItem(QListWidgetItem(doc))

    def _refresh_reminders_status(self) -> None:
        """Zeige Reminder-Status."""
        reminders = self.manager.get_reminders()
        if reminders:
            count = len(reminders)
            self.status_label.setText(f"{count} Erinnerungen")
        else:
            self.status_label.setText("Bereit")

    def _stylesheet(self) -> str:
        return """
            QDialog {
                background: #0f1319;
                color: #e7edf2;
            }

            /* Chat-Header */
            QLabel#eiChatHeader {
                font-size: 28px;
                font-weight: 700;
                color: #f4f8fb;
                margin-bottom: 8px;
            }

            /* Chat Display */
            QTextEdit#eiChatDisplay {
                background: #0f1319;
                border: none;
                color: #e7edf2;
                font-size: 13px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue';
                padding: 0;
                margin: 0;
            }

            /* Chat Input */
            QTextEdit#eiChatInput {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 8px;
                color: #e7edf2;
                font-size: 13px;
                padding: 10px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue';
            }

            /* Send Button */
            QPushButton#eiSendButton {
                background: #2f6f73;
                border: none;
                border-radius: 6px;
                color: #f4f8fb;
                font-weight: 500;
                padding: 10px 16px;
            }

            QPushButton#eiSendButton:hover {
                background: #39838a;
            }

            QPushButton#eiSendButton:pressed {
                background: #26575a;
            }

            /* Sidebar */
            QFrame#eiSidebar {
                background: #0f1319;
                border-left: 1px solid #2b333b;
            }

            QLabel#eiSidebarHeader {
                font-size: 12px;
                font-weight: 600;
                color: #94a3af;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            QLabel#eiStatusText {
                font-size: 12px;
                color: #b8c7d3;
                margin-bottom: 8px;
            }

            /* Index Button */
            QPushButton#eiIndexButton {
                background: #2f6f73;
                border: none;
                border-radius: 6px;
                color: #f4f8fb;
                font-weight: 500;
                padding: 10px 14px;
                font-size: 12px;
            }

            QPushButton#eiIndexButton:hover {
                background: #39838a;
            }

            /* Lists */
            QListWidget#eiDocList,
            QListWidget#eiSearchList {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 6px;
                color: #e7edf2;
                font-size: 11px;
                outline: none;
            }

            QListWidget#eiDocList::item,
            QListWidget#eiSearchList::item {
                padding: 8px 10px;
                border-bottom: 1px solid #2b333b;
            }

            QListWidget#eiDocList::item:selected,
            QListWidget#eiSearchList::item:selected {
                background: #263d40;
            }

            /* Search Input */
            QLineEdit#eiSearchInput {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 6px;
                color: #e7edf2;
                font-size: 12px;
                padding: 8px 10px;
            }

            QLineEdit#eiSearchInput:focus {
                border: 1px solid #3f8b90;
            }
        """