"""EncryptIntelligence UI v2: Modernes Chat-Interface mit Live-Streaming.

Features:
- Markdown-Support für Antworten
- Streaming-Display während LLM antwortet
- Verbesserte Sidebar mit Tabs
- Responsive Design
- Besserer Loading-State
"""

from pathlib import Path
import re
from typing import Optional, Callable
from datetime import datetime

from PyQt6.QtCore import Qt, QTimer, QThread, pyqtSignal, QSize
from PyQt6.QtGui import QFont, QIcon, QColor, QTextCursor
from PyQt6.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QWidget, QTextEdit, QPushButton,
    QLineEdit, QListWidget, QListWidgetItem, QLabel, QScrollArea,
    QMessageBox, QFrame, QSplitter, QTabWidget, QMenu, QProgressBar
)


# ============================================================================
# Worker Threads für Non-Blocking Operations
# ============================================================================

class QuestionWorker(QThread):
    """Worker für asynchrone Question-Answering mit Streaming."""
    
    response_token = pyqtSignal(str)
    response_done = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, manager, question: str):
        super().__init__()
        self.manager = manager
        self.question = question
        self._buffer = ""
    
    def _on_token(self, token: str) -> None:
        """Callback für jeden generierten Token."""
        self._buffer += token
        # Emittiere nach jedem Satz
        if re.search(r'[.!?]\s*$', self._buffer):
            self.response_token.emit(self._buffer)
            self._buffer = ""
    
    def run(self) -> None:
        try:
            answer = self.manager.answer_question(self.question, self._on_token)
            if self._buffer:
                self.response_token.emit(self._buffer)
            self.response_done.emit(answer)
        except Exception as exc:
            self.error_occurred.emit(str(exc))


class IndexWorker(QThread):
    """Worker für asynchrone Indexierung."""
    
    progress = pyqtSignal(int, str)
    finished = pyqtSignal(list, list)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, manager, container_path: str, meta: dict, master_key: bytes):
        super().__init__()
        self.manager = manager
        self.container_path = container_path
        self.meta = meta
        self.master_key = master_key
    
    def run(self) -> None:
        try:
            indexed = self.manager.index_container(
                self.container_path, self.meta, self.master_key
            )
            skipped = self.manager.last_index_report.get("skipped", [])
            self.finished.emit(indexed, skipped)
        except Exception as exc:
            self.error_occurred.emit(str(exc))


# ============================================================================
# Markdown Rendering Helper
# ============================================================================

class MarkdownRenderer:
    """Einfaches Markdown zu HTML für QTextEdit."""
    
    @staticmethod
    def to_html(text: str) -> str:
        """Konvertiere Markdown zu HTML."""
        text = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', text)
        text = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', text)
        text = re.sub(r'`([^`]+)`', r'<code style="background:#2b3340;padding:2px 4px;">\1</code>', text)
        text = text.replace('\n', '<br>')
        return f'<p>{text}</p>'


# ============================================================================
# Main Dialog
# ============================================================================

class EncryptIntelligenceDialog(QDialog):
    """Modernes Chat-Interface für lokale Dokumentensuche."""

    def __init__(self, parent=None, manager=None):
        super().__init__(parent)
        self.setWindowTitle("EncryptIntelligence")
        self.resize(1400, 800)
        self.setMinimumSize(1000, 600)
        self.setModal(False)

        # Lazy load manager if needed
        if manager is None:
            try:
                from .core import EncryptIntelligenceManager
                manager = EncryptIntelligenceManager()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load manager: {e}")
                raise

        self.manager = manager
        self._question_worker: Optional[QuestionWorker] = None
        self._index_worker: Optional[IndexWorker] = None
        self._build_ui()
        self._refresh_sidebar()
        self._update_status()

    def _build_ui(self) -> None:
        """Baue Hauptlayout."""
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        chat_widget = self._build_chat_area()
        sidebar = self._build_sidebar()

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(chat_widget)
        splitter.addWidget(sidebar)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter)

        self.setStyleSheet(self._stylesheet())

    def _build_chat_area(self) -> QWidget:
        """Baue Chat-Bereich."""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        # Header
        header = QLabel("EncryptIntelligence")
        header_font = QFont()
        header_font.setPointSize(24)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setObjectName("eiChatHeader")
        layout.addWidget(header)

        # Chat-Display
        self.chat_display = QTextEdit()
        self.chat_display.setObjectName("eiChatDisplay")
        self.chat_display.setReadOnly(True)
        self.chat_display.setPlaceholderText(
            "Stelle eine Frage zu deinen indizierten Dokumenten..."
        )
        layout.addWidget(self.chat_display, 1)

        # Input Area
        input_layout = QVBoxLayout()
        input_layout.setSpacing(8)

        # Status während Verarbeitung
        self.status_bar = QProgressBar()
        self.status_bar.setObjectName("eiStatusBar")
        self.status_bar.setVisible(False)
        self.status_bar.setMaximumHeight(20)
        input_layout.addWidget(self.status_bar)

        # Chat Input
        self.chat_input = QTextEdit()
        self.chat_input.setObjectName("eiChatInput")
        self.chat_input.setFixedHeight(80)
        self.chat_input.setPlaceholderText("Deine Frage...")
        self.chat_input.keyPressEvent = self._handle_input_key
        input_layout.addWidget(self.chat_input)

        # Button-Zeile
        button_layout = QHBoxLayout()
        button_layout.setSpacing(8)

        self.send_button = QPushButton("Senden")
        self.send_button.setObjectName("eiSendButton")
        self.send_button.clicked.connect(self._on_send_question)
        button_layout.addWidget(self.send_button)

        clear_button = QPushButton("Löschen")
        clear_button.setObjectName("eiClearButton")
        clear_button.clicked.connect(lambda: self.chat_display.clear())
        button_layout.addWidget(clear_button)

        button_layout.addStretch()
        input_layout.addLayout(button_layout)

        layout.addLayout(input_layout)
        return widget

    def _build_sidebar(self) -> QFrame:
        """Baue Sidebar mit Tabs."""
        sidebar = QFrame()
        sidebar.setObjectName("eiSidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 24, 24, 24)
        layout.setSpacing(16)

        # Status-Bereich
        status_label = QLabel("Status")
        status_label.setObjectName("eiSidebarHeader")
        layout.addWidget(status_label)

        self.llm_status = QLabel("Initialisiere...")
        self.llm_status.setObjectName("eiStatusText")
        layout.addWidget(self.llm_status)

        self.docs_status = QLabel("0 Dokumente")
        self.docs_status.setObjectName("eiStatusText")
        layout.addWidget(self.docs_status)

        self.reminder_status = QLabel("0 Erinnerungen")
        self.reminder_status.setObjectName("eiStatusText")
        layout.addWidget(self.reminder_status)

        # Index Button
        self.index_button = QPushButton("Tresor indexieren")
        self.index_button.setObjectName("eiIndexButton")
        self.index_button.clicked.connect(self._on_index_current_container)
        layout.addWidget(self.index_button)

        # Tabs
        tabs = QTabWidget()
        tabs.setObjectName("eiSidebarTabs")

        # Tab 1: Dokumente
        self.documents_list = QListWidget()
        self.documents_list.setObjectName("eiDocList")
        tabs.addTab(self.documents_list, "📄 Dokumente")

        # Tab 2: Suche
        search_widget = QWidget()
        search_layout = QVBoxLayout(search_widget)
        search_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setObjectName("eiSearchInput")
        self.search_input.setPlaceholderText("Suche...")
        self.search_input.returnPressed.connect(self._on_search)
        search_layout.addWidget(self.search_input)

        self.search_results = QListWidget()
        self.search_results.setObjectName("eiSearchList")
        self.search_results.itemClicked.connect(self._on_search_result_selected)
        search_layout.addWidget(self.search_results)

        tabs.addTab(search_widget, "🔍 Suche")

        # Tab 3: Erinnerungen
        self.reminders_list = QListWidget()
        self.reminders_list.setObjectName("eiReminderList")
        tabs.addTab(self.reminders_list, "⏰ Erinnerungen")

        layout.addWidget(tabs, 1)

        # Footer
        footer_layout = QVBoxLayout()
        footer_layout.setSpacing(4)

        stats_label = QLabel("Statistiken")
        stats_label.setObjectName("eiSidebarHeader")
        footer_layout.addWidget(stats_label)

        self.stats_label = QLabel("Lade...")
        self.stats_label.setObjectName("eiStatusText")
        self.stats_label.setWordWrap(True)
        footer_layout.addWidget(self.stats_label)

        layout.addLayout(footer_layout)

        return sidebar

    def _handle_input_key(self, event) -> None:
        """Handle Enter in Chat-Input."""
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() == Qt.KeyboardModifier.ShiftModifier:
                self.chat_input.insertPlainText("\n")
            else:
                self._on_send_question()
        else:
            QTextEdit.keyPressEvent(self.chat_input, event)

    def _update_status(self) -> None:
        """Aktualisiere Status-Anzeige."""
        # LLM Status
        if self.manager.llm.is_available():
            model = self.manager.llm.model_path.stem
            backend = self.manager.llm.backend_name().replace("_", "-")
            self.llm_status.setText(f"✓ LLM ({model}, {backend})")
            self.llm_status.setStyleSheet("color: #4ade80;")
        else:
            error = (self.manager.llm.load_error() or "offline")[:30]
            self.llm_status.setText(f"⚠ LLM ({error}...)")
            self.llm_status.setStyleSheet("color: #facc15;")

        # Dokumente & Reminders
        docs = len(self.manager.list_documents())
        reminders = len(self.manager.get_reminders())
        
        self.docs_status.setText(f"{docs} Dokumente")
        self.reminder_status.setText(f"{reminders} Erinnerungen")

        # Statistiken
        stats = self.manager.get_statistics()
        self.stats_label.setText(
            f"Gesamt: {stats['documents_indexed']} Docs\n"
            f"Cache: {stats['embedding_cache_hits']} Einträge\n"
            f"Größe: {stats['total_text_size'] // 1024}KB"
        )

    def _on_send_question(self) -> None:
        """Verarbeite Chat-Nachricht."""
        question = self.chat_input.toPlainText().strip()
        if not question:
            return

        # Zeige Frage
        self.chat_display.append(f"<b style='color:#4ade80'>Du:</b> {question}\n")
        self.chat_input.clear()
        self.send_button.setEnabled(False)
        self.status_bar.setVisible(True)

        # Starte Worker
        self._question_worker = QuestionWorker(self.manager, question)
        self._question_worker.response_token.connect(self._on_response_token)
        self._question_worker.response_done.connect(self._on_response_done)
        self._question_worker.error_occurred.connect(self._on_response_error)
        self._question_worker.start()

    def _on_response_token(self, token: str) -> None:
        """Zeige Streaming-Token."""
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.chat_display.setTextCursor(cursor)
        self.chat_display.insertPlainText(token)

    def _on_response_done(self, answer: str) -> None:
        """Verarbeite fertige Antwort."""
        self.chat_display.append(f"\n<b style='color:#2f6f73'>EncryptIntelligence:</b>\n{answer}\n")
        self.send_button.setEnabled(True)
        self.status_bar.setVisible(False)
        self._refresh_sidebar()

        scrollbar = self.chat_display.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _on_response_error(self, error: str) -> None:
        """Verarbeite Fehler."""
        self.chat_display.append(f"<span style='color:#ff6b6b'>[Fehler] {error}</span>\n")
        self.send_button.setEnabled(True)
        self.status_bar.setVisible(False)

    def _on_search(self) -> None:
        """Durchsuche Dokumente."""
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
            snippet = entry['snippet'][:120]
            score_pct = int(entry['score'] * 100)
            display = f"{entry['document_name']} ({score_pct}%)\n{snippet}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, entry['document_id'])
            self.search_results.addItem(item)

    def _on_search_result_selected(self, item: QListWidgetItem) -> None:
        """Zeige Suchergebnis."""
        doc_id = item.data(Qt.ItemDataRole.UserRole)
        if not doc_id:
            return

        doc = self.manager.fetch_document(doc_id)
        if not doc:
            return

        snippet = doc['text'][:300] + ("..." if len(doc['text']) > 300 else "")
        self.chat_display.append(f"📄 <b>{doc['display_name']}</b>\n\n{snippet}\n")

    def _on_index_current_container(self) -> None:
        """Indexiere aktuellen Tresor."""
        parent = self.parent()
        if parent is None:
            QMessageBox.warning(self, "Fehler", "Kein Tresor-Fenster gefunden.")
            return

        container_path = getattr(parent, "container_path", None)
        master_key = getattr(parent, "master_key", None)
        meta = getattr(parent, "meta", None)

        if not all([container_path, master_key, meta]):
            QMessageBox.warning(self, "Fehler", "Bitte öffne zuerst einen Tresor.")
            return

        self.index_button.setEnabled(False)
        self.status_bar.setVisible(True)
        self.status_bar.setRange(0, 0)

        self._index_worker = IndexWorker(
            self.manager, container_path, meta, master_key
        )
        self._index_worker.finished.connect(self._on_index_finished)
        self._index_worker.error_occurred.connect(self._on_index_error)
        self._index_worker.start()

    def _on_index_finished(self, indexed: list, skipped: list) -> None:
        """Indexierung abgeschlossen."""
        self.index_button.setEnabled(True)
        self.status_bar.setVisible(False)
        self._refresh_sidebar()

        detail = ""
        if skipped:
            detail = f"\n\nÜbersprungen ({len(skipped)}):"
            for item in skipped[:5]:
                detail += f"\n• {item['name']}: {item['reason']}"
            if len(skipped) > 5:
                detail += f"\n• +{len(skipped)-5} weitere"

        QMessageBox.information(
            self,
            "Indexierung erfolgreich",
            f"✓ {len(indexed)} Dokument(e) indexiert.{detail}",
        )

    def _on_index_error(self, error: str) -> None:
        """Indexierung fehlgeschlagen."""
        self.index_button.setEnabled(True)
        self.status_bar.setVisible(False)
        QMessageBox.critical(self, "Indexierungsfehler", error)

    def _refresh_sidebar(self) -> None:
        """Aktualisiere Sidebar."""
        self._refresh_documents()
        self._refresh_reminders()
        self._update_status()

    def _refresh_documents(self) -> None:
        """Zeige indizierte Dokumente."""
        self.documents_list.clear()
        docs = self.manager.list_documents()

        if not docs:
            item = QListWidgetItem("Keine Dokumente")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.documents_list.addItem(item)
        else:
            for doc in docs:
                self.documents_list.addItem(QListWidgetItem(doc))

    def _refresh_reminders(self) -> None:
        """Zeige Erinnerungen."""
        self.reminders_list.clear()
        reminders = self.manager.get_reminders()

        if not reminders:
            item = QListWidgetItem("Keine Erinnerungen")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.reminders_list.addItem(item)
        else:
            for reminder in reminders:
                title = reminder.get("title", "Unbekannt")
                date = reminder.get("date", "-")
                display = f"{title}\n📅 {date}"
                item = QListWidgetItem(display)
                item.setData(Qt.ItemDataRole.UserRole, reminder)
                self.reminders_list.addItem(item)

    def _stylesheet(self) -> str:
        return """
            QDialog {
                background: #0f1319;
                color: #e7edf2;
            }

            QLabel#eiChatHeader {
                font-size: 28px;
                font-weight: 700;
                color: #f4f8fb;
            }

            QLabel#eiSidebarHeader {
                font-size: 11px;
                font-weight: 700;
                color: #94a3af;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            QTextEdit#eiChatDisplay {
                background: #0f1319;
                border: none;
                color: #e7edf2;
                font-size: 13px;
                padding: 0;
                selection-background-color: #2f6f73;
            }

            QTextEdit#eiChatInput {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 8px;
                color: #e7edf2;
                font-size: 13px;
                padding: 10px;
            }

            QTextEdit#eiChatInput:focus {
                border: 1px solid #3f8b90;
            }

            QPushButton#eiSendButton,
            QPushButton#eiClearButton {
                background: #2f6f73;
                border: none;
                border-radius: 6px;
                color: #f4f8fb;
                font-weight: 500;
                padding: 10px 16px;
                font-size: 13px;
            }

            QPushButton#eiSendButton:hover,
            QPushButton#eiClearButton:hover {
                background: #39838a;
            }

            QPushButton#eiSendButton:pressed,
            QPushButton#eiClearButton:pressed {
                background: #26575a;
            }

            QPushButton#eiSendButton:disabled {
                background: #1a3f42;
                color: #6b8185;
            }

            QPushButton#eiIndexButton {
                background: #2f6f73;
                border: none;
                border-radius: 6px;
                color: #f4f8fb;
                font-weight: 500;
                padding: 10px;
                font-size: 12px;
            }

            QPushButton#eiIndexButton:hover {
                background: #39838a;
            }

            QFrame#eiSidebar {
                background: #0f1319;
                border-left: 1px solid #2b333b;
            }

            QLabel#eiStatusText {
                font-size: 12px;
                color: #b8c7d3;
            }

            QListWidget#eiDocList,
            QListWidget#eiSearchList,
            QListWidget#eiReminderList {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 6px;
                color: #e7edf2;
                font-size: 12px;
                outline: none;
            }

            QListWidget#eiDocList::item,
            QListWidget#eiSearchList::item,
            QListWidget#eiReminderList::item {
                padding: 8px 10px;
                border-bottom: 1px solid #2b333b;
            }

            QListWidget#eiDocList::item:selected,
            QListWidget#eiSearchList::item:selected,
            QListWidget#eiReminderList::item:selected {
                background: #263d40;
                color: #4ade80;
            }

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

            QTabWidget#eiSidebarTabs {
                background: #0f1319;
                border: none;
            }

            QTabBar::tab {
                background: #181d22;
                border: 1px solid #2b333b;
                color: #b8c7d3;
                padding: 6px 12px;
                margin: 2px;
                border-radius: 4px;
            }

            QTabBar::tab:selected {
                background: #2f6f73;
                color: #f4f8fb;
                border: 1px solid #3f8b90;
            }

            QProgressBar#eiStatusBar {
                background: #181d22;
                border: 1px solid #2b333b;
                border-radius: 4px;
                height: 6px;
                text-align: center;
            }

            QProgressBar#eiStatusBar::chunk {
                background: #2f6f73;
                border-radius: 3px;
            }
        """