"""EncryptIntelligence UI v3: Chat-Interface mit Keyword-Suche."""

import re
from typing import Optional
from datetime import datetime

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QTextCursor
from PyQt6.QtWidgets import (
    QDialog, QHBoxLayout, QVBoxLayout, QWidget, QTextEdit, QPushButton,
    QLineEdit, QListWidget, QListWidgetItem, QLabel, QMessageBox,
    QFrame, QSplitter, QTabWidget, QProgressBar,
)


class QuestionWorker(QThread):
    response_token = pyqtSignal(str)
    response_done = pyqtSignal(str)
    error_occurred = pyqtSignal(str)

    def __init__(self, manager, question: str):
        super().__init__()
        self.manager = manager
        self.question = question
        self._buffer = ""

    def _on_token(self, token: str) -> None:
        self._buffer += token
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


class EncryptIntelligenceDialog(QDialog):

    def __init__(self, parent=None, manager=None):
        super().__init__(parent)
        self.setWindowTitle("EncryptIntelligence")
        self.resize(1400, 800)
        self.setMinimumSize(1000, 600)
        self.setModal(False)

        if manager is None:
            try:
                from .core import EncryptIntelligenceManager
                manager = EncryptIntelligenceManager()
            except Exception as e:
                QMessageBox.critical(self, "Fehler", f"Manager konnte nicht geladen werden: {e}")
                raise

        self.manager = manager
        self._question_worker: Optional[QuestionWorker] = None
        self._index_worker: Optional[IndexWorker] = None
        self._build_ui()
        self._refresh_sidebar()
        self._update_status()

    def _build_ui(self) -> None:
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_chat_area())
        splitter.addWidget(self._build_sidebar())
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        root.addWidget(splitter)

        self.setStyleSheet(self._stylesheet())

    def _build_chat_area(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        header = QLabel("EncryptIntelligence")
        f = QFont()
        f.setPointSize(24)
        f.setBold(True)
        header.setFont(f)
        header.setObjectName("eiChatHeader")
        layout.addWidget(header)

        self.chat_display = QTextEdit()
        self.chat_display.setObjectName("eiChatDisplay")
        self.chat_display.setReadOnly(True)
        self.chat_display.setPlaceholderText("Stelle eine Frage zu deinen indizierten Dokumenten...")
        layout.addWidget(self.chat_display, 1)

        input_area = QVBoxLayout()
        input_area.setSpacing(8)

        self.status_bar = QProgressBar()
        self.status_bar.setObjectName("eiStatusBar")
        self.status_bar.setVisible(False)
        self.status_bar.setMaximumHeight(20)
        input_area.addWidget(self.status_bar)

        self.chat_input = QTextEdit()
        self.chat_input.setObjectName("eiChatInput")
        self.chat_input.setFixedHeight(80)
        self.chat_input.setPlaceholderText("Deine Frage...")
        self.chat_input.keyPressEvent = self._handle_input_key
        input_area.addWidget(self.chat_input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.send_button = QPushButton("Senden")
        self.send_button.setObjectName("eiSendButton")
        self.send_button.clicked.connect(self._on_send_question)
        btn_row.addWidget(self.send_button)
        clear_btn = QPushButton("Löschen")
        clear_btn.setObjectName("eiClearButton")
        clear_btn.clicked.connect(lambda: self.chat_display.clear())
        btn_row.addWidget(clear_btn)
        btn_row.addStretch()
        input_area.addLayout(btn_row)

        layout.addLayout(input_area)
        return w

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("eiSidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(16, 24, 24, 24)
        layout.setSpacing(16)

        layout.addWidget(self._sidebar_label("Status"))
        self.llm_status = QLabel("Initialisiere...")
        self.llm_status.setObjectName("eiStatusText")
        layout.addWidget(self.llm_status)
        self.docs_status = QLabel("0 Dokumente")
        self.docs_status.setObjectName("eiStatusText")
        layout.addWidget(self.docs_status)
        self.reminder_status = QLabel("0 Erinnerungen")
        self.reminder_status.setObjectName("eiStatusText")
        layout.addWidget(self.reminder_status)

        self.index_button = QPushButton("Tresor indexieren")
        self.index_button.setObjectName("eiIndexButton")
        self.index_button.clicked.connect(self._on_index_current_container)
        layout.addWidget(self.index_button)

        tabs = QTabWidget()
        tabs.setObjectName("eiSidebarTabs")

        self.documents_list = QListWidget()
        self.documents_list.setObjectName("eiDocList")
        tabs.addTab(self.documents_list, "📄 Dokumente")

        search_tab = QWidget()
        search_layout = QVBoxLayout(search_tab)
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
        tabs.addTab(search_tab, "🔍 Suche")

        self.reminders_list = QListWidget()
        self.reminders_list.setObjectName("eiReminderList")
        tabs.addTab(self.reminders_list, "⏰ Erinnerungen")

        layout.addWidget(tabs, 1)

        layout.addWidget(self._sidebar_label("Statistiken"))
        self.stats_label = QLabel("Lade...")
        self.stats_label.setObjectName("eiStatusText")
        self.stats_label.setWordWrap(True)
        layout.addWidget(self.stats_label)

        return sidebar

    def _sidebar_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setObjectName("eiSidebarHeader")
        return lbl

    def _handle_input_key(self, event) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            if event.modifiers() == Qt.KeyboardModifier.ShiftModifier:
                self.chat_input.insertPlainText("\n")
            else:
                self._on_send_question()
        else:
            QTextEdit.keyPressEvent(self.chat_input, event)

    def _update_status(self) -> None:
        if self.manager.llm.is_available():
            model = self.manager.llm.model_path.stem
            self.llm_status.setText(f"✓ LLM ({model})")
            self.llm_status.setStyleSheet("color: #10b981;")
        else:
            error = (self.manager.llm.load_error() or "offline")[:30]
            self.llm_status.setText(f"⚠ LLM ({error}...)")
            self.llm_status.setStyleSheet("color: #facc15;")

        docs = len(self.manager.list_documents())
        reminders = len(self.manager.get_reminders())
        self.docs_status.setText(f"{docs} Dokumente")
        self.reminder_status.setText(f"{reminders} Erinnerungen")

        stats = self.manager.get_statistics()
        self.stats_label.setText(
            f"Gesamt: {stats['documents_indexed']} Docs\n"
            f"Größe: {stats['total_text_size'] // 1024}KB"
        )

    def _on_send_question(self) -> None:
        question = self.chat_input.toPlainText().strip()
        if not question:
            return
        self.chat_display.append(f"<b style='color:#3f8cff'>Du:</b> {question}\n")
        self.chat_input.clear()
        self.send_button.setEnabled(False)
        self.status_bar.setVisible(True)

        self._question_worker = QuestionWorker(self.manager, question)
        self._question_worker.response_token.connect(self._on_response_token)
        self._question_worker.response_done.connect(self._on_response_done)
        self._question_worker.error_occurred.connect(self._on_response_error)
        self._question_worker.start()

    def _on_response_token(self, token: str) -> None:
        cursor = self.chat_display.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.chat_display.setTextCursor(cursor)
        self.chat_display.insertPlainText(token)

    def _on_response_done(self, answer: str) -> None:
        self.chat_display.append(f"\n<b style='color:#2f7cf6'>EncryptIntelligence:</b>\n{answer}\n")
        self.send_button.setEnabled(True)
        self.status_bar.setVisible(False)
        self._refresh_sidebar()
        sb = self.chat_display.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _on_response_error(self, error: str) -> None:
        self.chat_display.append(f"<span style='color:#ff6b6b'>[Fehler] {error}</span>\n")
        self.send_button.setEnabled(True)
        self.status_bar.setVisible(False)

    def _on_search(self) -> None:
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
            snippet = entry["snippet"][:120]
            score_pct = int(entry["score"] * 100)
            display = f"{entry['document_name']} ({score_pct}%)\n{snippet}"
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, entry["document_id"])
            self.search_results.addItem(item)

    def _on_search_result_selected(self, item: QListWidgetItem) -> None:
        doc_id = item.data(Qt.ItemDataRole.UserRole)
        if not doc_id:
            return
        doc = self.manager.fetch_document(doc_id)
        if not doc:
            return
        snippet = doc["text"][:300] + ("..." if len(doc["text"]) > 300 else "")
        self.chat_display.append(f"📄 <b>{doc['display_name']}</b>\n\n{snippet}\n")

    def _on_index_current_container(self) -> None:
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
        self._index_worker = IndexWorker(self.manager, container_path, meta, master_key)
        self._index_worker.finished.connect(self._on_index_finished)
        self._index_worker.error_occurred.connect(self._on_index_error)
        self._index_worker.start()

    def _on_index_finished(self, indexed: list, skipped: list) -> None:
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
            self, "Indexierung erfolgreich",
            f"✓ {len(indexed)} Dokument(e) indexiert.{detail}",
        )

    def _on_index_error(self, error: str) -> None:
        self.index_button.setEnabled(True)
        self.status_bar.setVisible(False)
        QMessageBox.critical(self, "Indexierungsfehler", error)

    def _refresh_sidebar(self) -> None:
        self._refresh_documents()
        self._refresh_reminders()
        self._update_status()

    def _refresh_documents(self) -> None:
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
        self.reminders_list.clear()
        reminders = self.manager.get_reminders()
        if not reminders:
            item = QListWidgetItem("Keine Erinnerungen")
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.reminders_list.addItem(item)
        else:
            for r in reminders:
                title = r.get("title", "Unbekannt")
                date = r.get("date", "-")
                item = QListWidgetItem(f"{title}\n📅 {date}")
                item.setData(Qt.ItemDataRole.UserRole, r)
                self.reminders_list.addItem(item)

    def _stylesheet(self) -> str:
        return """
            QDialog { background: #0b0f16; color: #e6eef8; }
            QLabel#eiChatHeader { font-size: 28px; font-weight: 700; color: #ffffff; }
            QLabel#eiSidebarHeader { font-size: 11px; font-weight: 700; color: #9fb0d8; text-transform: uppercase; letter-spacing: 0.5px; }
            QTextEdit#eiChatDisplay { background: #0b0f16; border: none; color: #e6eef8; font-size: 13px; padding: 0; selection-background-color: #163a73; }
            QTextEdit#eiChatInput { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; color: #e6eef8; font-size: 13px; padding: 10px; }
            QTextEdit#eiChatInput:focus { border: 1px solid #2a78ff; background: #13203a; }
            QPushButton#eiSendButton, QPushButton#eiClearButton { background: #0f1522; border: 1px solid rgba(255,255,255,0.08); border-radius: 10px; color: #ffffff; font-weight: 600; padding: 9px 16px; font-size: 13px; min-height: 36px; }
            QPushButton#eiSendButton:hover, QPushButton#eiClearButton:hover { background: #121a2b; border: 1px solid #2a78ff; }
            QPushButton#eiSendButton:pressed, QPushButton#eiClearButton:pressed { background: #0b1220; border: 1px solid #1f5ed6; }
            QPushButton#eiSendButton:disabled { background: #0b0f16; color: #3a4152; border: 1px solid #1a1f2a; }
            QPushButton#eiIndexButton { background: #2f7cf6; border: none; border-radius: 10px; color: white; font-weight: 700; padding: 10px; font-size: 12px; min-height: 36px; }
            QPushButton#eiIndexButton:hover { background: #3f8cff; }
            QPushButton#eiIndexButton:pressed { background: #2265d1; }
            QFrame#eiSidebar { background: #0b0f16; border-left: 1px solid rgba(255,255,255,0.06); }
            QLabel#eiStatusText { font-size: 12px; color: #cfd8ea; }
            QListWidget#eiDocList, QListWidget#eiSearchList, QListWidget#eiReminderList { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; color: #e6eef8; font-size: 12px; outline: none; }
            QListWidget#eiDocList::item, QListWidget#eiSearchList::item, QListWidget#eiReminderList::item { padding: 8px 10px; border-bottom: 1px solid rgba(255,255,255,0.06); }
            QListWidget#eiDocList::item:selected, QListWidget#eiSearchList::item:selected, QListWidget#eiReminderList::item:selected { background: #163a73; color: white; }
            QLineEdit#eiSearchInput { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; color: #e6eef8; font-size: 12px; padding: 9px 12px; }
            QLineEdit#eiSearchInput:focus { border: 1px solid #2a78ff; background: #13203a; }
            QTabWidget#eiSidebarTabs { background: #0b0f16; border: none; }
            QTabBar::tab { background: #111827; border: 1px solid rgba(255,255,255,0.06); color: #cfd8ea; padding: 8px 14px; margin: 2px; border-radius: 10px; }
            QTabBar::tab:selected { background: #163a73; color: white; border: 1px solid #2a78ff; }
            QProgressBar#eiStatusBar { background: #111827; border: 1px solid rgba(255,255,255,0.06); border-radius: 10px; height: 6px; text-align: center; }
            QProgressBar#eiStatusBar::chunk { background: #2f7cf6; border-radius: 5px; }
        """
