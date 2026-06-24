"""EncryptIntelligence: Leichtgewichtiges Indexierungs- und Suchsystem."""

import locale
import hashlib
import json
import math
import os
import platform
import re
import socket
import sqlite3
import threading
import time
import uuid
import zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

try:
    import fitz
    if not hasattr(fitz, "open"):
        raise ImportError("PyMuPDF-compatible fitz.open is missing")
except Exception:
    fitz = None

try:
    import docx
    if not hasattr(docx, "Document"):
        raise ImportError("python-docx Document is missing")
except Exception:
    docx = None

try:
    import pypdf
except Exception:
    pypdf = None

try:
    from PIL import Image
except Exception:
    Image = None

try:
    import easyocr
    _easyocr_reader = None
except Exception:
    easyocr = None

# easyocr verwendet Unicode-Zeichen für Fortschrittsbalken,
# die auf Windows mit cp1252 zu Fehlern führen – daher UTF-8 erzwingen.
if os.name == "nt" and locale.getencoding() != "utf-8":
    os.environ["PYTHONIOENCODING"] = "utf-8"


# ============================================================================
# Model-Registry: 3 Tiers
# ============================================================================

_MODELS_DIR = Path(os.path.expanduser("~")) / ".ancorate" / "encrypt_models"

TIER_LIGHT = "EncryptIntelligence Light"
TIER_BASE = "EncryptIntelligence Base"
TIER_PRO = "EncryptIntelligence Pro"

_MODEL_REGISTRY = {
    TIER_LIGHT: {
        "filename": "qwen2-1_5b-instruct-q4_0.gguf",
        "url": "https://huggingface.co/Qwen/Qwen2-1.5B-Instruct-GGUF/resolve/main/qwen2-1_5b-instruct-q4_0.gguf",
        "filesize": 937532800,
        "md5": "a8c5a783105f87a481543d4ed7d7586d",
        "ram_gb": 3,
        "description": "1,5 Mrd. Parameter, ~900 MB Download, sehr schnell, ideal für schwache Systeme",
        "system_prompt": (
            "Extrahiere die Antwort aus den untenstehenden Dokumenten. "
            "Nenne nur die Fakten. Keine Erklärungen."
        ),
    },
    TIER_BASE: {
        "filename": "mistral-7b-instruct-v0.1.Q4_0.gguf",
        "url": "https://gpt4all.io/models/gguf/mistral-7b-instruct-v0.1.Q4_0.gguf",
        "filesize": 4108916384,
        "md5": "97463be739b50525df56d33b26b00852",
        "ram_gb": 8,
        "description": "7 Mrd. Parameter, ~3,9 GB Download, gute Qualität, empfohlen für die meisten Systeme",
        "system_prompt": (
            "Du bist EncryptIntelligence Base. Deine Wissensbasis sind die "
            "unten als 'Relevante Dokumente' aufgelisteten Inhalte. Diese "
            "wurden von einer Suchmaschine aus dem verschlüsselten Tresor "
            "des Benutzers abgerufen. Antworte AUSSCHLIESSLICH auf Basis "
            "dieser Dokumente. Wenn die Dokumente keine Antwort enthalten, "
            "sage es klar. Antworte natürlich und prägnant auf Deutsch."
        ),
    },
    TIER_PRO: {
        "filename": "Meta-Llama-3-8B-Instruct.Q4_0.gguf",
        "url": "https://gpt4all.io/models/gguf/Meta-Llama-3-8B-Instruct.Q4_0.gguf",
        "filesize": 4661724384,
        "md5": "c87ad09e1e4c8f9c35a5fcef52b6f1c9",
        "ram_gb": 16,
        "description": "8 Mrd. Parameter, ~4,3 GB Download, höchste Qualität, erfordert starke Hardware",
        "system_prompt": (
            "Du bist EncryptIntelligence Pro. Deine Wissensbasis sind die "
            "unten als 'Relevante Dokumente' aufgelisteten Inhalte. Diese "
            "wurden von einer Suchmaschine aus dem verschlüsselten Tresor "
            "des Benutzers abgerufen. Antworte AUSSCHLIESSLICH auf Basis "
            "dieser Dokumente. Wenn die Dokumente keine Antwort enthalten, "
            "sage es klar. Analysiere gründlich und beziehe dich auf "
            "konkrete Textstellen. Antworte auf Deutsch."
        ),
    },
}

AVAILABLE_TIERS = [TIER_LIGHT, TIER_BASE, TIER_PRO]


def get_models_dir() -> Path:
    _MODELS_DIR.mkdir(parents=True, exist_ok=True)
    return _MODELS_DIR


def get_model_info(tier: str) -> Optional[dict]:
    return _MODEL_REGISTRY.get(tier)


def resolve_model_path(tier: str) -> Optional[Path]:
    info = get_model_info(tier)
    if info is None:
        return None
    return get_models_dir() / info["filename"]


def get_system_prompt(tier: str) -> str:
    info = get_model_info(tier)
    if info is None:
        return "Du bist ein hilfsbereiter Assistent für verschlüsselte Dokumente."
    return info["system_prompt"]


def download_model(
    tier: str,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Optional[Path]:
    """Lädt ein Modell aus der Registry herunter. Gibt den Pfad zurück oder None bei Fehler."""
    info = get_model_info(tier)
    if info is None:
        raise ValueError(f"Unbekannter Tier: {tier}")

    models_dir = get_models_dir()
    dest = models_dir / info["filename"]
    if dest.exists():
        return dest

    url = info["url"]
    temp_dest = dest.with_suffix(dest.suffix + ".partial")
    try:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))
        downloaded = 0
        with open(temp_dest, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if progress_callback and total:
                        progress_callback(downloaded, total)
        temp_dest.rename(dest)
        # MD5 prüfen
        if info.get("md5"):
            h = hashlib.md5()
            with open(dest, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            if h.hexdigest() != info["md5"]:
                dest.unlink()
                raise ValueError("MD5-Prüfung fehlgeschlagen – Download korrupt")
        return dest
    except Exception:
        if temp_dest.exists():
            temp_dest.unlink()
        raise


# ============================================================================
# Tokenisierung & Text-Helfer
# ============================================================================


# ============================================================================
# Tokenisierung & Text-Helfer
# ============================================================================

def _tokenize(text: str) -> List[str]:
    return re.findall(r"\b[\wäöüÄÖÜß]+\b", text.lower())


def _normalize_text(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n\s*\n", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _make_snippet(text: str, query: str, max_length: int = 250) -> str:
    query_terms = _tokenize(query)
    lower_text = text.lower()
    best_pos = 0
    for term in query_terms:
        idx = lower_text.find(term)
        if idx != -1:
            best_pos = max(0, idx - 50)
            break
    snippet = text[best_pos: best_pos + max_length]
    if best_pos > 0:
        snippet = "..." + snippet
    if len(text) > best_pos + max_length:
        snippet += "..."
    return snippet.strip()


def _ocr_available() -> bool:
    return easyocr is not None


def _ocr_image(img) -> str:
    """Extrahiert Text aus einem Bild mittels easyocr (Lazy Loading)."""
    global _easyocr_reader
    if easyocr is None:
        return ""
    try:
        if _easyocr_reader is None:
            # Lazy Loading des Readers erst beim ersten OCR-Aufruf
            try:
                import torch
                gpu = torch.cuda.is_available()
            except Exception:
                gpu = False
            # Initialisierung kann mehrere Sekunden dauern
            _easyocr_reader = easyocr.Reader(["de", "en"], gpu=gpu)
        
        arr = img.convert("RGB")
        import numpy as np
        result = _easyocr_reader.readtext(np.array(arr), detail=0, paragraph=True)
        return "\n".join(result)
    except Exception:
        return ""


# ============================================================================
# TextIndex – leichtgewichtige Keyword-Suche (kein numpy/ML)
# ============================================================================

class TextIndex:
    """In-Memory Volltextindex mit TF-IDF-Ranking und invertiertem Index."""

    def __init__(self):
        self._docs: Dict[str, dict] = {}
        self._idf: Dict[str, float] = {}
        self._inverted_index: Dict[str, List[str]] = {}
        self._batch_mode = False

    def set_batch_mode(self, enabled: bool) -> None:
        """Aktiviert/Deaktiviert den Batch-Modus. Bei Deaktivierung wird der IDF-Index neu aufgebaut."""
        self._batch_mode = enabled
        if not enabled:
            self._rebuild_idf()

    def add(self, doc_id: str, text: str, metadata: dict) -> None:
        tokens = _tokenize(text)
        term_counts = Counter(tokens)
        self._docs[doc_id] = {
            "text": text,
            "term_counts": term_counts,
            "metadata": metadata,
        }
        # Invertierten Index aktualisieren
        for term in term_counts:
            if term not in self._inverted_index:
                self._inverted_index[term] = []
            self._inverted_index[term].append(doc_id)
            
        if not self._batch_mode:
            self._rebuild_idf()

    def remove(self, doc_id: str) -> None:
        if doc_id in self._docs:
            doc = self._docs.pop(doc_id)
            # Aus invertiertem Index entfernen
            for term in doc["term_counts"]:
                if term in self._inverted_index:
                    self._inverted_index[term].remove(doc_id)
                    if not self._inverted_index[term]:
                        del self._inverted_index[term]
            if not self._batch_mode:
                self._rebuild_idf()

    def clear(self) -> None:
        self._docs.clear()
        self._idf.clear()
        self._inverted_index.clear()

    def doc_count(self) -> int:
        return len(self._docs)

    def _rebuild_idf(self) -> None:
        n = len(self._docs)
        if n == 0:
            self._idf.clear()
            return
        self._idf = {
            term: math.log(1 + (n - len(doc_ids) + 0.5) / (len(doc_ids) + 0.5))
            for term, doc_ids in self._inverted_index.items()
        }

    def _tfidf(self, term: str, count: int) -> float:
        if count == 0:
            return 0.0
        tf = 1 + math.log10(count)
        idf = self._idf.get(term, 0.0)
        return tf * idf

    def search(self, query: str, top_k: int = 5) -> List[Tuple[str, float]]:
        query_terms = _tokenize(query)
        if not query_terms or not self._docs:
            return []
        
        query_counts = Counter(query_terms)
        # Nur Dokumente betrachten, die mindestens einen Query-Term enthalten (Invertierter Index)
        candidate_ids = set()
        for term in query_counts:
            if term in self._inverted_index:
                candidate_ids.update(self._inverted_index[term])
        
        if not candidate_ids:
            return []

        scores: List[Tuple[str, float]] = []
        for doc_id in candidate_ids:
            doc = self._docs[doc_id]
            dot = 0.0
            q_norm = 0.0
            d_norm = 0.0
            for term, qc in query_counts.items():
                qv = self._tfidf(term, qc)
                q_norm += qv * qv
                dc = doc["term_counts"].get(term, 0)
                dv = self._tfidf(term, dc)
                d_norm += dv * dv
                dot += qv * dv
            if q_norm == 0.0 or d_norm == 0.0:
                continue
            score = dot / (math.sqrt(q_norm) * math.sqrt(d_norm))
            if score > 0:
                scores.append((doc_id, score))
        
        scores.sort(key=lambda x: -x[1])
        return scores[:top_k]


# ============================================================================
# Text-Extraktion aus Dateiformaten
# ============================================================================

class DocumentExtractor:
    """Extrahiert Text aus PDF, DOCX, TXT, Bilder."""

    def __init__(self):
        self.last_error = ""

    def extract(self, name: str, raw: bytes) -> str:
        self.last_error = ""
        ext = os.path.splitext(name)[1].lower()
        if ext == ".txt":
            return self._from_txt(raw)
        if ext == ".pdf":
            return self._from_pdf(raw)
        if ext == ".docx":
            return self._from_docx(raw)
        if ext in (".png", ".jpg", ".jpeg"):
            return self._from_image(raw)
        self.last_error = f"Typ '{ext}' nicht unterstützt"
        return ""

    def _from_txt(self, raw: bytes) -> str:
        try:
            return raw.decode("utf-8")
        except Exception:
            return raw.decode("latin-1", errors="ignore")

    def _from_pdf(self, raw: bytes) -> str:
        if fitz is not None:
            try:
                parts = []
                doc = fitz.open(stream=raw, filetype="pdf")
                for page in doc:
                    text = page.get_text() or ""
                    parts.append(text)
                    if not text and _ocr_available() and Image is not None:
                        for img in page.get_images(full=True):
                            try:
                                xref = img[0]
                                pix = fitz.Pixmap(doc, xref)
                                mode = "RGB" if pix.n < 5 else "RGBA"
                                image = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
                                parts.append(_ocr_image(image))
                            except Exception:
                                pass
                return "\n".join(parts)
            except Exception as e:
                self.last_error = str(e)

        if pypdf is not None:
            try:
                from io import BytesIO
                reader = pypdf.PdfReader(BytesIO(raw))
                parts = []
                for page in reader.pages:
                    text = page.extract_text() or ""
                    parts.append(text)
                return "\n".join(parts)
            except Exception as e:
                self.last_error = str(e)
                return ""

        self.last_error = "PDF-Parser fehlt (PyMuPDF oder pypdf)"
        return ""

    def _from_docx(self, raw: bytes) -> str:
        if docx is not None:
            try:
                from io import BytesIO
                d = docx.Document(BytesIO(raw))
                text = "\n".join(p.text for p in d.paragraphs if p.text)
                if text.strip():
                    return text
            except Exception as e:
                self.last_error = str(e)
        try:
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(raw)) as z:
                xml = z.read("word/document.xml")
            root = ElementTree.fromstring(xml)
            ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            parts = []
            for p in root.findall(".//w:p", ns):
                texts = [t.text or "" for t in p.findall(".//w:t", ns)]
                if texts:
                    parts.append("".join(texts))
            return "\n".join(parts)
        except Exception as e:
            self.last_error = str(e)
            return ""

    def _from_image(self, raw: bytes) -> str:
        if Image is None:
            self.last_error = "Pillow nicht installiert"
            return ""
        if not _ocr_available():
            self.last_error = "easyocr nicht installiert"
            return ""
        try:
            from io import BytesIO
            img = Image.open(BytesIO(raw))
            return _ocr_image(img)
        except Exception as e:
            self.last_error = str(e)
            return ""

def _parallel_extract_task(extractor_instance, name, raw):
    """Globale Hilfsfunktion für Multiprocessing-Tasks."""
    return extractor_instance.extract(name, raw)


# ============================================================================
# LLM-Client (nur gpt4all)
# ============================================================================

class LocalLLMClient:
    """Wrapper für gpt4all mit asynchronem Laden."""

    def __init__(self, model_path: str, context_length: int = 8192):
        self._available = False
        self.llm = None
        self._load_error = ""
        self._loading = False
        self._gpt4all_class = None
        self._context_length = context_length
        self.model_path = Path(model_path) if model_path else Path()

        if not model_path or not self.model_path.exists():
            self._load_error = f"Modell nicht gefunden: {self.model_path}" if model_path else "Kein Modell konfiguriert"
            return

        try:
            from gpt4all import GPT4All
            self._gpt4all_class = GPT4All
        except ImportError:
            self._load_error = "gpt4all nicht installiert"

    def load(self) -> None:
        """Lädt das Modell synchron (blockierend)."""
        if self._available or self._gpt4all_class is None:
            return
        self._loading = True
        self._load_model(self._gpt4all_class, self._context_length)
        self._loading = False

    def load_async(self, callback: Optional[Callable[[bool], None]] = None) -> None:
        """Lädt das Modell im Hintergrund-Thread."""
        def _run():
            self.load()
            if callback:
                callback(self._available)
        threading.Thread(target=_run, daemon=True).start()

    def is_loading(self) -> bool:
        return self._loading

    def _load_model(self, GPT4All, context_length: int) -> None:
        """Erzeugt GPT4All-Instanz und prüft, ob das Modell wirklich geladen wurde."""
        # C-Level stderr unterdrücken (CUDA-DLL-Fehler, etc.)
        orig_stderr = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        os.close(devnull)
        try:
            self.llm = GPT4All(
                model_name=self.model_path.name,
                model_path=str(self.model_path.parent),
                model_type="gguf",
                allow_download=False,
                device="cpu",
                n_ctx=context_length,
            )
        except Exception as exc:
            self._load_error = str(exc)
            self.llm = None
            return
        finally:
            os.dup2(orig_stderr, 2)
            os.close(orig_stderr)

        if self.llm is None:
            return

        # Prüfen ob das Modell wirklich geladen wurde (z.B. inkompatibler Tokenizer)
        try:
            self.llm.model.thread_count()
            self._available = True
        except Exception:
            self.llm = None
            self._load_error = (
                "Modell konnte nicht geladen werden – möglicherweise inkompatibler "
                "Tokenizer. Verwende ein Standard-GGUF-Modell (z.B. Mistral, Llama)."
            )

    def is_available(self) -> bool:
        return self._available

    def load_error(self) -> str:
        return self._load_error

    def backend_name(self) -> str:
        return "gpt4all" if self._available else ""

    def generate(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: float = 0.01,
        max_tokens: int = 40,
        repeat_penalty: float = 1.2,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        if not self._available or self.llm is None:
            return ""
        try:
            collected: list = []
            with self.llm.chat_session(system_prompt=system_prompt or None):
                for tok in self.llm.generate(
                    prompt, max_tokens=max_tokens, temp=temperature,
                    repeat_penalty=repeat_penalty, streaming=True,
                ):
                    if tok.strip() in ("<|im_end|>", "</s>", "<|eot_id|>", "<|endoftext|>"):
                        break
                    collected.append(tok)
                    if on_token:
                        on_token(tok)
            return "".join(collected).strip()
        except Exception as exc:
            return f"[LLM Fehler: {exc}]"


# ============================================================================
# Konfiguration
# ============================================================================

@dataclass
class EncryptIntelligenceConfig:
    storage_dir: Path = Path(os.path.expanduser("~")) / ".ancorate" / "encrypt_intelligence"
    index_name: str = "encrypt_intelligence_index"
    model_tier: str = TIER_LIGHT
    ocr_enabled: bool = True
    max_chunk_size: int = 1200
    allowed_extensions: tuple = (".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg")

    def __post_init__(self):
        self.storage_dir = Path(self.storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    @property
    def llm_model_path(self) -> str:
        path = resolve_model_path(self.model_tier)
        return str(path) if path else ""

    @llm_model_path.setter
    def llm_model_path(self, value: str) -> None:
        pass


# ============================================================================
# Manager
# ============================================================================

class EncryptIntelligenceManager:
    """Manager für lokale Dokumentenindexierung mit SQLite-Persistenz und Multiprocessing."""

    def __init__(self, config: Optional[EncryptIntelligenceConfig] = None):
        self.config = config or EncryptIntelligenceConfig()
        self.db_path = self.config.storage_dir / "intelligence.db"
        self.key_path = self.config.storage_dir / "storage_key.bin"

        self.last_index_report: dict = {"indexed": [], "skipped": []}
        self._last_extraction_error = ""
        self._index_lock = threading.Lock()

        # Text-Index (Keyword-Suche)
        self._text_index = TextIndex()

        # System-Prompt je nach Tier
        self._system_prompt = get_system_prompt(self.config.model_tier)

        # LLM (lädt im Hintergrund)
        self.llm = LocalLLMClient(self.config.llm_model_path)
        self.llm.load_async()

        # Document Extractor
        self._extractor = DocumentExtractor()
        self._executor = ProcessPoolExecutor(max_workers=os.cpu_count())

        # Storage & Encryption
        self._storage_key = self._derive_storage_key()
        self._init_db()
        self._load_all_to_index()

    # --- Storage I/O (SQLite + AES-GCM) ---

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            # Haupttabelle für Dokumente
            conn.execute("""
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    hash TEXT,
                    encrypted_data BLOB,
                    indexed_at TEXT
                )
            """)
            # FTS5 Tabelle für Volltextsuche (unverschlüsselt für Performance, aber lokal)
            # Hinweis: Wenn maximale Sicherheit gewünscht, müsste FTS5 entfallen, 
            # aber für Performance ist dies der Standardweg.
            try:
                conn.execute("CREATE VIRTUAL TABLE IF NOT EXISTS fts_idx USING fts5(id UNINDEXED, content)")
            except sqlite3.OperationalError:
                # Falls FTS5 nicht verfügbar ist (selten)
                pass
            
            # OCR Cache
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ocr_cache (
                    hash TEXT PRIMARY KEY,
                    text TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

    def _derive_storage_key(self) -> bytes:
        mac = uuid.getnode().to_bytes(6, "big", signed=False)
        raw = b"|".join([
            b"EncryptIntelligence storage key v4",
            socket.gethostname().encode("utf-8", errors="ignore"),
            platform.system().encode("utf-8", errors="ignore"),
            platform.machine().encode("utf-8", errors="ignore"),
            platform.node().encode("utf-8", errors="ignore"),
            mac,
        ])
        d = hashes.Hash(hashes.SHA256())
        d.update(raw)
        return d.finalize()

    def _encrypt_blob(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._storage_key)
        return nonce + aesgcm.encrypt(nonce, data, None)

    def _decrypt_blob(self, blob: bytes) -> bytes:
        if len(blob) < 12:
            raise ValueError("Ungültige verschlüsselte Daten")
        nonce = blob[:12]
        aesgcm = AESGCM(self._storage_key)
        return aesgcm.decrypt(nonce, blob[12:], None)

    def _load_all_to_index(self) -> None:
        """Lädt alle Dokumente aus der DB in den In-Memory Suchindex."""
        self._text_index.clear()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT id, encrypted_data FROM documents")
            for doc_id, encrypted_data in cursor:
                try:
                    data = json.loads(self._decrypt_blob(encrypted_data).decode("utf-8"))
                    self._text_index.add(doc_id, data["text"], data["metadata"])
                except Exception:
                    continue
        self._text_index._rebuild_idf()

    def _save_document_to_db(self, doc_id: str, data: dict) -> None:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        encrypted = self._encrypt_blob(payload)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO documents (id, encrypted_data, indexed_at) VALUES (?, ?, ?)",
                (doc_id, encrypted, datetime.now().isoformat())
            )

    def reload_storage(self) -> None:
        self._load_all_to_index()

    def _save_storage(self) -> None:
        # Platzhalter für Kompatibilität mit altem Code
        pass

    # --- Dokumenten-Management ---

    def _make_document_id(self, name: str, source: str) -> str:
        return f"{source}::{name}"

    def batch_index_start(self) -> None:
        """Startet den Batch-Modus für effiziente Massenindexierung."""
        with self._index_lock:
            self._text_index.set_batch_mode(True)

    def batch_index_end(self) -> None:
        """Beendet den Batch-Modus und baut den Index final auf."""
        with self._index_lock:
            self._text_index.set_batch_mode(False)
            self._save_storage()

    def index_text(self, name: str, text: str, metadata: dict, file_hash: Optional[str] = None) -> None:
        normalized = _normalize_text(text)
        source = metadata.get("source", "unbekannt")
        doc_id = self._make_document_id(name, source)
        
        doc_data = {
            "id": doc_id,
            "text": normalized,
            "metadata": metadata,
            "document_name": name,
            "source": source,
            "display_name": name,
            "indexed_at": datetime.now().isoformat(),
        }
        
        with self._index_lock:
            # In SQLite speichern
            payload = json.dumps(doc_data, ensure_ascii=False).encode("utf-8")
            encrypted = self._encrypt_blob(payload)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO documents (id, hash, encrypted_data, indexed_at) VALUES (?, ?, ?, ?)",
                    (doc_id, file_hash, encrypted, datetime.now().isoformat())
                )
                # FTS Index aktualisieren
                try:
                    conn.execute("INSERT OR REPLACE INTO fts_idx (id, content) VALUES (?, ?)", (doc_id, normalized))
                except sqlite3.OperationalError:
                    pass
            
            # In-Memory Index ebenfalls aktualisieren (Fallback)
            self._text_index.add(doc_id, normalized, metadata)

    def is_already_indexed(self, name: str, source: str, file_hash: str) -> bool:
        """Prüft via Hash, ob eine Datei bereits unverändert indiziert wurde."""
        doc_id = self._make_document_id(name, source)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT hash FROM documents WHERE id = ?", (doc_id,))
            row = cursor.fetchone()
            return row is not None and row[0] == file_hash

    def get_ocr_cache(self, file_hash: str) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT text FROM ocr_cache WHERE hash = ?", (file_hash,))
            row = cursor.fetchone()
            return row[0] if row else None

    def set_ocr_cache(self, file_hash: str, text: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT OR REPLACE INTO ocr_cache (hash, text) VALUES (?, ?)", (file_hash, text))

    def fetch_document(self, doc_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT encrypted_data FROM documents WHERE id = ?", (doc_id,))
            row = cursor.fetchone()
            if row:
                return json.loads(self._decrypt_blob(row[0]).decode("utf-8"))
        return None

    def list_documents(self) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT encrypted_data FROM documents")
            names = []
            for row in cursor:
                try:
                    data = json.loads(self._decrypt_blob(row[0]).decode("utf-8"))
                    names.append(data.get("display_name", "Unbekannt"))
                except Exception:
                    continue
            return sorted(names)

    # --- Suche ---

    def search_documents(self, query: str, top_k: int = 5) -> List[dict]:
        if not query.strip():
            return []
            
        # Versuche zuerst FTS5 Suche
        out = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                # FTS5 nutzt BM25 Ranking automatisch
                cursor = conn.execute(
                    "SELECT id, snippet(fts_idx, 1, '...', '...', '...', 64) FROM fts_idx WHERE fts_idx MATCH ? ORDER BY rank LIMIT ?",
                    (query, top_k)
                )
                for doc_id, snippet in cursor:
                    doc = self.fetch_document(doc_id)
                    if doc:
                        out.append({
                            "document_id": doc_id,
                            "filename": doc["document_name"],
                            "document_name": doc["display_name"],
                            "metadata": doc["metadata"],
                            "snippet": snippet,
                            "text": doc["text"],
                            "score": 1.0, # FTS5 Rank ist nicht direkt 0-1
                            "source": doc["source"],
                        })
            if out:
                return out
        except sqlite3.OperationalError:
            # Fallback auf In-Memory TF-IDF wenn FTS5 fehlschlägt
            pass

        results = self._text_index.search(query, top_k)
        for doc_id, score in results:
            doc = self.fetch_document(doc_id)
            if doc is None:
                continue
            snippet = _make_snippet(doc["text"], query, max_length=400)
            out.append({
                "document_id": doc_id,
                "filename": doc["document_name"],
                "document_name": doc["display_name"],
                "metadata": doc["metadata"],
                "snippet": snippet,
                "text": doc["text"],
                "score": score,
                "source": doc["source"],
            })
        return out

    # --- Statistiken ---

    def get_statistics(self) -> dict:
        docs = self._storage.get("documents", {})
        return {
            "documents_indexed": len(docs),
            "total_text_size": sum(len(d.get("text", "")) for d in docs.values()),
            "storage_location": str(self.config.storage_dir),
            "metadata": self._storage.get("metadata", {}),
        }

    # --- Capability Status ---

    def capability_status(self) -> dict:
        return {
            "pdf": fitz is not None or pypdf is not None,
            "docx": True,
            "ocr": Image is not None and _ocr_available(),
            "llm": self.llm.is_available(),
            "llm_backend": self.llm.backend_name(),
            "llm_model": str(self.llm.model_path),
            "llm_error": self.llm.load_error(),
            "llm_tier": self.config.model_tier,
            "search": True,
        }

    def embeddings_available(self) -> bool:
        return True

    def embedding_error(self) -> str:
        return ""

    # --- Frage-Antwort mit LLM ---

    def answer_question(
        self,
        question: str,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        if not question.strip():
            return "Stelle eine Frage zu deinen indizierten Dokumenten."
        candidates = self.search_documents(question)
        if self.llm.is_available():
            return self._answer_with_llm(question, candidates, on_token)
        return self._answer_fallback(candidates)

    def _answer_with_llm(
        self, question: str, candidates: List[dict],
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        good = [c for c in candidates if c.get("score", 0) > 0.6]
        if not good:
            return self._answer_fallback(candidates)
        parts = []
        for doc in good[:2]:
            snippet = (doc.get("snippet") or doc.get("text", ""))[:300]
            parts.append(f"- {doc['document_name']}: {snippet}")
        context = "\n".join(parts)
        prompt = f"Relevante Dokumente:\n{context}\n\nFrage: {question}"
        answer = self.llm.generate(
            prompt, system_prompt=self._system_prompt,
            on_token=on_token,
        )
        if not answer or answer.startswith("[LLM Fehler"):
            return self._answer_fallback(candidates)
        return answer

    def _answer_fallback(self, candidates: List[dict]) -> str:
        if not candidates:
            return "Keine relevanten Dokumente gefunden."
        lines = ["**Basierend auf deinen Dokumenten:**"]
        for i, doc in enumerate(candidates, 1):
            lines.append(f"\n**{i}. {doc['document_name']}**")
            lines.append(doc["snippet"])
        return "\n".join(lines)

    # --- Container-Indexierung ---

    def _decrypt_blob_in_memory(self, blob: bytes, master_key: bytes, filename: str) -> bytes:
        if len(blob) < 16 + 12 + 16 + 32:
            raise ValueError("Blob zu klein")
        file_nonce = blob[:16]
        nonce = blob[16:28]
        ciphertext = blob[28:-48]
        tag = blob[-48:-32]
        hmac_val = blob[-32:]

        hm = HMAC(master_key, hashes.SHA256())
        hm.update(ciphertext)
        try:
            hm.verify(hmac_val)
        except Exception as e:
            raise ValueError("HMAC-Prüfung fehlgeschlagen") from e

        from base import derive_subkey
        subkey = derive_subkey(master_key, file_nonce, filename)
        aesgcm = AESGCM(subkey)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)

    def index_container(self, container_path: str, meta: dict, master_key: bytes) -> List[str]:
        if not container_path or not meta or master_key is None:
            raise ValueError("Container-Pfad, Metadaten und Master-Key erforderlich.")
        indexed: List[str] = []
        skipped: List[dict] = []
        with open(container_path, "rb") as fh:
            for entry in meta.get("files", []):
                name = entry.get("name")
                if not name:
                    skipped.append({"name": "<unbekannt>", "reason": "Dateiname fehlt"})
                    continue
                ext = os.path.splitext(name)[1].lower()
                if ext not in self.config.allowed_extensions:
                    skipped.append({"name": name, "reason": f"Typ '{ext}' nicht unterstützt"})
                    continue
                fh.seek(entry.get("offset", 0))
                blob = fh.read(entry.get("length", 0))
                if not blob:
                    skipped.append({"name": name, "reason": "Leerer Blob"})
                    continue
                try:
                    raw = self._decrypt_blob_in_memory(blob, master_key, name)
                except Exception:
                    skipped.append({"name": name, "reason": "Entschlüsselung fehlgeschlagen"})
                    continue
                text = self._extractor.extract(name, raw)
                if not text.strip():
                    reason = self._extractor.last_error or "Kein Text extrahierbar"
                    skipped.append({"name": name, "reason": reason})
                    continue
                self.index_text(name, text, {
                    "source": os.path.basename(container_path),
                    "filename": name,
                    "size": len(raw),
                    "extension": ext,
                })
                indexed.append(name)
        self.last_index_report = {"indexed": indexed, "skipped": skipped}
        return indexed
