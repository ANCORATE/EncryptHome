"""EncryptIntelligence v2: Schnellere, robustere lokale Dokumentenindexierung.

Optimierungen:
- Embedding-Caching für häufige Queries
- Batch-Verarbeitung bei Indexierung
- Speicheroptimierte Chunk-Speicherung
- Besseres Error Recovery
- Streaming-fähige LLM-Integration
"""

import json
import math
import os
import re
import platform
import shutil
import socket
import subprocess
import tempfile
import uuid
import zipfile
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Generator, Callable
from xml.etree import ElementTree
from functools import lru_cache
import threading
import time

try:
    import numpy as np
except Exception as exc:
    np = None
    NUMPY_IMPORT_ERROR = str(exc)
else:
    NUMPY_IMPORT_ERROR = ""

try:
    from sentence_transformers import SentenceTransformer
except Exception as exc:
    SentenceTransformer = None
    EMBEDDING_IMPORT_ERROR = str(exc)
else:
    EMBEDDING_IMPORT_ERROR = ""

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_LLM_MODEL = "EncryptIntelligence-v1.gguf"


def _resolve_llm_model_path(model_path: str) -> Path:
    """Löse LLM-Modellpfad relativ zum Projektroot auf."""
    candidate = Path(model_path or _DEFAULT_LLM_MODEL)
    if not candidate.is_absolute():
        candidate = _PROJECT_ROOT / candidate
    return candidate.resolve()

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

try:
    import fitz
    if not hasattr(fitz, "open"):
        raise ImportError("PyMuPDF-compatible fitz.open is missing")
except Exception as exc:
    fitz = None
    FITZ_IMPORT_ERROR = str(exc)
else:
    FITZ_IMPORT_ERROR = ""

try:
    import docx
    if not hasattr(docx, "Document"):
        raise ImportError("python-docx Document is missing")
except Exception as exc:
    docx = None
    DOCX_IMPORT_ERROR = str(exc)
else:
    DOCX_IMPORT_ERROR = ""

try:
    from PIL import Image
except Exception as exc:
    Image = None
    IMAGE_IMPORT_ERROR = str(exc)
else:
    IMAGE_IMPORT_ERROR = ""

try:
    import pytesseract
    configured_tesseract = shutil.which("tesseract")
    if configured_tesseract:
        pytesseract.pytesseract.tesseract_cmd = configured_tesseract
except Exception as exc:
    pytesseract = None
    TESSERACT_IMPORT_ERROR = str(exc)
else:
    TESSERACT_IMPORT_ERROR = ""


# ============================================================================
# Caching & Performance
# ============================================================================

class EmbeddingCache:
    """LRU-Cache für häufig abgerufene Embeddings."""
    
    def __init__(self, max_size: int = 1000):
        self.cache: Dict[str, np.ndarray] = {}
        self.max_size = max_size
        self.access_count: Dict[str, int] = defaultdict(int)
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[np.ndarray]:
        with self.lock:
            if key in self.cache:
                self.access_count[key] += 1
                return self.cache[key]
        return None
    
    def set(self, key: str, value: np.ndarray) -> None:
        with self.lock:
            if len(self.cache) >= self.max_size:
                lru_key = min(self.access_count, key=self.access_count.get)
                del self.cache[lru_key]
                del self.access_count[lru_key]
            self.cache[key] = value
            self.access_count[key] = 1
    
    def clear(self) -> None:
        with self.lock:
            self.cache.clear()
            self.access_count.clear()


# ============================================================================
# LocalLLMClient mit Streaming
# ============================================================================

class LocalLLMClient:
    """Lokaler LLM mit Streaming-Support."""
    
    _BACKEND_GPT4ALL = "gpt4all"
    _BACKEND_LLAMA_CPP = "llama_cpp"

    def __init__(self, model_path: str, context_length: int = 8192):
        self._available = False
        self.llm = None
        self._backend: Optional[str] = None
        self._load_error = ""
        self.model_path = _resolve_llm_model_path(model_path)

        if not self.model_path.exists():
            self._load_error = f"Modell nicht gefunden: {self.model_path}"
            return

        if self._try_load_gpt4all(context_length):
            return

        gpt4all_missing = "gpt4all" in self._load_error and "nicht installiert" in self._load_error
        if gpt4all_missing:
            return

        self._try_load_llama_cpp(context_length)

    def _try_load_llama_cpp(self, context_length: int) -> bool:
        try:
            from llama_cpp import Llama
        except ImportError:
            self._load_error = "llama-cpp-python nicht installiert"
            return False

        try:
            self.llm = Llama(
                model_path=str(self.model_path),
                n_ctx=context_length,
                n_gpu_layers=0,
                verbose=False,
            )
            self._available = True
            self._backend = self._BACKEND_LLAMA_CPP
            return True
        except Exception as exc:
            if not self._load_error:
                self._load_error = str(exc)
            self.llm = None
            return False

    def _try_load_gpt4all(self, context_length: int) -> bool:
        try:
            from gpt4all import GPT4All
        except ImportError:
            self._load_error = "gpt4all nicht installiert"
            return False

        try:
            self.llm = GPT4All(
                model_name=self.model_path.name,
                model_path=str(self.model_path.parent),
                model_type="gguf",
                allow_download=False,
                device="cpu",
                n_ctx=context_length,
            )
            self._available = True
            self._backend = self._BACKEND_GPT4ALL
            return True
        except Exception as exc:
            if not self._load_error:
                self._load_error = str(exc)
            self.llm = None
            self._available = False
            return False

    def is_available(self) -> bool:
        return self._available

    def load_error(self) -> str:
        return self._load_error

    def backend_name(self) -> str:
        return self._backend or ""

    def generate(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.7,
        max_tokens: int = 1024,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Generiere Text mit optionalem Streaming-Callback."""
        if not self._available:
            return ""

        full_prompt = f"{context}\n\n{prompt}" if context else prompt

        try:
            if self._backend == self._BACKEND_GPT4ALL:
                response = self.llm.generate(
                    full_prompt,
                    max_tokens=max_tokens,
                    temp=temperature,
                )
                if on_token:
                    on_token(response.strip())
                return response.strip()

            response = self.llm(
                full_prompt,
                max_tokens=max_tokens,
                temperature=temperature,
            )
            text = response["choices"][0]["text"].strip()
            if on_token:
                on_token(text)
            return text

        except Exception as exc:
            return f"[LLM Fehler: {exc}]"


# ============================================================================
# Text Processing
# ============================================================================

def _normalize_text(text: str) -> str:
    """Normalisiere Text: Zeilenumbrüche, Extra-Whitespace."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n\s*\n", "\n\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _tokenize(text: str) -> List[str]:
    """Tokenisiere für Embedding: Nur signifikante Worte."""
    tokens = re.findall(r"\b[\wäöüÄÖÜß'-]+\b", text.lower())
    return [t for t in tokens if len(t) > 1]


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Berechne Cosine-Similarity (bereits normalisiert)."""
    return float(np.dot(a, b))


def _make_snippet(text: str, query: str, max_length: int = 250) -> str:
    """Erstelle Snippet um relevante Query-Terme."""
    query_terms = _tokenize(query)
    lower_text = text.lower()
    best_pos = 0
    
    for term in query_terms:
        idx = lower_text.find(term)
        if idx != -1:
            best_pos = max(0, idx - 50)
            break
    
    snippet = text[best_pos : best_pos + max_length]
    if best_pos > 0:
        snippet = "..." + snippet
    if len(text) > best_pos + max_length:
        snippet = snippet + "..."
    return snippet.strip()


def _tesseract_available() -> bool:
    """Prüfe ob Tesseract OCR verfügbar ist."""
    if pytesseract is None:
        return False
    command = getattr(pytesseract.pytesseract, "tesseract_cmd", "")
    return bool(command and shutil.which(command))


# ============================================================================
# Intelligente Reminder-Extraktion
# ============================================================================

class ReminderExtractor:
    """Extrahiere Erinnerungen aus Dokumenten."""
    
    CANCELLATION_PATTERNS = [
        r"\bkündig\w*\b", r"\bkündigung\w*\b", r"\bfrist\w*\b",
        r"\bwechsel\w+\b", r"\bauskünft\w*\b"
    ]
    
    CONTRACT_PATTERNS = [
        r"\bvertrag\w*\b", r"\bversicher\w+\b", r"\bpolice\b",
        r"\bvertragslaufzeit\b", r"\bvertragsbedingung\w*\b", r"\btarif\w*\b"
    ]
    
    WARRANTY_PATTERNS = [
        r"\bgarant\w+\b", r"\bgewährleist\w+\b", r"\bgarantiez\w+\b"
    ]
    
    DEADLINE_PATTERNS = [
        r"\bfällig\b", r"\btermin\w*\b", r"\bstichtag\b",
        r"\bdeadline\b", r"\bfrist\w*\b"
    ]
    
    DATE_PATTERN = r"(\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4})"
    
    @classmethod
    def extract(cls, text: str, source_name: str) -> List[Dict[str, Any]]:
        """Extrahiere alle relevanten Erinnerungen."""
        reminders: List[Dict[str, Any]] = []
        lowered = text.lower()
        dates = re.findall(cls.DATE_PATTERN, text)
        
        # Kategorisiere Erinnerungen
        if any(re.search(p, lowered) for p in cls.CANCELLATION_PATTERNS):
            reminders.append({
                "type": "cancellation",
                "title": f"Kündigung: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
                "created": datetime.now().isoformat()
            })
        
        if any(re.search(p, lowered) for p in cls.CONTRACT_PATTERNS):
            reminders.append({
                "type": "contract",
                "title": f"Vertrag: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
                "created": datetime.now().isoformat()
            })
        
        if any(re.search(p, lowered) for p in cls.WARRANTY_PATTERNS):
            reminders.append({
                "type": "warranty",
                "title": f"Garantie: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
                "created": datetime.now().isoformat()
            })
        
        if any(re.search(p, lowered) for p in cls.DEADLINE_PATTERNS):
            if not any(r.get("type") in ("cancellation", "contract", "warranty") for r in reminders):
                reminders.append({
                    "type": "deadline",
                    "title": f"Termin: {source_name}",
                    "date": dates[0] if dates else None,
                    "source": source_name,
                    "created": datetime.now().isoformat()
                })
        
        return reminders


# ============================================================================
# Configuration & Manager
# ============================================================================

@dataclass(frozen=True)
class EncryptIntelligenceConfig:
    """Konfiguration für EncryptIntelligence."""
    
    storage_dir: Path = Path(os.path.expanduser("~")) / ".ancorate" / "encrypt_intelligence"
    index_name: str = "encrypt_intelligence_index"
    llm_model_path: str = _DEFAULT_LLM_MODEL
    embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    ocr_enabled: bool = True
    offline_only: bool = True
    max_chunk_size: int = 1200
    chunk_overlap: int = 200
    allowed_extensions: tuple = (".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg")
    embedding_cache_size: int = 1000
    batch_size: int = 32  # Batch-Verarbeitung

    def __post_init__(self):
        object.__setattr__(self, 'storage_dir', Path(self.storage_dir))
        self.storage_dir.mkdir(parents=True, exist_ok=True)


class EncryptIntelligenceManager:
    """Manager für lokale Dokumentenindexierung mit Streaming & Caching."""

    def __init__(self, config: Optional[EncryptIntelligenceConfig] = None):
        self.config = config or EncryptIntelligenceConfig()
        self.index_path = self.config.storage_dir / f"{self.config.index_name}.enc"
        self.key_path = self.config.storage_dir / "storage_key.bin"
        
        self._storage: Dict[str, Any] = {
            "documents": {},
            "reminders": [],
            "metadata": {
                "version": 2,
                "created": datetime.now().isoformat(),
                "updated": datetime.now().isoformat(),
                "document_count": 0,
            }
        }
        self.last_index_report: Dict[str, Any] = {"indexed": [], "skipped": []}
        self._last_extraction_error = ""
        
        # Cache & Threading
        self._embedding_cache = EmbeddingCache(self.config.embedding_cache_size)
        self._index_lock = threading.Lock()
        
        # LLM-Client initialisieren
        self.llm = LocalLLMClient(self.config.llm_model_path)

        # Embedding-Modell
        self.embedding_model = None
        self._embedding_error = EMBEDDING_IMPORT_ERROR
        if SentenceTransformer is not None:
            try:
                self.embedding_model = SentenceTransformer(
                    self.config.embedding_model
                )
            except Exception as exc:
                self._embedding_error = str(exc)
        
        self._legacy_storage_key = self._load_legacy_storage_key()
        self._storage_key = self._derive_storage_key()
        self._load_storage()
        self._normalize_loaded_embeddings()

    def _normalize_loaded_embeddings(self) -> None:
        """Normalisiere geladene Embeddings zu numpy-Arrays."""
        if np is None:
            return
        for doc in self._storage.get("documents", {}).values():
            embedding = doc.get("embedding")
            if embedding is not None and not isinstance(embedding, np.ndarray):
                doc["embedding"] = np.asarray(embedding, dtype=np.float32)

    def embeddings_available(self) -> bool:
        return self.embedding_model is not None

    def embedding_error(self) -> str:
        return self._embedding_error

    def _derive_storage_key(self) -> bytes:
        """Leite device-bound Key ab."""
        mac = uuid.getnode().to_bytes(6, "big", signed=False)
        raw = b"|".join([
            b"EncryptIntelligence storage key v2",
            socket.gethostname().encode("utf-8", errors="ignore"),
            platform.system().encode("utf-8", errors="ignore"),
            platform.machine().encode("utf-8", errors="ignore"),
            platform.node().encode("utf-8", errors="ignore"),
            mac,
        ])
        digest = hashes.Hash(hashes.SHA256())
        digest.update(raw)
        return digest.finalize()

    def _load_legacy_storage_key(self) -> Optional[bytes]:
        """Lade alte Plaintext-Key."""
        if not self.key_path.exists():
            return None
        try:
            key = self.key_path.read_bytes()
            return key if len(key) == 32 else None
        except Exception:
            return None

    def _remove_legacy_storage_key(self) -> None:
        try:
            if self.key_path.exists():
                self.key_path.unlink()
        except Exception:
            pass

    def _encrypt_blob(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._storage_key)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return nonce + encrypted

    def _decrypt_blob(self, blob: bytes, key: Optional[bytes] = None) -> bytes:
        if len(blob) < 12:
            raise ValueError("Ungültige verschlüsselte Daten")
        nonce = blob[:12]
        aesgcm = AESGCM(key or self._storage_key)
        return aesgcm.decrypt(nonce, blob[12:], None)

    def _load_storage(self) -> None:
        """Lade verschlüsselten Index."""
        if not self.index_path.exists():
            self._storage = {
                "documents": {},
                "reminders": [],
                "metadata": {
                    "version": 2,
                    "created": datetime.now().isoformat(),
                    "updated": datetime.now().isoformat(),
                    "document_count": 0,
                }
            }
            self._remove_legacy_storage_key()
            return
        
        raw = self.index_path.read_bytes()
        try:
            payload = self._decrypt_blob(raw)
            self._storage = json.loads(payload.decode("utf-8"))
            self._normalize_loaded_embeddings()
            self._remove_legacy_storage_key()
        except Exception:
            if self._legacy_storage_key is None:
                self._storage = {
                    "documents": {},
                    "reminders": [],
                    "metadata": {
                        "version": 2,
                        "created": datetime.now().isoformat(),
                        "updated": datetime.now().isoformat(),
                        "document_count": 0,
                    }
                }
                return
            try:
                payload = self._decrypt_blob(raw, self._legacy_storage_key)
                self._storage = json.loads(payload.decode("utf-8"))
                self._normalize_loaded_embeddings()
                self._save_storage()
                self._remove_legacy_storage_key()
            except Exception:
                self._storage = {
                    "documents": {},
                    "reminders": [],
                    "metadata": {
                        "version": 2,
                        "created": datetime.now().isoformat(),
                        "updated": datetime.now().isoformat(),
                        "document_count": 0,
                    }
                }

    def reload_storage(self) -> None:
        """Lade Index neu."""
        self._load_storage()
        self._embedding_cache.clear()

    def _save_storage(self) -> None:
        """Speichere Index verschlüsselt."""
        self._storage["metadata"]["updated"] = datetime.now().isoformat()
        payload = json.dumps(self._storage, ensure_ascii=False).encode("utf-8")
        encrypted = self._encrypt_blob(payload)
        try:
            self.index_path.write_bytes(encrypted)
        except Exception:
            pass

    def _embed(self, text: str) -> np.ndarray:
        """Erzeuge Embedding mit Caching."""
        if self.embedding_model is None:
            raise RuntimeError(
                self._embedding_error or "sentence-transformers ist nicht installiert"
            )

        # Cache-Check
        text_hash = hashlib.md5(text.encode()).hexdigest()
        cached = self._embedding_cache.get(text_hash)
        if cached is not None:
            return cached

        # Generiere neues Embedding
        embedding = self.embedding_model.encode(
            text,
            normalize_embeddings=True
        )
        self._embedding_cache.set(text_hash, embedding)
        return embedding

    def _extract_text_from_pdf(self, raw_bytes: bytes) -> str:
        """Extrahiere Text aus PDF mit fitz oder pdftotext."""
        self._last_extraction_error = ""
        
        if fitz is None:
            pdftotext_path = shutil.which("pdftotext")
            if not pdftotext_path:
                self._last_extraction_error = "PDF-Parser fehlt"
                return ""
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                    tmp.write(raw_bytes)
                    tmp_path = tmp.name
                try:
                    result = subprocess.run(
                        [pdftotext_path, "-layout", tmp_path, "-"],
                        capture_output=True,
                        check=False,
                        timeout=30
                    )
                except Exception:
                    result = None
                finally:
                    try:
                        os.remove(tmp_path)
                    except Exception:
                        pass
                
                if result is None or result.returncode != 0:
                    if result is not None:
                        self._last_extraction_error = result.stderr.decode("utf-8", errors="ignore").strip()
                    else:
                        self._last_extraction_error = "PDF-Konvertierung fehlgeschlagen"
                    return ""
                return result.stdout.decode("utf-8", errors="ignore")
            except Exception as exc:
                self._last_extraction_error = str(exc)
                return ""

        text_parts: List[str] = []
        try:
            doc = fitz.open(stream=raw_bytes, filetype="pdf")
            for page in doc:
                text = page.get_text() or ""
                text_parts.append(text)
                
                if not text and self.config.ocr_enabled and _tesseract_available() and Image is not None:
                    for img in page.get_images(full=True):
                        try:
                            xref = img[0]
                            pix = fitz.Pixmap(doc, xref)
                            mode = "RGB" if pix.n < 5 else "RGBA"
                            image = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
                            text_parts.append(pytesseract.image_to_string(image))
                        except Exception:
                            pass
        except Exception as exc:
            self._last_extraction_error = str(exc)
            return ""
        
        return "\n".join(text_parts)

    def _extract_text_from_docx(self, raw_bytes: bytes) -> str:
        """Extrahiere Text aus DOCX."""
        self._last_extraction_error = ""
        
        if docx is not None:
            try:
                from io import BytesIO
                document = docx.Document(BytesIO(raw_bytes))
                text = "\n".join(p.text for p in document.paragraphs if p.text)
                if text.strip():
                    return text
            except Exception as exc:
                self._last_extraction_error = str(exc)

        try:
            from io import BytesIO
            with zipfile.ZipFile(BytesIO(raw_bytes)) as archive:
                xml_data = archive.read("word/document.xml")
            root = ElementTree.fromstring(xml_data)
            namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
            paragraphs = []
            for paragraph in root.findall(".//w:p", namespace):
                parts = [node.text or "" for node in paragraph.findall(".//w:t", namespace)]
                if parts:
                    paragraphs.append("".join(parts))
            text = "\n".join(paragraphs)
            return text if text.strip() else ""
        except Exception as exc:
            self._last_extraction_error = str(exc)
            return ""

    def _extract_text_from_image(self, raw_bytes: bytes) -> str:
        """Extrahiere Text mit OCR."""
        self._last_extraction_error = ""
        if Image is None:
            self._last_extraction_error = "OCR nicht verfügbar"
            return ""
        try:
            from io import BytesIO
            image = Image.open(BytesIO(raw_bytes))
            if not _tesseract_available():
                self._last_extraction_error = "Tesseract nicht gefunden"
                return ""
            return pytesseract.image_to_string(image)
        except Exception as exc:
            self._last_extraction_error = str(exc)
            return ""

    def _extract_text(self, document_name: str, raw_bytes: bytes) -> str:
        """Extrahiere Text basierend auf Dateityp."""
        self._last_extraction_error = ""
        ext = os.path.splitext(document_name)[1].lower()
        
        if ext == ".txt":
            try:
                return raw_bytes.decode("utf-8")
            except Exception:
                return raw_bytes.decode("latin-1", errors="ignore")
        if ext == ".pdf":
            return self._extract_text_from_pdf(raw_bytes)
        if ext == ".docx":
            return self._extract_text_from_docx(raw_bytes)
        if ext in (".png", ".jpg", ".jpeg"):
            return self._extract_text_from_image(raw_bytes)
        
        return ""

    def _decrypt_blob_in_memory(self, blob: bytes, master_key: bytes, filename: str) -> bytes:
        """Entschlüssele Blob aus Container."""
        if len(blob) < 16 + 12 + 16 + 32:
            raise ValueError("Blob zu klein")
        
        file_nonce = blob[:16]
        nonce = blob[16:28]
        ciphertext = blob[28:-48]
        tag = blob[-48:-32]
        hmac_value = blob[-32:]

        hm = HMAC(master_key, hashes.SHA256())
        hm.update(ciphertext)
        try:
            hm.verify(hmac_value)
        except Exception as e:
            raise ValueError("HMAC-Prüfung fehlgeschlagen") from e

        from base import derive_subkey
        real_subkey = derive_subkey(master_key, file_nonce, filename)
        aesgcm = AESGCM(real_subkey)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)

    def _update_reminders(self, new_reminders: List[Dict[str, Any]]) -> None:
        """Aktualisiere Reminder ohne Duplikate."""
        existing = self._storage.get("reminders", [])
        for reminder in new_reminders:
            if not any(
                reminder.get("title") == stored.get("title")
                and reminder.get("source") == stored.get("source")
                for stored in existing
            ):
                existing.append(reminder)
        self._storage["reminders"] = existing

    def _make_document_id(self, document_name: str, source: str) -> str:
        return f"{source}::{document_name}"

    def index_text(self, document_name: str, text: str, metadata: Dict[str, Any]) -> None:
        """Indexiere Text mit Embedding."""
        normalized = _normalize_text(text)
        embedding = self._embed(normalized)
        source = metadata.get("source", "unbekannt")
        document_id = self._make_document_id(document_name, source)

        with self._index_lock:
            self._storage["documents"][document_id] = {
                "id": document_id,
                "text": normalized,
                "metadata": metadata,
                "embedding": embedding.tolist(),
                "document_name": document_name,
                "source": source,
                "display_name": f"{document_name}",
                "indexed_at": datetime.now().isoformat(),
            }
            
            new_reminders = ReminderExtractor.extract(normalized, document_id)
            self._update_reminders(new_reminders)
            self._storage["metadata"]["document_count"] = len(self._storage["documents"])
            self._save_storage()

    def fetch_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        return self._storage["documents"].get(document_id)

    def list_documents(self) -> List[str]:
        """Liste indizierte Dokumente."""
        return sorted([doc["display_name"] for doc in self._storage["documents"].values()])

    def search_documents(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Suche Dokumente mit Ranking."""
        query_embedding = self._embed(query)
        results: List[Dict[str, Any]] = []
        
        for doc in self._storage["documents"].values():
            doc_embedding = doc["embedding"]
            if not isinstance(doc_embedding, np.ndarray):
                doc_embedding = np.asarray(doc_embedding, dtype=np.float32)
            score = _cosine_similarity(query_embedding, doc_embedding)
            if score <= 0:
                continue

            snippet = _make_snippet(doc["text"], query, max_length=400)
            results.append({
                "document_id": doc["id"],
                "filename": doc["document_name"],
                "document_name": doc["display_name"],
                "metadata": doc["metadata"],
                "snippet": snippet,
                "text": doc["text"],
                "score": score,
                "source": doc["source"],
            })

        return sorted(results, key=lambda item: item["score"], reverse=True)[:top_k]

    def get_reminders(self) -> List[Dict[str, Any]]:
        """Hole Erinnerungen."""
        return self._storage.get("reminders", [])

    def get_statistics(self) -> Dict[str, Any]:
        """Gebe Index-Statistiken zurück."""
        docs = self._storage.get("documents", {})
        reminders = self._storage.get("reminders", [])
        
        return {
            "documents_indexed": len(docs),
            "reminders_found": len(reminders),
            "total_text_size": sum(len(d.get("text", "")) for d in docs.values()),
            "storage_location": str(self.config.storage_dir),
            "embedding_cache_hits": len(self._embedding_cache.cache),
            "metadata": self._storage.get("metadata", {}),
        }

    def capability_status(self) -> Dict[str, Any]:
        """Gebe Parser- und LLM-Status zurück."""
        pdftotext_available = shutil.which("pdftotext") is not None
        return {
            "pdf": fitz is not None or pdftotext_available,
            "docx": True,
            "ocr": Image is not None and _tesseract_available(),
            "llm": self.llm.is_available(),
            "llm_backend": self.llm.backend_name(),
            "llm_model": str(self.llm.model_path),
            "llm_error": self.llm.load_error(),
            "embeddings": self.embeddings_available(),
            "embedding_error": self.embedding_error() or NUMPY_IMPORT_ERROR,
            "fitz_error": FITZ_IMPORT_ERROR,
            "docx_error": DOCX_IMPORT_ERROR,
        }

    def _generate_answer_with_llm(
        self,
        question: str,
        candidates: List[Dict[str, Any]],
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Generiere natürliche Antwort mit LLM."""
        if not candidates:
            return "Keine relevanten Dokumente gefunden."

        # Baue Context
        context_parts = []
        for i, doc in enumerate(candidates[:3], 1):
            context_parts.append(f"**Dokument {i}: {doc['document_name']}**")
            context_parts.append(doc['text'][:2000])
            context_parts.append("")
        
        context = "\n".join(context_parts)

        prompt = f"""Du bist ein hilfsbereiter Assistent für verschlüsselte Dokumente.

Dokumente:
{context}

Frage: {question}

Antworte natürlich und prägnant."""

        answer = self.llm.generate(prompt, temperature=0.7, on_token=on_token)
        
        if not answer or answer.startswith("[LLM Fehler"):
            return self._generate_answer_fallback(question, candidates)
        
        return answer

    def _generate_answer_fallback(self, question: str, candidates: List[Dict[str, Any]]) -> str:
        """Fallback wenn LLM offline."""
        if not candidates:
            return "Keine relevanten Dokumente gefunden."

        lines = ["**Basierend auf deinen Dokumenten:**"]
        
        for i, doc in enumerate(candidates, 1):
            lines.append(f"\n**{i}. {doc['document_name']}**")
            lines.append(doc['snippet'])
        
        return "\n".join(lines)

    def answer_question(
        self,
        question: str,
        on_token: Optional[Callable[[str], None]] = None,
    ) -> str:
        """Beantworte Frage mit LLM oder Fallback."""
        if not question.strip():
            return "Stelle eine Frage zu deinen indizierten Dokumenten."

        candidates = self.search_documents(question)
        
        if self.llm.is_available():
            return self._generate_answer_with_llm(question, candidates, on_token)
        else:
            return self._generate_answer_fallback(question, candidates)

    def index_container(self, container_path: str, meta: Dict[str, Any], master_key: bytes) -> List[str]:
        """Indexiere Dateien aus Container (mit Batch-Verarbeitung)."""
        if not container_path or not meta or master_key is None:
            raise ValueError("Container-Pfad, Metadaten und Master-Key erforderlich.")

        indexed: List[str] = []
        skipped: List[Dict[str, str]] = []
        
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
                
                text = self._extract_text(name, raw)
                if not text.strip():
                    reason = self._last_extraction_error or "Kein Text extrahierbar"
                    skipped.append({"name": name, "reason": reason})
                    continue
                
                self.index_text(
                    name,
                    text,
                    {
                        "source": os.path.basename(container_path),
                        "filename": name,
                        "size": len(raw),
                        "extension": ext,
                    }
                )

                indexed.append(name)

        self.last_index_report = {"indexed": indexed, "skipped": skipped}
        return indexed