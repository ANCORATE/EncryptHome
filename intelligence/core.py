"""Kernfunktionalität für EncryptIntelligence.

Dieses Modul definiert die Konfiguration und die Managerklasse für lokale Dokumentenindexierung,
RAG-basierte Antwortgenerierung und den Schutz sensibler Inhalte.
"""

import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

try:
    import fitz
except ImportError:
    fitz = None

try:
    import docx
except ImportError:
    docx = None

try:
    from PIL import Image
except ImportError:
    Image = None

try:
    import pytesseract
except ImportError:
    pytesseract = None


def _normalize_text(text: str) -> str:
    text = text.replace("\r", "\n")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _tokenize(text: str) -> List[str]:
    tokens = re.findall(r"\b[\wäöüÄÖÜß'-]+\b", text.lower())
    return [t for t in tokens if len(t) > 1]


def _cosine_similarity(a: Dict[str, float], b: Dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a.get(k, 0.0) * b.get(k, 0.0) for k in a)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0.0 or norm_b == 0.0:
        return 0.0
    return dot / (norm_a * norm_b)


def _make_snippet(text: str, query: str, max_length: int = 300) -> str:
    query_terms = _tokenize(query)
    lower_text = text.lower()
    best_pos = 0
    for term in query_terms:
        idx = lower_text.find(term)
        if idx != -1:
            best_pos = idx
            break
    start = max(0, best_pos - 80)
    snippet = text[start : start + max_length]
    if start > 0:
        snippet = "..." + snippet
    if len(text) > start + max_length:
        snippet = snippet + "..."
    return snippet


@dataclass(frozen=True)
class EncryptIntelligenceConfig:
    """Konfiguration für das lokale EncryptIntelligence-Modul."""

    storage_dir: Path = Path(os.path.expanduser("~")) / ".ancorate" / "encrypt_intelligence"
    index_name: str = "encrypt_intelligence_index"
    model_name: str = "qwen3-8b"
    embedding_model: str = "bge-m3"
    ocr_enabled: bool = True
    offline_only: bool = True
    max_chunk_size: int = 1200
    chunk_overlap: int = 200
    allowed_extensions: tuple = (".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg")

    def __post_init__(self):
        self.storage_dir.mkdir(parents=True, exist_ok=True)


class EncryptIntelligenceManager:
    """Manager für Dokumentenindexierung, RAG-Abfragen und Erinnerungsextraktion."""

    def __init__(self, config: Optional[EncryptIntelligenceConfig] = None):
        self.config = config or EncryptIntelligenceConfig()
        self.index_path = self.config.storage_dir / f"{self.config.index_name}.enc"
        self.key_path = self.config.storage_dir / "storage_key.bin"
        self._storage: Dict[str, Any] = {
            "documents": {},
            "reminders": [],
        }
        self._storage_key = self._load_or_create_storage_key()
        self._load_storage()

    def _load_or_create_storage_key(self) -> bytes:
        if self.key_path.exists():
            key = self.key_path.read_bytes()
            if len(key) == 32:
                return key

        key = os.urandom(32)
        try:
            self.key_path.write_bytes(key)
            os.chmod(self.key_path, 0o600)
        except Exception:
            pass
        return key

    def _encrypt_blob(self, data: bytes) -> bytes:
        nonce = os.urandom(12)
        aesgcm = AESGCM(self._storage_key)
        encrypted = aesgcm.encrypt(nonce, data, None)
        return nonce + encrypted

    def _decrypt_blob(self, blob: bytes) -> bytes:
        if len(blob) < 12:
            raise ValueError("Ungültige verschlüsselte Daten")
        nonce = blob[:12]
        aesgcm = AESGCM(self._storage_key)
        return aesgcm.decrypt(nonce, blob[12:], None)

    def _load_storage(self) -> None:
        if not self.index_path.exists():
            self._storage = {"documents": {}, "reminders": []}
            return
        try:
            raw = self.index_path.read_bytes()
            payload = self._decrypt_blob(raw)
            self._storage = json.loads(payload.decode("utf-8"))
        except Exception:
            self._storage = {"documents": {}, "reminders": []}

    def reload_storage(self) -> None:
        """Lädt den lokal gespeicherten Index erneut aus dem verschlüsselten Speicher."""
        self._load_storage()

    def _save_storage(self) -> None:
        payload = json.dumps(self._storage, ensure_ascii=False).encode("utf-8")
        encrypted = self._encrypt_blob(payload)
        try:
            self.index_path.write_bytes(encrypted)
        except Exception:
            pass

    def _embed(self, text: str) -> Dict[str, float]:
        tokens = _tokenize(_normalize_text(text))
        counter = Counter(tokens)
        total = sum(counter.values())
        if total == 0:
            return {}
        return {token: count / total for token, count in counter.items()}

    def _extract_text_from_pdf(self, raw_bytes: bytes) -> str:
        if fitz is None:
            return ""
        text_parts: List[str] = []
        try:
            doc = fitz.open(stream=raw_bytes, filetype="pdf")
            for page in doc:
                text = page.get_text() or ""
                text_parts.append(text)
                if not text and self.config.ocr_enabled and pytesseract is not None:
                    for img in page.get_images(full=True):
                        xref = img[0]
                        pix = fitz.Pixmap(doc, xref)
                        if pix.n < 5:
                            mode = "RGB"
                        else:
                            mode = "RGBA"
                        image = Image.frombytes(mode, [pix.width, pix.height], pix.samples)
                        text_parts.append(pytesseract.image_to_string(image))
        except Exception:
            return ""
        return "\n".join(text_parts)

    def _extract_text_from_docx(self, raw_bytes: bytes) -> str:
        if docx is None:
            return ""
        try:
            from io import BytesIO

            document = docx.Document(BytesIO(raw_bytes))
            return "\n".join(p.text for p in document.paragraphs if p.text)
        except Exception:
            return ""

    def _extract_text_from_image(self, raw_bytes: bytes) -> str:
        if Image is None:
            return ""
        try:
            from io import BytesIO

            image = Image.open(BytesIO(raw_bytes))
            if pytesseract is None:
                return ""
            return pytesseract.image_to_string(image)
        except Exception:
            return ""

    def _extract_text(self, document_name: str, raw_bytes: bytes) -> str:
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
        normalized = _normalize_text(text)
        embedding = self._embed(normalized)
        source = metadata.get("source", "unbekannt")
        document_id = self._make_document_id(document_name, source)

        self._storage["documents"][document_id] = {
            "id": document_id,
            "text": normalized,
            "metadata": metadata,
            "embedding": embedding,
            "document_name": document_name,
            "source": source,
            "display_name": f"{document_name} ({source})",
        }
        self._update_reminders(self.extract_reminders(normalized, document_id))
        self._save_storage()

    def fetch_document(self, document_id: str) -> Optional[Dict[str, Any]]:
        return self._storage["documents"].get(document_id)

    def list_documents(self) -> List[str]:
        return sorted(
            [doc["display_name"] for doc in self._storage["documents"].values()]
        )

    def search_documents(self, query: str) -> List[Dict[str, Any]]:
        query_embedding = self._embed(query)
        results: List[Dict[str, Any]] = []
        for doc in self._storage["documents"].values():
            score = _cosine_similarity(query_embedding, doc["embedding"])
            if score <= 0:
                continue

            snippet = _make_snippet(doc["text"], query)
            results.append(
                {
                    "document_id": doc["id"],
                    "filename": doc["document_name"],
                    "document_name": doc["display_name"],
                    "metadata": doc["metadata"],
                    "snippet": snippet,
                    "score": score,
                    "source": doc["source"],
                }
            )

        return sorted(results, key=lambda item: item["score"], reverse=True)

    def extract_reminders(self, text: str, source_name: str) -> List[Dict[str, Any]]:
        reminders: List[Dict[str, Any]] = []
        lowered = text.lower()
        dates = re.findall(r"\b(\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{4}[./-]\d{1,2}[./-]\d{1,2})\b", text)
        if "kündigung" in lowered or "kündigungsfrist" in lowered:
            reminders.append({
                "title": f"Kündigungsfrist erkennen: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
            })
        if "vertrag" in lowered or "versicher" in lowered:
            reminders.append({
                "title": f"Vertragsinformation: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
            })
        if "garantie" in lowered:
            reminders.append({
                "title": f"Garantiehinweis: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
            })
        if "ausweis" in lowered:
            reminders.append({
                "title": f"Ausweis geprüft: {source_name}",
                "date": dates[0] if dates else None,
                "source": source_name,
            })
        return reminders

    def get_reminders(self) -> List[Dict[str, Any]]:
        return self._storage.get("reminders", [])

    def _generate_answer(self, question: str, candidates: List[Dict[str, Any]]) -> str:
        header = f"Antwort zu Ihrer Frage: '{question}'\n\n"
        if not candidates:
            return "Keine relevanten Dokumente gefunden. Bitte indizieren Sie zuerst Dateien im Tresor."

        top = candidates[:3]
        sources = sorted({entry["source"] for entry in top})
        summary_lines = [
            f"Ich habe relevante Informationen in {len(top)} Dokumenten gefunden, unter anderem aus: {', '.join(sources)}."
        ]

        for entry in top:
            summary_lines.append(
                f"- {entry['document_name']} (Score: {entry['score']:.2f}): {entry['snippet']}"
            )

        if len(candidates) > 3:
            remaining = len(candidates) - 3
            summary_lines.append(f"Weitere {remaining} Dokumente enthalten ebenfalls relevante Treffer.")

        summary_lines.append("\nDiese Antwort wurde lokal aus Ihren indizierten Dokumenten generiert.")
        return header + "\n".join(summary_lines)

    def answer_question(self, question: str) -> str:
        if not question.strip():
            return "Bitte stellen Sie eine Frage."

        candidates = self.search_documents(question)
        return self._generate_answer(question, candidates)

    def index_container(self, container_path: str, meta: Dict[str, Any], master_key: bytes) -> List[str]:
        if not container_path or not meta or master_key is None:
            raise ValueError("Containerpfad, Metadaten und Master-Key werden benötigt.")

        indexed: List[str] = []
        with open(container_path, "rb") as fh:
            for entry in meta.get("files", []):
                name = entry.get("name")
                ext = os.path.splitext(name)[1].lower()
                if ext not in self.config.allowed_extensions:
                    continue
                fh.seek(entry.get("offset", 0))
                blob = fh.read(entry.get("length", 0))
                if not blob:
                    continue
                try:
                    raw = self._decrypt_blob_in_memory(blob, master_key, name)
                except Exception:
                    continue
                text = self._extract_text(name, raw)
                if not text.strip():
                    continue
                self.index_text(
                    name,
                    text,
                    {
                        "source": os.path.basename(container_path),
                        "filename": name,
                        "size": len(raw),
                        "extension": ext,
                    },
                )
                indexed.append(name)
        return indexed
