"""Lazy Loading Module für EncryptIntelligence - verhindert blocking Imports.
"""

from typing import Optional, Any
from pathlib import Path
import threading


class LazyLocalLLMClient:
    """Proxy für LocalLLMClient mit Lazy Initialization."""
    
    def __init__(self, model_path: str, context_length: int = 8192):
        self._model_path = model_path
        self._context_length = context_length
        self._real_client = None
        self._initialized = False
        self._lock = threading.Lock()
        self._init_error: Optional[Exception] = None
    
    def _ensure_initialized(self) -> None:
        """Initialisiere echten Client beim ersten Zugriff."""
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            
            try:
                from .core import LocalLLMClient
                self._real_client = LocalLLMClient(self._model_path, self._context_length)
                self._initialized = True
            except Exception as e:
                self._init_error = e
                self._initialized = True
    
    def is_available(self) -> bool:
        self._ensure_initialized()
        if self._real_client is None:
            return False
        return self._real_client.is_available()
    
    def load_error(self) -> str:
        self._ensure_initialized()
        if self._init_error:
            return str(self._init_error)
        if self._real_client is None:
            return "Client nicht initialisiert"
        return self._real_client.load_error()
    
    def backend_name(self) -> str:
        self._ensure_initialized()
        if self._real_client is None:
            return ""
        return self._real_client.backend_name()
    
    @property
    def model_path(self) -> Path:
        self._ensure_initialized()
        if self._real_client is None:
            from .core import _resolve_llm_model_path
            return _resolve_llm_model_path(self._model_path)
        return self._real_client.model_path
    
    def generate(
        self,
        prompt: str,
        context: str = "",
        temperature: float = 0.7,
        max_tokens: int = 1024,
        on_token=None,
    ) -> str:
        self._ensure_initialized()
        if self._real_client is None:
            return ""
        return self._real_client.generate(prompt, context, temperature, max_tokens, on_token)


class LazyEmbeddingModel:
    """Proxy für Sentence Transformers mit Lazy Initialization."""
    
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self._model_name = model_name
        self._real_model = None
        self._initialized = False
        self._lock = threading.Lock()
        self._init_error: Optional[Exception] = None
    
    def _ensure_initialized(self) -> None:
        """Initialisiere echtes Modell beim ersten Zugriff."""
        if self._initialized:
            return
        
        with self._lock:
            if self._initialized:
                return
            
            try:
                from sentence_transformers import SentenceTransformer
                self._real_model = SentenceTransformer(self._model_name)
                self._initialized = True
            except Exception as e:
                self._init_error = e
                self._initialized = True
    
    def is_available(self) -> bool:
        self._ensure_initialized()
        return self._real_model is not None
    
    def load_error(self) -> str:
        self._ensure_initialized()
        if self._init_error:
            return str(self._init_error)
        if self._real_model is None:
            return "Embedding Modell nicht verfügbar"
        return ""
    
    def encode(self, text: str, normalize_embeddings: bool = True):
        """Encode mit automatischer Initialisierung."""
        self._ensure_initialized()
        if self._real_model is None:
            raise RuntimeError(f"Embedding Modell nicht geladen: {self.load_error()}")
        return self._real_model.encode(text, normalize_embeddings=normalize_embeddings)


# ============================================================================
# Factory Functions mit Lazy Loading
# ============================================================================

_lazy_llm_instance = None
_lazy_embedding_instance = None


def get_lazy_llm_client(model_path: str = "EncryptIntelligence-v1.gguf", context_length: int = 8192) -> LazyLocalLLMClient:
    """Hole oder erstelle Lazy LLM Client (Singleton)."""
    global _lazy_llm_instance
    if _lazy_llm_instance is None:
        _lazy_llm_instance = LazyLocalLLMClient(model_path, context_length)
    return _lazy_llm_instance


def get_lazy_embedding_model(model_name: str = "sentence-transformers/all-MiniLM-L6-v2") -> LazyEmbeddingModel:
    """Hole oder erstelle Lazy Embedding Model (Singleton)."""
    global _lazy_embedding_instance
    if _lazy_embedding_instance is None:
        _lazy_embedding_instance = LazyEmbeddingModel(model_name)
    return _lazy_embedding_instance


# ============================================================================
# Alternative: Non-Blocking Manager Initialization
# ============================================================================

class DeferredManagerInitializer:
    """Initialisiere Manager in Background Thread."""
    
    def __init__(self, config=None):
        self.config = config
        self.manager = None
        self._thread = None
        self._ready_event = threading.Event()
        self._error = None
    
    def start(self) -> None:
        """Starte Background Initialization."""
        if self._thread is not None:
            return
        
        self._thread = threading.Thread(target=self._init_manager, daemon=False)
        self._thread.start()
    
    def _init_manager(self) -> None:
        """Initialisiere Manager in Thread."""
        try:
            from .core import EncryptIntelligenceManager
            self.manager = EncryptIntelligenceManager(self.config)
            self._ready_event.set()
        except Exception as e:
            self._error = e
            self._ready_event.set()
    
    def wait_ready(self, timeout: float = 30.0) -> bool:
        """Warte bis Manager bereit ist."""
        return self._ready_event.wait(timeout)
    
    def get_manager(self):
        """Hole Manager (blocked bis ready)."""
        self.wait_ready()
        if self._error:
            raise RuntimeError(f"Manager initialization failed: {self._error}")
        return self.manager
    
    def is_ready(self) -> bool:
        """Check ob Manager ready ist."""
        return self._ready_event.is_set()


# ============================================================================
# Configuration mit Lazy Defaults
# ============================================================================

class LazyConfig:
    """Config mit Lazy Loading von Defaults."""
    
    def __init__(self, **kwargs):
        self._values = kwargs
        self._defaults = {
            'storage_dir': self._resolve_storage_dir,
            'index_name': lambda: 'encrypt_intelligence_index',
            'llm_model_path': lambda: 'EncryptIntelligence-v1.gguf',
            'embedding_model': lambda: 'sentence-transformers/all-MiniLM-L6-v2',
            'ocr_enabled': lambda: True,
            'offline_only': lambda: True,
            'max_chunk_size': lambda: 1200,
            'chunk_overlap': lambda: 200,
            'allowed_extensions': lambda: ('.pdf', '.docx', '.txt', '.png', '.jpg', '.jpeg'),
            'embedding_cache_size': lambda: 1000,
            'batch_size': lambda: 32,
        }
    
    @staticmethod
    def _resolve_storage_dir():
        from pathlib import Path
        import os
        return Path(os.path.expanduser('~')) / '.ancorate' / 'encrypt_intelligence'
    
    def __getattr__(self, name: str) -> Any:
        if name in self._values:
            return self._values[name]
        if name in self._defaults:
            return self._defaults[name]()
        raise AttributeError(f"Config hat kein Attribut '{name}'")
    
    def to_dict(self) -> dict:
        """Konvertiere zu Dictionary."""
        return {
            'storage_dir': self.storage_dir,
            'index_name': self.index_name,
            'llm_model_path': self.llm_model_path,
            'embedding_model': self.embedding_model,
            'ocr_enabled': self.ocr_enabled,
            'offline_only': self.offline_only,
            'max_chunk_size': self.max_chunk_size,
            'chunk_overlap': self.chunk_overlap,
            'allowed_extensions': self.allowed_extensions,
            'embedding_cache_size': self.embedding_cache_size,
            'batch_size': self.batch_size,
        }


# ============================================================================
# Usage Example
# ============================================================================

"""
# Statt:
from intelligence.core import EncryptIntelligenceManager, LocalLLMClient
manager = EncryptIntelligenceManager()  # ← Blockiert auf Import/Init

# Nutze stattdessen:
from intelligence.lazy_loading import get_lazy_llm_client, DeferredManagerInitializer

# Option 1: LLM wird lazy geladen
llm = get_lazy_llm_client()
print(llm.is_available())  # ← Erste echte Nutzung triggert Loading

# Option 2: Manager im Background starten
initializer = DeferredManagerInitializer()
initializer.start()
# UI startet sofort...
manager = initializer.get_manager()  # ← Blockiert bis ready


# In main.py:
def setup_intelligence_async():
    '''Setup Intelligence ohne UI zu blockieren.'''
    from intelligence.lazy_loading import DeferredManagerInitializer
    
    init = DeferredManagerInitializer()
    init.start()
    
    # Später, wenn User Dialog öffnet:
    if init.is_ready():
        manager = init.get_manager()
        return EncryptIntelligenceDialog(manager=manager)
    else:
        # Zeige Loading-Spinner
        return None
"""