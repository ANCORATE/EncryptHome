"""EncryptIntelligence package for ANCORATE EncryptHome.

Dieses Paket bietet die grundlegenden Komponenten für EncryptIntelligence.
Alle Funktionen werden lokal ausgeführt und arbeiten ausschließlich mit verschlüsselten Dokumenten im Tresor.
"""

from .core import EncryptIntelligenceConfig, EncryptIntelligenceManager
from .ui import EncryptIntelligenceDialog

__all__ = [
    "EncryptIntelligenceConfig",
    "EncryptIntelligenceManager",
    "EncryptIntelligenceDialog",
]
