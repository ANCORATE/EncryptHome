# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CHUNK = 128 * 1024


def derive_subkey(master_key: bytes, file_nonce: bytes, filename: str) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=file_nonce,
        info=filename.encode('utf-8'),
    )
    return hkdf.derive(master_key)

