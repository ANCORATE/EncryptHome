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

# THIS CODE IS PROPERTY OF SAMUEL J. TIRWA & GABRIEL LEIRIA-ROUSSIN. NO PART OF THIS CODE MAY BE REPRODUCED, REUSED, MODIFIED, OR DISTRIBUTED WITHOUT THE EXPRESS PERMISSION OF THE AUTHORS. VIOLATORS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW. COPYRIGHT 2025. ALL RIGHTS RESERVED.
