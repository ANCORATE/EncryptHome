from base import *
import os
import json
import tempfile
import threading
from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK = 128 * 1024

from main import load_device_key
from base import derive_subkey

def decrypt_key(path: str) -> bytes:
    """
    Liest ein Keyfile ein und invertiert die optionale 'Device-Adder'-Obfuskation,
    wie sie in generate_keyfile verwendet wird.
    Gibt den echten 32-Byte AES-Key zurück.
    !UNUSED!
    """
    import os

    # --- Keyfile einlesen ---
    if not os.path.exists(path):
        raise FileNotFoundError(f"Keyfile nicht gefunden: {path}")

    with open(path, "rb") as f:
        data = f.read()

    # --- Validierung ---
    if len(data) != 32:
        raise ValueError(
            f"Keyfile hat falsche Länge ({len(data)} Bytes). Erwartet 32 Bytes für AES-256."
        )

    # --- Optional: Device-Key (z. B. aus Hardware-ID) ---
    try:
        device_key = load_device_key()
    except (ImportError, NameError):
        device_key = None

    adder = device_key[-1] if device_key else 0

    # --- Obfuskation rückgängig machen ---
    real_key = bytes(((b - adder) & 0xFF) for b in data)

    return real_key


def decrypt_blob_range(fh, out_path: str, blob_len: int, master_key: bytes, filename: str, progress_cb=None, stop_event: threading.Event | None=None):
    if blob_len < (16 + 12 + 16 + 32):
        raise ValueError("Blob too small")
    file_nonce = fh.read(16)
    nonce = fh.read(12)
    rest = blob_len - (16 + 12)
    if rest < (16 + 32):
        raise ValueError("Invalid blob length")
    ciphertext_len = rest - (16 + 32)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmpname = tmp.name
        read = 0
        while read < ciphertext_len:
            if stop_event and stop_event.is_set():
                raise RuntimeError("Cancelled")
            chunk = fh.read(min(CHUNK, ciphertext_len - read))
            if not chunk:
                raise IOError("Unexpected EOF in ciphertext")
            tmp.write(chunk)
            read += len(chunk)
            if progress_cb and ciphertext_len:
                progress_cb(min(60, 10 + int(read / ciphertext_len * 50)))
        tag = fh.read(16)
        hval = fh.read(32)
    hm = hmac.HMAC(master_key, hashes.SHA256())
    with open(tmpname, "rb") as tmp:
        while True:
            c = tmp.read(CHUNK)
            if not c:
                break
            hm.update(c)
    try:
        hm.verify(hval)
    except InvalidSignature as e:
        raise ValueError(
            "Ungültiges Passwort oder beschädigter Tresor. Bitte Passwort prüfen."
        ) from e
    subkey = derive_subkey(master_key, file_nonce, filename)
    decryptor = Cipher(algorithms.AES(subkey), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    out_dir = os.path.dirname(out_path) or os.curdir
    tmp_out_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, dir=out_dir) as out_tmp:
            tmp_out_path = out_tmp.name
            with open(tmpname, "rb") as tmpf:
                done = 0
                while True:
                    if stop_event and stop_event.is_set():
                        raise RuntimeError("Cancelled")
                    c = tmpf.read(CHUNK)
                    if not c:
                        break
                    pt = decryptor.update(c)
                    if pt:
                        out_tmp.write(pt)
                    done += len(c)
                    if progress_cb and ciphertext_len:
                        progress_cb(60 + int(done / ciphertext_len * 39))
                try:
                    last = decryptor.finalize()
                except InvalidTag as e:
                    raise ValueError(
                        "Ungültiges Passwort oder beschädigter Tresor. Bitte Passwort prüfen."
                    ) from e
                if last:
                    out_tmp.write(last)
        os.replace(tmp_out_path, out_path)
        tmp_out_path = None
    finally:
        if tmp_out_path:
            try:
                os.remove(tmp_out_path)
            except:
                pass
    try:
        os.remove(tmpname)
    except:
        pass
    if progress_cb:
        progress_cb(100)


def decrypt_meta(blob: bytes, master_key: bytes) -> dict:
    if len(master_key) not in (16, 24, 32):
        raise ValueError(f"master_key Länge ungültig: {len(master_key)} Bytes (nur 16/24/32 erlaubt)")
    if len(blob) < 12 + 32 + 1:
        raise ValueError("Meta blob ungültig oder zu kurz")

    # wichtigste Einträge erhalten
    nonce = blob[:12]
    hval = blob[-32:]
    ct_tag = blob[12:-32]

    hm = hmac.HMAC(master_key, hashes.SHA256())
    hm.update(ct_tag)
    try:
        hm.verify(hval)
    except InvalidSignature as e:
        raise ValueError(
            "Ungültiges Passwort oder beschädigter Tresor. Bitte Passwort prüfen."
        ) from e

    aesg = AESGCM(master_key)
    try:
        pt = aesg.decrypt(nonce, ct_tag, None)
    except InvalidTag as e:
        raise ValueError(
            "Ungültiges Passwort oder beschädigter Tresor. Bitte Passwort prüfen."
        ) from e

    return json.loads(pt.decode("utf-8"))

# THIS CODE IS PROPERTY OF SAMUEL J. TIRWA & GABRIEL LEIRIA-ROUSSIN. NO PART OF THIS CODE MAY BE REPRODUCED, REUSED, MODIFIED, OR DISTRIBUTED WITHOUT THE EXPRESS PERMISSION OF THE AUTHORS. VIOLATORS WILL BE PROSECUTED TO THE FULLEST EXTENT OF THE LAW. COPYRIGHT 2025. ALL RIGHTS RESERVED.
