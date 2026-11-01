# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import json
import os
import tempfile
import threading

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from base import CHUNK, derive_subkey


def decrypt_key(path: str) -> bytes:
    """
    Reads a legacy keyfile and returns the real 32-byte AES key.
    Deprecated and unused. The previous single-byte device-key "adder"
    obfuscation was cryptographically unsound and has been removed;
    legacy keyfiles are read verbatim.

    !UNUSED!
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Keyfile not found: {path}")

    with open(path, "rb") as f:
        data = f.read()

    if len(data) != 32:
        raise ValueError(
            f"Keyfile has invalid length ({len(data)} bytes). Expected 32 bytes for AES-256."
        )

    return data


def decrypt_blob_range(
    fh,
    out_path: str,
    blob_len: int,
    master_key: bytes,
    filename: str,
    progress_cb=None,
    stop_event: threading.Event | None = None,
):
    if blob_len < (16 + 12 + 16 + 32 + 1):
        raise ValueError("Blob too small")

    file_nonce = fh.read(16)
    nonce = fh.read(12)
    rest = blob_len - (16 + 12)
    if rest < (16 + 32):
        raise ValueError("Invalid blob length")

    ciphertext_len = rest - (16 + 32)
    tmpname = None
    tmp_out_path = None
    out_dir = os.path.dirname(out_path) or os.curdir

    try:
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
            for chunk in iter(lambda: tmp.read(CHUNK), b""):
                hm.update(chunk)
        try:
            hm.verify(hval)
        except InvalidSignature as e:
            raise ValueError(
                "Invalid password or damaged vault. Please verify the password."
            ) from e

        subkey = derive_subkey(master_key, file_nonce, filename)
        decryptor = Cipher(
            algorithms.AES(subkey), modes.GCM(nonce, tag), backend=default_backend()
        ).decryptor()

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
                        "Invalid password or damaged vault. Please verify the password."
                    ) from e
                if last:
                    out_tmp.write(last)
        os.replace(tmp_out_path, out_path)
        tmp_out_path = None
    finally:
        if tmpname:
            try:
                os.remove(tmpname)
            except Exception:
                pass
        if tmp_out_path:
            try:
                os.remove(tmp_out_path)
            except Exception:
                pass

    if progress_cb:
        progress_cb(100)


def decrypt_meta(blob: bytes, master_key: bytes) -> dict:
    if len(master_key) not in (16, 24, 32):
        raise ValueError(f"master_key length invalid: {len(master_key)} bytes (only 16/24/32 allowed)")
    if len(blob) < 12 + 16 + 32 + 1:
        raise ValueError("Meta blob invalid or too short")

    nonce = blob[:12]
    hval = blob[-32:]
    ct_tag = blob[12:-32]

    hm = hmac.HMAC(master_key, hashes.SHA256())
    hm.update(ct_tag)
    try:
        hm.verify(hval)
    except InvalidSignature as e:
        raise ValueError(
            "Invalid password or damaged vault. Please verify the password."
        ) from e

    aesg = AESGCM(master_key)
    try:
        pt = aesg.decrypt(nonce, ct_tag, None)
    except InvalidTag as e:
        raise ValueError(
            "Invalid password or damaged vault. Please verify the password."
        ) from e

    return json.loads(pt.decode("utf-8"))