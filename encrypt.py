# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

import json
import os
import secrets
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from base import CHUNK, derive_subkey

# AES-GCM encryption
def encrypt_meta(meta: dict, master_key: bytes) -> bytes:
    plaintext = json.dumps(meta, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    aesg = AESGCM(master_key)
    nonce = secrets.token_bytes(12)
    ct_tag = aesg.encrypt(nonce, plaintext, None)
    hm = hmac.HMAC(master_key, hashes.SHA256())
    hm.update(ct_tag)
    hval = hm.finalize()
    return nonce + ct_tag + hval


# AES-GCM file encryption to blob
def encrypt_file_to_blob(src_path: str, out_fh, master_key: bytes, filename: str | None = None, progress_cb=None, stop_event: threading.Event | None=None):
    total = os.path.getsize(src_path)
    read_bytes = 0
    file_nonce = secrets.token_bytes(16)
    out_fh.write(file_nonce)
    file_name = filename if filename is not None else os.path.basename(src_path)
    subkey = derive_subkey(master_key, file_nonce, file_name)
    nonce = secrets.token_bytes(12)
    out_fh.write(nonce)
    encryptor = Cipher(algorithms.AES(subkey), modes.GCM(nonce), backend=default_backend()).encryptor()
    hm = hmac.HMAC(master_key, hashes.SHA256())
    with open(src_path, "rb") as inf:
        while True:
            if stop_event and stop_event.is_set():
                raise RuntimeError("Cancelled")
            chunk = inf.read(CHUNK)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                out_fh.write(ct)
                hm.update(ct)
            read_bytes += len(chunk)
            if progress_cb and total:
                progress_cb(min(90, int(read_bytes / total * 90)))
        final_ct = encryptor.finalize()
        if final_ct:
            out_fh.write(final_ct)
            hm.update(final_ct)
    tag = encryptor.tag
    out_fh.write(tag)
    hmac_val = hm.finalize()
    out_fh.write(hmac_val)
    if progress_cb:
        progress_cb(100)

