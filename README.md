# EncryptHome

<div align="center">

**Secure Device-Bound Encryption Software**

Version 26.2 | EncryptHome Citadel

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin

</div>

---

## Overview

EncryptHome is a security-focused desktop application for securely storing, managing, and protecting user data with strong encryption, optional device binding, and integrity verification.

### Current Features

- **AES-256-GCM encryption** with authenticated encryption
- **Argon2id key derivation** with a 128 MB memory cost
- **HKDF-SHA256 per-file subkeys**
- **Optional device-bound vaults** using a hardware fingerprint
- **Custom `.salt` vault containers** with versioned headers
- **Encrypted metadata** for the vault file list
- **HMAC-SHA256 integrity verification** for encrypted blobs and metadata
- **Application checksum verification**
- **In-memory file preview** without writing preview plaintext to disk
- **Secure deletion** with configurable overwrite methods
- **Drag-and-drop file import**
- **File search** inside the vault
- **Recent containers**
- **Configurable keyboard shortcuts**
- **Light and dark themes**
- **Auto-lock support**
- **Cross-platform design** for Windows, Linux, and macOS

## Quick Start

### Prerequisites

- Python 3.10 or higher
- PyQt6
- argon2-cffi
- cryptography
- requests

### Installation

```bash
pip install PyQt6 argon2-cffi cryptography requests
```

### Run

```bash
python main.py
```

### Basic Usage

1. **Create a Vault** with `Ctrl+N`.
2. **Open a Vault** with `Ctrl+O`.
3. **Add Files** with drag and drop or `Ctrl++`.
4. **Preview Files** by double-clicking a file.
5. **Export Files** with `Ctrl+E`.
6. **Search** for files with the search bar.
7. **Delete Files** with `Del`.
8. **Lock/close the vault** when finished.

## Security Architecture

EncryptHome uses a layered cryptographic design:

```text
Password
   ↓
Project Pepper
   ↓
Argon2id
   ↓
Password-derived Key
   ↓
Device Key (when device binding is enabled)
   ↓
HKDF-SHA256
   ↓
Master Key
   ↓
Per-file HKDF-SHA256 Subkey
   ↓
AES-256-GCM
```

### Cryptographic Parameters

- **Argon2id:** time cost 3, memory cost 131072 KiB (128 MB), parallelism 4, output 32 bytes
- **AES-256-GCM:** 256-bit key, 12-byte nonce, 16-byte authentication tag
- **HKDF-SHA256:** 32-byte derived keys
- **HMAC-SHA256:** additional integrity verification
- **Container salt:** 16 bytes
- **Encryption chunk size:** 128 KiB

### Device Binding

Device-bound vaults derive a device fingerprint from hardware identifiers. The current implementation uses MAC address, CPU information, and disk information. The resulting fingerprint is hashed and used to derive a device key at runtime.

A vault can therefore require both the user's password and the expected device identity.

## Container Format

EncryptHome uses a custom `.salt` container format.

```text
[Header 28B][File Blob 1][File Blob 2]...[Meta Length 8B][Encrypted Meta]
```

### Header

```text
Magic      4 bytes   ANC0
Version    1 byte    0x09
Flags      1 byte    Device / Keyfile / Pro flags
Salt       16 bytes  Random container salt
Reserved   6 bytes   Reserved for future use
```

### File Blob

```text
[File Nonce 16B]
[GCM Nonce 12B]
[Ciphertext]
[GCM Tag 16B]
[HMAC-SHA256 32B]
```

### Metadata

Vault metadata is serialized as JSON and encrypted with AES-256-GCM. An HMAC-SHA256 value provides an additional integrity check.

## Integrity Protection

EncryptHome performs several integrity checks:

1. **AES-GCM authentication** during decryption
2. **HMAC-SHA256 verification** for encrypted file data
3. **HMAC-SHA256 verification** for encrypted metadata
4. **Header validation** for vault structure
5. **SHA-256 application checksums** for detecting modified application files

Integrity failures are reported instead of silently accepting corrupted or modified data.

## Secure Deletion

EncryptHome can securely overwrite files before deletion. Available deletion methods include standard deletion and multiple multi-pass overwrite modes, including ANCORATE-specific methods.

The application also provides an emergency vault-wiping function for deleting vault files.

> Secure overwrite effectiveness depends on the storage medium. On SSDs and modern copy-on-write filesystems, software overwriting cannot guarantee physical erasure of previous data.

## File Preview

Files can be previewed in memory without first exporting the decrypted content to a normal file on disk. Preview caching is limited and automatically managed.

## Configuration

Settings are stored in platform-specific locations:

- **Linux:** `~/.config/ANCORATE/settings.json`
- **Windows:** `%APPDATA%\\ANCORATE\\settings.json`
- **macOS:** `~/Library/Application Support/ANCORATE/settings.json`

Current settings include:

- Theme selection
- Keyboard shortcuts
- Auto-lock configuration
- Secure deletion method
- Source-file deletion after encryption
- Other application preferences

## Keyboard Shortcuts

| Action | Shortcut |
|---|---|
| Create New Vault | `Ctrl+N` |
| Open Existing Vault | `Ctrl+O` |
| Add Files | `Ctrl++` |
| Export Selected | `Ctrl+E` |
| Export All | `Alt+E` |
| Delete Selected | `Del` |
| Delete Container | `Alt+Del` |
| Search Files | `Return` |
| Recent Containers | `Ctrl+R` |

## Project Structure

```text
EncryptHome/
├── main.py                 # Main application and GUI
├── base.py                 # Cryptographic primitives and key derivation
├── encrypt.py              # Encryption operations
├── decrypt.py              # Decryption operations
├── decrypt_preview.py      # In-memory preview system
├── utilities/
│   ├── settings.py         # Settings management
│   ├── header_utils.py     # Container header utilities
│   ├── checksum_check.py   # Application integrity verification
│   ├── sos_delete.py       # Emergency vault deletion
│   ├── updater.py          # Update mechanism
│   └── themes/             # Qt themes
├── docs/                   # Technical documentation
├── AGENTS.md               # Development guidelines
└── README.md               # Project documentation
```

## Development

### Development Environment

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\\Scripts\\activate
pip install PyQt6 argon2-cffi cryptography requests
```

Optional development tools:

```bash
pip install black pylint mypy pytest pytest-cov PyInstaller
```

### Build

The repository contains the current PyInstaller build specification. For the current 26.2 build:

```bash
pyinstaller ANCORATE_EncryptHome_26.2_Build_0009.spec
```

## Requirements

### Minimum

- Python 3.10+
- 1 GB RAM
- 100 MB free disk space
- Windows 10+, Ubuntu 18.04+, or macOS 10.15+

### Recommended

- Python 3.10+
- 8 GB RAM
- 500 MB free disk space

## Security Notes

EncryptHome is designed around defense in depth. Passwords and cryptographic keys are not intentionally stored in plaintext on disk. The master key is kept in memory for the active session, while device keys are derived at runtime.

Users should still use strong, unique passwords, enable device binding for sensitive vaults, keep secure backups, use full-disk encryption, and keep EncryptHome and its dependencies up to date.

## Documentation

Technical documentation is available in `docs/`:

- `docs/README.md` — developer documentation
- `docs/ARCHITECTURE.md` — architecture and data flow
- `docs/SECURITY.md` — security model and threat analysis
- `docs/API_REFERENCE.md` — API reference
- `docs/DEVELOPMENT.md` — development guide
- `docs/CONTRIBUTING.md` — contribution guidelines

## License

This is proprietary software. All rights reserved.

**Copyright © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin.**

Unauthorized reproduction, reuse, modification, or distribution is strictly prohibited.

## Acknowledgments

EncryptHome uses:

- **PyQt6** — GUI framework
- **argon2-cffi** — Argon2 password hashing and key derivation
- **cryptography** — cryptographic primitives
- **requests** — HTTP library

---

<div align="center">

**EncryptHome — Security Through Strong Encryption**

</div>
