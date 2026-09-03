# EncryptHome Developer Documentation

Developer documentation for the ANCORATE EncryptHome desktop application.

## Current codebase

- **Entry point:** `main.py`
- **Application UI:** PyQt6
- **Language:** Python 3
- **Edition:** EncryptHome Capsule
- **Container:** `.salt`
- **License:** Proprietary — © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin

`main.py` remains the public entry point. It re-exports symbols from the `app` package so existing imports such as `from main import ...` remain valid.

## Documentation

- [Architecture](ARCHITECTURE.md) — current module structure and runtime flows
- [Security](SECURITY.md) — cryptographic and security model
- [API Reference](API_REFERENCE.md) — public code interfaces documented here
- [Development Guide](DEVELOPMENT.md) — setup, build and development workflow
- [Contributing](CONTRIBUTING.md) — project contribution rules

## Current feature set

The current code implements:

- `.salt` vault creation, opening and updating
- password-based key derivation with optional device binding
- AES-256-GCM file encryption
- encrypted vault metadata
- per-file subkey derivation with HKDF-SHA256
- HMAC-SHA256 integrity checks for encrypted file blobs and metadata
- file add, export and batch export
- drag-and-drop file input
- in-memory file preview with an LRU cache
- configurable application settings and themes (Standard-dark / Standard-White, central app-wide styling)
- header validation and repair helpers
- startup integrity/checksum verification
- background update checking
- emergency `.salt` vault scanning/deletion
- LAN discovery/sharing functionality in the main application
- device registration and device-based login
- password change with container re-encryption
- secure deletion methods
- in-vault file editing (double-click opens the decrypted file in the system's default application; saves are re-encrypted back into the vault)
- extended container/file metadata (modified/opened timestamps, app version, per-file SHA-256 and created/added/edited timestamps)

### Windows screenshot protection

The current EncryptHome 27 development work also includes an optional Windows-only screenshot/capture protection layer. It uses the Windows `SetWindowDisplayAffinity` API with `WDA_EXCLUDEFROMCAPTURE` for EncryptHome-owned Qt windows.

On Linux and macOS the protection layer is a no-op. It does not alter the vault format or cryptographic operations.

This protection does **not** claim to block every possible capture method and does not automatically protect windows owned by external applications such as Microsoft Word.

## Architecture at a glance

```text
main.py
  │
  ├── app.core
  ├── app.passwords
  ├── app.workers
  ├── app.dialogs
  └── app.main_window
        │
        ├── encryption/decryption modules
        ├── preview subsystem
        └── utility modules
```

### Core modules

- `base.py` — cryptographic primitives and key derivation
- `encrypt.py` — file and metadata encryption
- `decrypt.py` — file/blob decryption
- `decrypt_preview.py` — in-memory preview
- `app/core.py` — shared application helpers and constants
- `app/passwords.py` — password and password-change dialogs/helpers
- `app/workers.py` — background encryption/export/update workers
- `app/dialogs.py` — application dialogs and widgets
- `app/main_window.py` — `App` main window and application behavior

### Utilities

- `utilities/settings.py` — settings and settings UI
- `utilities/header_utils.py` — container header validation/repair
- `utilities/checksum_check.py` — application integrity/checksum handling
- `utilities/sos_delete.py` — emergency `.salt` vault scanner/wiper
- `utilities/updater.py` — update-related functionality
- `utilities/screenshot_protection.py` — optional Windows capture protection

## Cryptographic data flow

```text
Password
   │
   ├── project pepper
   ↓
Argon2id
   ↓
Password-derived key
   │
   ├── optional device key binding
   ↓
HKDF-SHA256
   ↓
Master key
   ↓
Per-file HKDF-SHA256 subkey
   ↓
AES-256-GCM
   ↓
Encrypted file blob
```

The exact implementation and current constants are documented in [SECURITY.md](SECURITY.md) and should be treated as authoritative over this overview.

## Development principle

Documentation should describe the code that exists, not planned features. If implementation and documentation differ, update the documentation or the implementation before release.

## License

This is proprietary software. Unauthorized reproduction, reuse, modification, or distribution is prohibited.

© 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
