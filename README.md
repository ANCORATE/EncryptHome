# ANCORATE EncryptHome

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/ANCORATE/EncryptHome/actions/workflows/ci.yml/badge.svg)](https://github.com/ANCORATE/EncryptHome/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PyQt6](https://img.shields.io/badge/UI-PyQt6-green.svg)](https://www.riverbankcomputing.com/software/pyqt/)

**EncryptHome 27 Beta 1 — Capsule**

A local desktop application for encrypted `.salt` vaults: file management, device binding, file preview, secure deletion, and vault integrity checks.

Copyright © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin.

---

## What EncryptHome does

EncryptHome provides a graphical vault application built with PyQt6. The current codebase supports:

- Creating and opening `.salt` containers
- Password-protected vault access
- Optional device-bound vaults
- Adding files to a vault (including drag-and-drop import)
- Selecting multiple files
- Exporting one, several, or all files
- Deleting files from a vault
- Deleting a vault/container
- Searching vault contents
- Recent-container history (up to 10 entries)
- In-memory file preview with a bounded LRU cache
- Configurable secure-deletion methods
- Optional deletion of source files after successful encryption
- Changing the password of an existing vault
- Auto-lock behavior
- Configurable keyboard shortcuts
- Four built-in themes (Standard-dark / Standard-White / High-Contrast / Midnight Blue) with central app-wide styling
- Application integrity and update checks
- Update news and changelog display
- A settings window (General, Shortcuts, Design, Updates)
- Technical details and About dialogs
- A local emergency vault-deletion scanner

The GUI also contains LAN-sharing infrastructure in the `App` class (UDP discovery and TCP transfer ports for ANCORATE LAN functionality).

## Current version

```text
EncryptHome 27 Beta 1
Edition: EncryptHome
Codename: Capsule
Container version: 0x09
```

`main.py` is the application entry point. It imports and re-exports the application modules so existing imports from `main` continue to work.

## Cryptography

EncryptHome uses the Python `cryptography` package for AES-GCM, HKDF, HMAC, and related primitives.

### File encryption

Each encrypted file uses:

- A random 16-byte file nonce
- A random 12-byte AES-GCM nonce
- A 32-byte per-file subkey derived with HKDF-SHA256
- AES-GCM encryption
- An HMAC-SHA256 value over the ciphertext

Files are processed in **128 KiB chunks**.

### Metadata encryption

Vault metadata is serialized as JSON and encrypted with AES-GCM. The encrypted metadata also receives an HMAC-SHA256 value.

### Key derivation

The per-file HKDF uses the file nonce as its salt and the UTF-8-encoded filename as its `info` value. The resulting 32-byte key is used for AES-256-GCM.

## Device binding

Device-bound vaults use a runtime-generated device key.

The current device fingerprint is built from:

- MAC address
- CPU information
- Disk information

These values are hashed with SHA-256. A deterministic device key is then derived from that fingerprint. The key is generated at runtime rather than stored as a persistent key file.

The application also keeps a local registration marker to determine whether the device has already completed the initial registration flow.

## Passwords

Password input enforces live requirements for:

- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

The same validation is used when changing an existing vault password. Changing a vault password re-encrypts the vault's file data with newly derived key material and is designed to leave the existing container unchanged if the re-key operation fails before the new container can be written.

## `.salt` container

The current container header is:

```text
Magic       4 bytes   ANC0
Version     1 byte    0x09
Flags       1 byte
Salt        16 bytes
Reserved    6 bytes
```

Header size: **28 bytes**. Defined flags:

```text
0x01  Device-bound vault
0x02  Keyfile flag
0x04  EncryptPro vault flag
```

A file blob contains:

```text
16-byte file nonce
12-byte GCM nonce
ciphertext
16-byte GCM tag
32-byte HMAC-SHA256
```

The vault stores encrypted metadata together with its length at the end of the container.

## Integrity checks

Encrypted data is verified with multiple mechanisms:

- AES-GCM authentication
- HMAC-SHA256 verification for file ciphertext
- HMAC-SHA256 verification for metadata
- Container and header validation during vault access
- Application checksum and update infrastructure

When file HMAC or AES-GCM verification fails during export or decryption, the application reports an invalid password or damaged data instead of accepting unauthenticated plaintext.

## File preview

EncryptHome supports file preview through a dedicated preview worker and an in-memory cache in the main application.

The `App` implementation keeps preview data in an LRU cache with a total cache limit of **200 MiB** and applies a maximum preview-file size from `decrypt_preview.py`.

## Secure deletion

The Settings dialog exposes these deletion choices:

- Standard (Schnell)
- DoD 5220.22-M (3x)
- Gutmann (35x)
- ANCORATE Vaporizer 1 (100x)
- ANCORATE Furnace Max (200x, large files)
- ANCORATE Shatterer Ultra (300x; marked in the UI as not for HDD use)

Settings also include an option to delete the original source file after successful encryption. EncryptHome also provides an emergency function for scanning and deleting vaults through `SaltScannerUI`.

## Vault and file operations

Menu actions:

### File

- New vault
- Open vault
- Recent containers
- Change vault password
- Close vault
- Delete vault
- Settings

### Edit

- Add files
- New folder
- Move to folder
- Start file preview
- Edit file in vault
- Delete selected files
- Export selected files
- Export all files

### Help

- First steps (onboarding)
- About EncryptHome

The file list supports extended selection and accepts dropped local files. Files can be dragged between folders inside the vault (dropping on empty space moves them back to the root). Double-clicking a file entry starts an in-vault edit session; double-clicking a folder toggles it (tree) or opens it (grid).

### Display layouts

The layout can be switched instantly with toolbar buttons or **Ansicht → Layout**:

- **Liste** – folder tree with columns (Name, Größe, Geändert, Typ)
- **Kompakt** – tree with name and size only
- **Raster** – icon grid of the current folder (with a "Zurück" tile)

The selection is stored in `settings.json` under `list_view_mode`. File types in the **Typ** column and in the preview are detected from the content's magic bytes first (via `utilities/file_types.py`) and only fall back to the file name/extension.

## Export and encryption workers

Long-running operations use Qt workers and signals:

- `AddWorker` for encrypting files into an existing vault
- `ExportWorker` for exporting one file
- `ExportBatchWorker` for exporting multiple files
- `RewriteEntryWorker` for writing an edited file back into a vault
- `StartupUpdateWorker` for background update checks

The add worker supports progress reporting, cancellation through a `threading.Event`, and removal of source files after successful encryption when that setting is enabled.

## Recent containers

EncryptHome stores recent-container information locally and keeps the most recent **10** entries. Each entry contains the container path, container name, and last-accessed timestamp. The UI allows opening a recent container or clearing the recent-container list.

## Auto-lock and runtime cleanup

The main window initializes a **5-minute auto-lock timeout** and runs a periodic cleanup timer every **10 seconds**. The cleanup invokes Python garbage collection.

## Keyboard shortcuts

Default shortcuts:

| Action | Default |
|---|---|
| Create vault | `Ctrl+N` |
| Open vault | `Ctrl+O` |
| Add files | `Ctrl++` |
| Export selected | `Ctrl+E` |
| Export all | `Alt+E` |
| Delete selected | `Del` |
| Delete vault/container | `Alt+Del` |
| Search | `Return` |
| Recent containers | `Ctrl+R` |

The Settings dialog allows these shortcuts to be edited with Qt's `QKeySequenceEdit`.

## Settings

The Settings dialog has four categories:

1. **General**
2. **Shortcuts**
3. **Design**
4. **Updates**

General settings include:

- Confirm before exiting
- Delete the original source after successful encryption
- Secure-deletion method
- Temporary-cache cleanup
- Immediate application exit
- Emergency vault-deletion scanner

The update system uses the configured update URL and can display release notes and changelog data.

### Design & themes

EncryptHome ships four application themes:

- **Standard-dark** (`utilities/themes/standard-dark.css`)
- **Standard-White** (`utilities/themes/standard-white.css`)
- **High-Contrast** (`utilities/themes/high-contrast.css`)
- **Midnight Blue** (`utilities/themes/midnight-blue.css`)

All theme files share the same selectors, properties, and widget object names and differ only in their color palettes. All application styling is centralized in these Qt stylesheet files. The active theme is stored in `settings.json` under the `theme` key (default `Standard-dark`) and is applied on startup and when changed in the **Design** tab. Unknown or legacy theme values from older versions are automatically normalized to `Standard-dark`.

## Application startup

On startup, EncryptHome:

1. Generates the runtime device key.
2. Checks whether the device has already been registered.
3. For a new device, shows the welcome flow, Terms of Service, and login/setup flow.
4. For an already registered device, opens the main window directly.
5. Starts the background update check.

The startup flow is implemented in `main.py`.

## Project structure

```text
EncryptHome/
├── main.py
├── base.py
├── encrypt.py
├── decrypt.py
├── decrypt_preview.py
├── app/
│   ├── core.py
│   ├── passwords.py
│   ├── workers.py
│   ├── dialogs.py
│   ├── main_window.py
│   └── power_lock.py
├── utilities/
│   ├── settings.py
│   ├── theme_engine.py
│   ├── container_ops.py
│   ├── file_types.py
│   ├── header_utils.py
│   ├── checksum_check.py
│   ├── updater.py
│   ├── screenshot_protection.py
│   ├── sos_delete.py
│   └── themes/
├── docs/
└── README.md
```

`main.py` remains the entry point even though most application code now lives in `app/`.

## Dependencies

The application imports and uses:

- Python 3.10+
- PyQt6
- `cryptography`
- `argon2-cffi`
- `requests`

Install them with:

```bash
pip install PyQt6 cryptography argon2-cffi requests
```

The source does not pin specific versions.

## Development

Run the application through its Python entry point:

```bash
python main.py
```

For setup, build, and development workflow details, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Testing

Run the test suite with:

```bash
pytest
```

The repository currently includes tests for atomic container updates and file-type icons.

## Documentation

The in-repository documentation is also mirrored in the project's GitHub Wiki.

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — module structure and runtime flows
- [docs/SECURITY.md](docs/SECURITY.md) — cryptographic and security model
- [docs/API_REFERENCE.md](docs/API_REFERENCE.md) — public code interfaces
- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — setup, build, and development workflow
- [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) — contribution rules

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) before submitting changes. Security-sensitive changes require careful review.

## Security

EncryptHome is a local desktop application. It provides authenticated encryption, password-derived keys, optional device binding, encrypted metadata, integrity checks, secure-deletion options, and local runtime controls.

For the security model and vulnerability reporting, see [SECURITY.md](SECURITY.md) and [docs/SECURITY.md](docs/SECURITY.md). Please report security vulnerabilities privately rather than via public issues.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

Copyright © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin.