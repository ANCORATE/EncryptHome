# ANCORATE EncryptHome

**EncryptHome 27 Beta 1 — Capsule**

A local desktop application for encrypted `.salt` vaults, file management, device binding, file preview, secure deletion, and vault integrity checks.

Copyright © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.

---

## What EncryptHome currently does

EncryptHome provides a graphical vault application built with PyQt6. The current codebase supports:

- Creating and opening `.salt` containers
- Password-protected vault access
- Optional device-bound vaults
- Adding files to a vault
- Drag-and-drop file import
- Selecting multiple files
- Exporting one or multiple selected files
- Exporting all files
- Deleting files from a vault
- Deleting a vault/container
- Searching vault contents
- Recent-container history with up to 10 entries
- In-memory file preview with a bounded LRU cache
- Configurable secure-deletion methods
- Optional deletion of source files after successful encryption
- Changing the password of an existing vault
- Auto-lock behavior
- Configurable keyboard shortcuts
- Four built-in themes (Standard-dark / Standard-White / High-Contrast / Midnight Blue) with central app-wide styling
- Application integrity and update checks
- Update news and changelog display
- A settings window with General, Shortcuts, Design, and Updates sections
- Technical details and About dialogs
- A local emergency vault-deletion scanner

The current GUI also contains LAN-sharing infrastructure in the `App` class. It defines UDP discovery and TCP transfer ports for ANCORATE LAN functionality.

## Current version

The code identifies itself as:

```text
EncryptHome 27 Beta 1
Edition: EncryptHome
Codename: Capsule
Container version: 0x09
```

`main.py` is the application entry point. It imports and re-exports the application modules so existing imports from `main` continue to work.

---

## Cryptography

The current implementation uses the Python `cryptography` package for AES-GCM, HKDF, HMAC, and related primitives.

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

### Key derivation detail

The per-file HKDF uses the file nonce as its salt and the UTF-8-encoded filename as its `info` value. The resulting 32-byte key is used for AES-256-GCM.

---

## Device binding

Device-bound vaults use a runtime-generated device key.

The current device fingerprint is built from:

- MAC address
- CPU information
- Disk information

These values are hashed with SHA-256. A deterministic device key is then derived from that fingerprint. The key is generated at runtime rather than stored as a persistent key file.

The application also keeps a local registration marker to determine whether the device has already completed the initial registration flow.

---

## Passwords

Password input has live requirements for:

- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

The same validation is used when changing an existing vault password.

Changing a vault password re-encrypts the vault's file data with newly derived key material. The implementation is designed to leave the existing container unchanged if the re-key operation fails before the new container can be written.

---

## `.salt` container

The current container header is defined as:

```text
Magic       4 bytes   ANC0
Version     1 byte    0x09
Flags       1 byte
Salt        16 bytes
Reserved    6 bytes
```

The resulting header size is **28 bytes**. The defined flags are:

```text
0x01  Device-bound vault
0x02  Keyfile flag
0x04  EncryptPro vault flag
```

The current implementation reserves these flags, although the legacy keyfile decryption helper is marked as unused in `decrypt.py`.

A file blob contains:

```text
16-byte file nonce
12-byte GCM nonce
ciphertext
16-byte GCM tag
32-byte HMAC-SHA256
```

The vault stores encrypted metadata together with its length at the end of the container.

---

## Integrity checks

The code verifies encrypted data with multiple mechanisms:

- AES-GCM authentication
- HMAC-SHA256 verification for file ciphertext
- HMAC-SHA256 verification for metadata
- Container and header validation during vault access
- Application checksum and update infrastructure

When file HMAC or AES-GCM verification fails during export or decryption, the application reports an invalid password or damaged data instead of accepting unauthenticated plaintext.

---

## File preview

EncryptHome supports file preview through a dedicated preview worker and an in-memory cache in the main application.

The current `App` implementation keeps preview data in an LRU cache with a total cache limit of **200 MiB** and applies a maximum preview-file size from `decrypt_preview.py`.

---

## Secure deletion

The Settings dialog currently exposes these deletion choices:

- Standard (Schnell)
- DoD 5220.22-M (3x)
- Gutmann (35x)
- ANCORATE Vaporizer 1 (100x)
- ANCORATE Furnace Max (200x, large files)
- ANCORATE Shatterer Ultra (300x; marked in the UI as not for HDD use)

The settings also include an option to delete the original source file after successful encryption.

EncryptHome also provides an emergency function for scanning and deleting vaults through `SaltScannerUI`.

---

## Vault and file operations

The main window currently provides menu actions for:

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

The file list supports extended selection and accepts dropped local files. Files can be dragged between folders inside the vault (and dropped on empty space to move them back to the root). Double-clicking a file entry starts an in-vault edit session (see below); double-clicking a folder toggles it (tree) or opens it (grid).

### Display layouts

The layout can be switched instantly with the layout buttons in the toolbar (or via **Ansicht → Layout**):

- **Liste** – folder tree with columns (Name, Größe, Geändert, Typ)
- **Kompakt** – tree with name and size only
- **Raster** – icon grid of the current folder (with a "Zurück" tile)

The selection is stored in `settings.json` under `list_view_mode`. File types in the **Typ** column and in the preview are detected from the content's magic bytes first (via `utilities/file_types.py`) and only fall back to the file name/extension, so misleading extensions are not trusted.

---

## Export and encryption workers

Long-running operations use Qt workers and signals.

The current code contains:

- `AddWorker` for encrypting files into an existing vault
- `ExportWorker` for exporting one file
- `ExportBatchWorker` for exporting multiple files
- `RewriteEntryWorker` for writing an edited file back into a vault
- `StartupUpdateWorker` for background update checks

The add worker supports progress reporting, cancellation through a `threading.Event`, and removal of source files after successful encryption when that setting is enabled.

---

## Recent containers

EncryptHome stores recent-container information locally and keeps the most recent **10** entries.

Each entry contains the container path, container name, and last-accessed timestamp. The UI allows opening a recent container or clearing the recent-container list.

---

## Auto-lock and runtime cleanup

The main window initializes a **5-minute auto-lock timeout** and runs a periodic cleanup timer every **10 seconds**. The cleanup invokes Python garbage collection.

---

## Keyboard shortcuts

The default shortcuts currently defined by the application are:

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

---

## Settings

The current Settings dialog has four categories:

1. **General**
2. **Shortcuts**
3. **Design**
4. **Updates**

General settings currently include:

- Confirm before exiting
- Delete the original source after successful encryption
- Secure-deletion method
- Temporary-cache cleanup
- Immediate application exit
- Emergency vault-deletion scanner

The update system uses the configured update URL and can display release notes and changelog data.

### Design & Themes

EncryptHome ships four application themes:

- **Standard-dark** (`utilities/themes/standard-dark.css`)
- **Standard-White** (`utilities/themes/standard-white.css`)
- **High-Contrast** (`utilities/themes/high-contrast.css`)
- **Midnight Blue** (`utilities/themes/midnight-blue.css`)

All theme files share the same selectors, properties and widget object names and differ only in their color palettes, so every theme renders every part of the application consistently. All application styling is centralized in these Qt stylesheet files — dialogs, the settings window, password dialogs, About/Details/News dialogs and the welcome overlay use object names that these themes style, instead of per-widget hardcoded colors.

The active theme is stored in `settings.json` under the `theme` key (default `Standard-dark`) and is applied on startup and when changed in the **Design** tab. Unknown or legacy theme values from older versions are automatically normalized to `Standard-dark`.

---

## Application startup

On startup, EncryptHome:

1. Generates the runtime device key.
2. Checks whether the device has already been registered.
3. For a new device, shows the welcome flow, Terms of Service, and login/setup flow.
4. For an already registered device, opens the main window directly.
5. Starts the background update check.

The startup flow is implemented in `main.py`.

---

## Project structure

The current codebase is split into application modules while retaining `main.py` as the public entry point:

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

`main.py` imports and re-exports the application components from `app/`, while `app/main_window.py` contains the main `App` class.

---

## Dependencies visible in the current implementation

The application imports and uses:

- Python
- PyQt6
- `cryptography`
- `argon2-cffi`
- `requests`

The application source does not fix specific versions for these libraries, so this README does not claim specific dependency versions.

---

## Development

Run the application through its Python entry point:

```bash
python main.py
```

`main.py` remains the entry point even though most application code now lives in `app/`.

---

## Security scope

EncryptHome is a local desktop application. The current code provides authenticated encryption, password-derived keys, optional device binding, encrypted metadata, integrity checks, secure-deletion options, and local runtime controls.

This README documents the **current implementation**. It does not describe planned EncryptHome 27 features or features that are represented only by unused flags, legacy helpers, comments, or future-oriented code.

---

## License

Proprietary software. All rights reserved.

Copyright © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin.
