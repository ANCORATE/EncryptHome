# ANCORATE EncryptHome

**EncryptHome 26.2 — Citadel**

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
- Recent-container history (up to 10 entries)
- In-memory file preview with a bounded LRU cache
- Configurable secure-deletion methods
- Optional deletion of source files after successful encryption
- Changing the password of an existing vault
- Auto-lock behavior
- Configurable keyboard shortcuts
- Dark/light application themes
- Application integrity/update checks
- Update news and changelog display
- A settings window with General, Shortcuts, Design, and Updates sections
- Technical details and About dialogs
- A local emergency vault-deletion scanner

The current GUI also contains LAN-sharing infrastructure in the `App` class. It defines UDP discovery and TCP transfer ports for ANCORATE LAN functionality.

## Current version

The code identifies itself as:

```text
EncryptHome 26.2
Edition: EncryptHome
Codename: Citadel
Container version: 0x09
```

`main.py` is the application entry point. It re-exports the application modules so existing imports from `main` continue to work. fileciteturn8file0

---

## Cryptography

The current implementation uses the Python `cryptography` package for AES-GCM, HKDF, HMAC, and related primitives.

### File encryption

Each encrypted file uses:

- A random 16-byte file nonce
- A random 12-byte AES-GCM nonce
- A per-file 32-byte subkey derived with HKDF-SHA256
- AES-GCM encryption
- An HMAC-SHA256 value over the ciphertext

Files are processed in **128 KiB chunks**. fileciteturn14file0 fileciteturn18file0

### Metadata encryption

Vault metadata is serialized as JSON and encrypted with AES-GCM. The encrypted metadata also receives an HMAC-SHA256 value. fileciteturn14file0

### Important implementation detail

The per-file HKDF currently uses the file nonce as its salt and the UTF-8 encoded filename as its HKDF `info` value. The resulting 32-byte key is used for AES-256-GCM. fileciteturn18file0

---

## Device binding

Device-bound vaults use a runtime-generated device key.

The current device fingerprint is built from:

- MAC address
- CPU information
- Disk information

Those values are hashed with SHA-256. A deterministic device key is then derived from that fingerprint. The key is generated at runtime rather than being stored as a persistent key file. fileciteturn19file0

The application also keeps a local registration marker to determine whether the device has already completed the initial registration flow. fileciteturn19file0

---

## Passwords

Password input has live requirements for:

- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

The same validation is used when changing an existing vault password. fileciteturn13file0

Changing a vault password re-encrypts the vault's file data with newly derived key material. The implementation is designed to leave the existing container unchanged if the re-key operation fails before the new container can be written. fileciteturn19file0

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

The current implementation therefore reserves space for these flags, although the legacy keyfile decryption helper is marked unused in `decrypt.py`. fileciteturn19file0 fileciteturn15file0

A file blob contains:

```text
16-byte file nonce
12-byte GCM nonce
ciphertext
16-byte GCM tag
32-byte HMAC-SHA256
```

The vault stores encrypted metadata together with its length at the end of the container. fileciteturn14file0 fileciteturn12file0

---

## Integrity checks

The code verifies encrypted data with multiple mechanisms:

- AES-GCM authentication
- HMAC-SHA256 verification for file ciphertext
- HMAC-SHA256 verification for metadata
- Container/header validation during vault access
- Application checksum/update infrastructure

When file HMAC or AES-GCM verification fails during export/decryption, the application reports the vault as having an invalid password or damaged data instead of accepting the unauthenticated plaintext. fileciteturn15file0

---

## File preview

EncryptHome supports file preview through a dedicated preview worker and an in-memory cache in the main application.

The current `App` implementation keeps preview data in an LRU cache with a total cache limit of **200 MiB** and applies a maximum preview-file size from `decrypt_preview.py`. fileciteturn10file0

---

## Secure deletion

The Settings dialog currently exposes these deletion choices:

- Standard (Schnell)
- DoD 5220.22-M (3x)
- Gutmann (35x)
- ANCORATE Vaporizer 1 (100x)
- ANCORATE Furnace Max (200x, large files)
- ANCORATE Shatterer Ultra (300x; marked in the UI as not for HDD use)

The settings also include an option to delete the original source file after successful encryption. fileciteturn16file0

EncryptHome also exposes an emergency function for scanning/deleting vaults through `SaltScannerUI`. fileciteturn16file0

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
- Start file preview
- Delete selected file(s)
- Export selected file(s)
- Export all files

### Help

- About EncryptHome

The file list supports extended selection and accepts dropped local files. Double-clicking an entry starts its preview. fileciteturn10file0 fileciteturn11file0

---

## Export and encryption workers

Long-running operations use Qt workers/signals.

The current code contains:

- `AddWorker` for encrypting files into an existing vault
- `ExportWorker` for exporting one file
- `ExportBatchWorker` for exporting multiple files
- `StartupUpdateWorker` for background update checks

The add worker supports progress reporting, cancellation through a `threading.Event`, and removal of source files after successful encryption when that setting is enabled. fileciteturn12file0

---

## Recent containers

EncryptHome stores recent container information locally and keeps the most recent **10** entries.

Each entry contains the container path, container name, and last-accessed timestamp. The UI allows opening a recent container or clearing the recent-container list. fileciteturn19file0 fileciteturn10file0

---

## Auto-lock and runtime cleanup

The main window initializes a **5-minute auto-lock timeout** and runs a periodic cleanup timer every **10 seconds**. The cleanup invokes Python garbage collection. fileciteturn10file0

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

The Settings dialog allows these shortcuts to be edited with Qt's `QKeySequenceEdit`. fileciteturn10file0 fileciteturn16file0

---

## Settings

The current Settings dialog has four categories:

1. **Allgemein**
2. **Kurzbefehle**
3. **Design**
4. **Updates**

General settings currently include:

- Confirm before exiting
- Delete the original source after successful encryption
- Secure deletion method
- Temporary-cache cleanup
- Immediate application exit
- Emergency vault deletion scanner

The update system uses the configured update URL and can display release notes/changelog data. fileciteturn16file0

---

## Application startup

On startup, EncryptHome:

1. Generates the runtime device key.
2. Checks whether the device has already been registered.
3. For a new device, shows the welcome flow, Terms of Service, and login/setup flow.
4. For an already registered device, opens the main window directly.
5. Starts the background update check.

The startup flow is implemented in `main.py`. fileciteturn8file0

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
│   └── main_window.py
├── utilities/
│   ├── settings.py
│   ├── header_utils.py
│   ├── checksum_check.py
│   ├── updater.py
│   ├── sos_delete.py
│   └── themes/
├── docs/
└── README.md
```

`main.py` imports and re-exports the application components from `app/`, while `app/main_window.py` contains the main `App` class. fileciteturn8file0 fileciteturn10file0

---

## Dependencies visible in the current implementation

The application imports and uses:

- Python
- PyQt6
- `cryptography`
- `argon2-cffi`
- `requests`

The exact versions are not fixed by the application source shown here, so this README does not claim specific library versions.

---

## Development

Run the application through its Python entry point:

```bash
python main.py
```

`main.py` is intentionally kept as the entry point even though most application code now lives in `app/`. fileciteturn8file0

---

## Security scope

EncryptHome is a local desktop application. The code provides authenticated encryption, password-derived keys, optional device binding, encrypted metadata, integrity checks, secure-deletion options, and local runtime controls.

This README documents the **current implementation**. It does not describe planned EncryptHome 27 features or other features that are only represented by unused flags, legacy helpers, comments, or future-oriented code.

---

## License

Proprietary software. All rights reserved.

Copyright © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin.
