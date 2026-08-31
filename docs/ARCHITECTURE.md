# EncryptHome Architecture

## Scope

This document describes the implementation currently present in the repository. Planned or commented-out features are not presented as implemented features.

## Entry point and module structure

`main.py` is the application entry point. It imports and re-exports the application modules for compatibility with existing imports.

```text
main.py
 ├── app/core.py
 ├── app/passwords.py
 ├── app/workers.py
 ├── app/dialogs.py
 └── app/main_window.py

Cryptography / storage
 ├── base.py
 ├── encrypt.py
 ├── decrypt.py
 └── decrypt_preview.py

Utilities
 ├── settings.py
 ├── header_utils.py
 ├── checksum_check.py
 ├── sos_delete.py
 ├── updater.py
 └── screenshot_protection.py
```

## Application startup

```text
main.py
  ↓
QApplication
  ↓
screenshot protection installation
  ↓
device-key generation/check
  ↓
registered device → App
new device → Welcome → Terms → Login/Setup
  ↓
Qt event loop
```

Screenshot protection is optional. On Windows it is installed for EncryptHome-owned Qt windows. On other platforms the installer returns without changing application behavior.

## Main application

### `app/main_window.py`

Contains `App(QWidget)`, the main application window and the main vault workflow. The class handles vault state, UI actions, file operations, preview caching, settings integration, update checks and LAN functionality.

### `app/dialogs.py`

Contains the application dialogs and UI widgets used by the current application, including setup/login, vault/file UI, update/news, details/about, terms and welcome UI.

### `app/passwords.py`

Contains password requirement handling and password-change UI/helpers.

### `app/workers.py`

Contains the background worker objects used by the application, including file-add, export, batch export and startup-update operations.

### `app/core.py`

Contains shared constants and standalone application helpers used by the split application modules.

## Cryptography

### `base.py`

Provides the cryptographic foundation, including per-file subkey derivation.

### `encrypt.py`

Encrypts files and vault metadata and writes encrypted blobs to the container.

### `decrypt.py`

Decrypts metadata and file blobs and performs the associated integrity checks.

### `decrypt_preview.py`

Provides in-memory preview decryption. Preview data is kept in an LRU cache with a 200 MiB total cache limit and a per-file preview limit defined by `PREVIEW_MAX_BYTES`.

## Vault data flow

### Create/open

```text
User
 ↓
select/create .salt container
 ↓
password/device authentication
 ↓
master-key derivation
 ↓
read/write encrypted metadata
 ↓
vault state in App
```

### Add files

```text
selected files
 ↓
AddWorker
 ↓
encrypt file blob
 ↓
update metadata
 ↓
write updated container
```

### Export files

```text
selected vault entries
 ↓
ExportWorker / ExportBatchWorker
 ↓
read encrypted blob
 ↓
verify integrity
 ↓
decrypt
 ↓
write destination file
```

### Preview

```text
vault entry
 ↓
PreviewDecryptWorker
 ↓
decrypt to bytes in memory
 ↓
LRU preview cache
 ↓
preview UI
```

### Password change

Changing the vault password re-encrypts the container data with a newly derived master key. It is not a metadata-only key wrap operation.

## Container format

The current container header is defined by the implementation in `app/core.py` and uses:

```text
Magic:    ANC0
Version:  0x09
Flags:    device/keyfile/pro-related flags
Salt:     16 bytes
Reserved: 6 bytes
```

The resulting header is 28 bytes. The container then stores encrypted file blobs followed by encrypted metadata and its length information.

The implementation is authoritative for the exact binary layout. Changes to this format require explicit compatibility work.

## Utilities

### `utilities/settings.py`

Application settings, settings UI, shortcuts and theme configuration.

### `utilities/header_utils.py`

Container-header validation, detection and repair helpers.

### `utilities/checksum_check.py`

Application integrity/checksum verification and related logging/notifications.

### `utilities/sos_delete.py`

Scans mounted drives for `.salt` vaults and provides the emergency vault deletion workflow.

### `utilities/updater.py`

Update-related functionality.

### `utilities/screenshot_protection.py`

Optional Windows screenshot/capture protection using `SetWindowDisplayAffinity` with `WDA_EXCLUDEFROMCAPTURE`. The module is safe to import on Linux and macOS, where the public installation function is a no-op.

## Threading

The application uses PyQt6 worker objects and signals for background operations. Current workers include:

- `AddWorker`
- `ExportWorker`
- `ExportBatchWorker`
- `StartupUpdateWorker`
- preview worker functionality from `decrypt_preview.py`

The application also uses background threads for selected LAN/search/update-related work.

## Compatibility principles

- Existing `.salt` containers are handled by the current container implementation.
- `main.py` keeps compatibility re-exports for code importing legacy symbols from `main`.
- Screenshot protection does not modify the vault format or encryption/decryption logic.
- Platform-specific features must fail safely and must not prevent the main application from starting.
