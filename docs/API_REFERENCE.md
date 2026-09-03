# EncryptHome API Reference

Complete API reference for all EncryptHome modules, functions, and classes.

## Table of Contents
- [base.py](#basepy)
- [encrypt.py](#encryptpy)
- [decrypt.py](#decryptpy)
- [decrypt_preview.py](#decrypt_previewpy)
- [main.py](#mainpy)
- [utilities/settings.py](#utilitiessettingspy)
- [utilities/header_utils.py](#utilitiesheader_utilspy)
- [utilities/checksum_check.py](#utilitieschecksum_checkpy)
- [utilities/sos_delete.py](#utilitiessos_deletepy)
- [utilities/updater.py](#utilitiesupdaterpy)

---

## base.py

Cryptographic foundation module providing key derivation and cryptographic primitives.

### Functions

#### `derive_subkey(master_key: bytes, file_nonce: bytes, filename: str) -> bytes`

Derives a file-specific encryption subkey from the master key using HKDF.

**Parameters:**
- `master_key` (bytes): The 32-byte master key
- `file_nonce` (bytes): 16-byte random nonce for the file
- `filename` (str): Name of the file (used as HKDF info)

**Returns:**
- bytes: 32-byte derived subkey for AES-256

**Algorithm:**
```python
HKDF-SHA256(
    input_key_material=master_key,
    salt=file_nonce,
    info=filename.encode('utf-8'),
    length=32
)
```

**Security Notes:**
- Each file gets a unique subkey
- Prevents cross-file cryptographic attacks
- Deterministic for same file+nonce combination

---

## encrypt.py

File and metadata encryption operations.

### Functions

#### `encrypt_meta(meta: dict, master_key: bytes) -> bytes`

Encrypts vault metadata using AES-GCM.

**Parameters:**
- `meta` (dict): Metadata dictionary to encrypt
- `master_key` (bytes): 32-byte master key

**Returns:**
- bytes: Encrypted metadata blob

**Structure:**
```
nonce(12B) | ciphertext | tag(16B) | hmac(32B)
```

**Process:**
1. Serialize metadata to JSON
2. Generate random 12-byte nonce
3. Encrypt with AES-GCM
4. Calculate HMAC-SHA256
5. Concatenate components

**Security Notes:**
- Metadata contains file list and structure
- Encrypted to prevent information leakage
- HMAC provides integrity verification

---

#### `encrypt_file_to_blob(src_path: str, out_fh, master_key: bytes, filename: str | None = None, progress_cb=None, stop_event: threading.Event | None=None)`

Encrypts a file to an encrypted blob structure.

**Parameters:**
- `src_path` (str): Path to source file
- `out_fh`: Output file handle (must support write)
- `master_key` (bytes): 32-byte master key
- `filename` (str, optional): Logical file name used for subkey derivation (defaults to `basename(src_path)`)
- `progress_cb` (callable, optional): Progress callback function
- `stop_event` (threading.Event, optional): Cancellation event

**Returns:**
- None (writes to out_fh)

**Structure Written:**
```
file_nonce(16B) | gcm_nonce(12B) | ciphertext | tag(16B) | hmac(32B)
```

**Process:**
1. Generate 16-byte file nonce
2. Derive file-specific subkey
3. Generate 12-byte GCM nonce
4. Encrypt file in 128KB chunks
5. Calculate HMAC over ciphertext
6. Write tag and HMAC

**Chunk Size:** 128 KB (128 * 1024 bytes)

**Progress Callback:**
- Called with percentage (0-100)
- File progress is scaled to 0-90 (the remaining 10% is reserved for finalization)

**Cancellation:**
- Checks stop_event before each chunk
- Raises RuntimeError("Cancelled") if stopped

---

## decrypt.py

File and metadata decryption operations.

### Functions

#### `decrypt_key(path: str) -> bytes`

**Deprecated:** Legacy function for keyfile decryption. Currently unused.

**Parameters:**
- `path` (str): Path to keyfile

**Returns:**
- bytes: 32-byte AES key

**Note:** This function is marked as !UNUSED! in the codebase.

---

#### `decrypt_blob_range(fh, out_path: str, blob_len: int, master_key: bytes, filename: str, progress_cb=None, stop_event: threading.Event | None=None)`

Decrypts an encrypted file blob from container.

**Parameters:**
- `fh`: Input file handle (must support seek/read)
- `out_path` (str): Path for decrypted output file
- `blob_len` (int): Length of encrypted blob
- `master_key` (bytes): 32-byte master key
- `filename` (str): Original filename for subkey derivation
- `progress_cb` (callable, optional): Progress callback
- `stop_event` (threading.Event, optional): Cancellation event

**Returns:**
- None (writes to out_path)

**Process:**
1. Read file nonce (16B) and GCM nonce (12B)
2. Calculate ciphertext length
3. Stream ciphertext to temporary file
4. Verify HMAC integrity
5. Derive file-specific subkey
6. Decrypt with AES-GCM
7. Write to temporary file
8. Atomic rename to final destination

**Progress Stages:**
- 0-60%: Reading and HMAC verification
- 60-99%: Decryption
- 100%: Complete

**Error Handling:**
- Raises ValueError on invalid blob length
- Raises IOError on unexpected EOF
- Raises RuntimeError on cancellation

**Atomic Write:**
- Uses temporary file
- Atomic rename on success
- Cleanup on failure

---

#### `decrypt_meta(blob: bytes, master_key: bytes) -> dict`

Decrypts vault metadata from encrypted blob.

**Parameters:**
- `blob` (bytes): Encrypted metadata blob
- `master_key` (bytes): 32-byte master key

**Returns:**
- dict: Decrypted metadata dictionary

**Structure Expected:**
```
nonce(12B) | ciphertext | tag(16B) | hmac(32B)
```

**Process:**
1. Extract nonce, ciphertext, HMAC
2. Verify HMAC integrity
3. Decrypt with AES-GCM
4. Parse JSON metadata

**Error Handling:**
- Raises ValueError on invalid key length (must be 16/24/32 bytes)
- Raises ValueError on invalid blob length
- Raises InvalidSignature on HMAC verification failure

**Security Notes:**
- Verifies integrity before decryption
- Prevents padding oracle attacks
- Metadata must be valid JSON

---

## decrypt_preview.py

In-memory file preview system for encrypted files.

### Constants

```python
PREVIEW_MAX_BYTES = 512 * 1024 * 1024  # 512 MiB max per file
PREVIEW_TEXT_SHOW_BYTES = 128 * 1024 * 1024  # 128 MiB max text display
PREVIEW_HEX_BYTES = 4096  # 4 KiB hex dump limit
```

### Classes

#### `PreviewInfo`

Dataclass containing preview information.

**Attributes:**
- `name` (str): File name
- `size` (int): Original file size
- `loaded_bytes` (int): Bytes loaded into memory
- `truncated` (bool): Whether preview was truncated

---

#### `PreviewDecryptWorker(QObject)`

Worker thread for background preview decryption.

**Signals:**
- `progress(int)`: Progress percentage
- `finished(bytes, PreviewInfo)`: Decryption complete
- `error(str)`: Error occurred

**Constructor:**
```python
PreviewDecryptWorker(
    container_path: str,
    meta_entry: dict,
    master_key: bytes,
    stop_event: Optional[threading.Event] = None,
    max_bytes: int = PREVIEW_MAX_BYTES
)
```

**Methods:**
- `run()`: Main worker method

**Process:**
1. Decrypt file to memory
2. Apply size limits
3. Emit finished signal with data

---

### Functions

#### `decrypt_entry_to_bytes(container_path: str, meta_entry: dict, master_key: bytes, *, stop_event: Optional[threading.Event] = None, progress_cb=None, max_bytes: int = PREVIEW_MAX_BYTES) -> tuple[bytes, PreviewInfo]`

Decrypts a file entry directly to memory for preview.

**Parameters:**
- `container_path` (str): Path to container file
- `meta_entry` (dict): File metadata entry
- `master_key` (bytes): 32-byte master key
- `stop_event` (threading.Event, optional): Cancellation event
- `progress_cb` (callable, optional): Progress callback
- `max_bytes` (int): Maximum bytes to load into memory

**Returns:**
- tuple[bytes, PreviewInfo]: Decrypted data and preview information

**Process:**
1. Validate file size against max_bytes
2. Read file blob from container
3. Verify HMAC integrity
4. Decrypt with AES-GCM
5. Apply size limits
6. Return decrypted data

**Size Limits:**
- Refuses files larger than max_bytes
- Truncates data if necessary
- Sets truncated flag in PreviewInfo

**Error Handling:**
- Raises ValueError if file too large
- Raises IOError on container read errors
- Raises RuntimeError on cancellation

---

#### `_guess_kind(filename: str) -> str`

Guesses file type from extension.

**Parameters:**
- `filename` (str): File name to analyze

**Returns:**
- str: File type ("text", "image", "pdf", "video", "binary")

**Supported Extensions:**

**Text:** .txt, .log, .md, .py, .json, .csv, .xml, .yaml, .yml, .ini, .cfg, .java

**Image:** .png, .jpg, .jpeg, .bmp, .gif, .webp

**PDF:** .pdf

**Video:** .mp4, .m4v, .mov, .avi, .mkv, .webm, .wmv, .mpg, .mpeg, .3gp, .3g2, .flv

**Default:** binary

---

#### `_hexdump(data: bytes, max_bytes: int = PREVIEW_HEX_BYTES) -> str`

Creates hex dump of binary data.

**Parameters:**
- `data` (bytes): Binary data to dump
- `max_bytes` (int): Maximum bytes to process (default 4KB)

**Returns:**
- str: Formatted hex dump string

**Format:**
```
0000: XX XX XX XX ... ASCII
```

**Purpose:** Fallback preview for unrecognized binary files

---

## main.py

Main application module containing GUI and orchestration logic.

### Constants

```python
MAGIC = b"ANC0"                    # Container magic bytes
VERSION = 0x09                     # Container format version
FLAG_DEVICE = 0x01                # Device binding flag
FLAG_KEYFILE = 0x02               # Keyfile flag
FLAG_PRO_VAULT = 0x04             # Pro vault flag
SALT_LEN = 16                      # Salt length
CHUNK = 128 * 1024                # Encryption chunk size
META_LEN_SIZE = 8                 # Metadata length size
ARGON2_TIME = 3                    # Argon2 time cost
ARGON2_MEM_KIB = 131072            # Argon2 memory cost
ARGON2_PAR = 4                     # Argon2 parallelism
ARGON2_OUT = 32                    # Argon2 output length
SCRYPT_N = 2**14                  # Scrypt N parameter
SCRYPT_R = 8                       # Scrypt r parameter
SCRYPT_P = 1                       # Scrypt p parameter
PROJECT_PEPPER = b"ANCORATE_734912285612843967510042198831607952451"
HEADER_FMT = f"4s B B {SALT_LEN}s 6s"
HEADER_LEN = 28
HKDF_INFO = b"ANCORATE-MASTER-26"
HKDF_LENGTH = 32
```

### Classes

#### `App(QWidget)`

Main application window class.

**Constructor:**
```python
App.__init__()
```

**Key Attributes:**
- `container_path` (str): Current container path
- `master_key` (bytes): Current session master key
- `meta` (dict): Current metadata
- `flags` (int): Current container flags
- `_preview_cache` (OrderedDict): LRU preview cache
- `_preview_cache_limit` (int): Total cache limit (200 MB)
- `MAX_ATTEMPTS` (int): Maximum login attempts (3)
- `timeout_ms` (int): Auto-lock timeout (300000ms)

**Key Methods:**

- `choose_container(mode=1)`: Container selection dialog
- `add_file_dialog()`: File addition dialog
- `export_selected()`: Export selected files
- `export_all()`: Export all files
- `delete_selected()`: Delete selected files
- `preview_selected()`: Preview selected file
- `start_search()`: Search in vault
- `delete_container()`: Delete current container
- `show_recent_containers()`: Show recent containers
- `apply_settings()`: Apply settings changes
- `open_settings()`: Open settings dialog

**Signals:**
- Uses PyQt6 signal/slot mechanism
- Custom signals for worker threads

---

#### `SetupDialog(QDialog)`

Vault creation wizard dialog.

**Purpose:** Guide users through vault creation process.

**Steps:**
1. Select container location
2. Enter password
3. Choose security options (device binding)
4. Create vault

---

#### `LoginDialog(QDialog)`

Authentication dialog for vault access.

**Purpose:** Authenticate users before vault access.

**Features:**
- Password input
- Attempt limiting (3 max)
- Device binding verification
- Error messages

**Security Notes:**
- Limits attempts to prevent brute force
- Locks after 3 failed attempts
- Clears memory on failure

---

#### `FileDropList(QListWidget)`

Custom file list widget with drag-and-drop support.

**Signal:**
- `fileDropped(list[str])`: Emitted when files are dropped

**Methods:**
- `selected_file_paths() -> list[str]`: Get selected file paths

---

### Functions

#### `derive_argon2(password_bytes: bytes, salt: bytes) -> bytes`

Runs the raw Argon2id KDF used for password hardening.

**Parameters:**
- `password_bytes` (bytes): Password bytes (pre-mixed with the project pepper by `derive_master_key`)
- `salt` (bytes): 16-byte random salt

**Returns:** bytes - 32-byte Argon2id-derived key

**Parameters:** time=3, memory=131072 KiB, parallelism=4, hash_len=32 (Argon2id)

---

#### `derive_master_key(password: str, salt: bytes, device_bound: bool = False, device_key: Optional[bytes] = None) -> bytes`

Derives the container master key from the password (and optional device key).

**Parameters:**
- `password` (str): User password
- `salt` (bytes): 16-byte container salt
- `device_bound` (bool): Whether the container uses device binding
- `device_key` (bytes, optional): 32-byte device key (required if `device_bound`)

**Returns:** bytes - 32-byte AES-256 master key

**Process:**
1. `pwd_key = Argon2id(password + PROJECT_PEPPER, salt)`
2. `device_hash = SHA256(device_key)` if bound, else empty
3. `master = HKDF-SHA256(pwd_key + device_hash, salt=salt, info=HKDF_INFO)`

**Raises:** `ValueError` if the salt is not 16 bytes or a bound container has no valid 32-byte `device_key`.

---

#### `validate_password_strength(password: str) -> tuple[bool, str]`

Validates password strength against the project policy.

**Returns:** tuple[bool, str] - `(is_valid, error_message)`

**Requirements (all must hold):**
- At least 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (from `!@#$%^&*()_+-=[]{}|;:,.<>?`)

---

#### `write_header(fh, flags: int, salt: bytes)`

Writes the 28-byte ANCORATE header (`MAGIC | VERSION | flags | salt | reserved`) at the start of the file.

**Raises:** `ValueError` if the salt is not 16 bytes or flags are not in 0-255.

---

#### `read_header(fh)`

Reads and validates the header of an open container, repairing it if damaged.

**Returns:** tuple[flags, salt]

---

#### `device_fingerprint() -> bytes`

Generates device fingerprint from hardware identifiers.

**Returns:**
- bytes: 32-byte SHA-256 hash of device components

**Components:**
- MAC address (6 bytes)
- CPU ID (variable)
- Disk serial (variable)

**Process:**
1. Get MAC address via UUID
2. Get CPU ID (platform-specific)
3. Get disk serial (platform-specific)
4. Combine with separator
5. SHA-256 hash

**Fallback:** Uses hostname and system name if fingerprint fails

---

#### `generate_device_key() -> bytes`

Generates deterministic device key.

**Returns:**
- bytes: 32-byte device key

**Process:**
1. Get device fingerprint
2. Combine with fixed seed
3. SHA-256 hash

**Deterministic:** Same device always generates same key

---

#### `load_device_key() -> bytes`

Loads or generates device key.

**Returns:**
- bytes: 32-byte device key

**Process:**
1. Generate device key at runtime
2. Validate length (must be 32 bytes)
3. Return key or empty bytes on failure

**Note:** Device key is no longer stored to file for security

---

#### `rekey_container_password(container_path: str, current_meta: dict, current_flags: int, current_master_key: bytes, new_password: str) -> None`

Changes vault password by re-encrypting all data.

**Parameters:**
- `container_path` (str): Path to container
- `current_meta` (dict): Current metadata
- `current_flags` (int): Current flags
- `current_master_key` (bytes): Current master key
- `new_password` (str): New password

**Process:**
1. Generate new salt
2. Derive new master key
3. For each file:
   - Decrypt with old key
   - Re-encrypt with new key
4. Update header
5. Re-encrypt metadata
6. Rewrite container

**Time Complexity:** O(n) where n is number/size of files

---

#### Container operations (`utilities/container_ops.py`)

##### `file_sha256(path: str, chunk_size: int = 128 * 1024) -> str`

Streams a file and returns its hex SHA-256. Used to store a plaintext integrity hash in the file metadata.

##### `new_file_entry(name, size, offset, length, *, mtime=None, created=None, added=None, edited=None, sha256=None) -> dict`

Builds a metadata entry dictionary for a file in the vault.

##### `touch_container_meta(meta: dict, *, flags: int | None = None, app_version: str | None = None) -> dict`

Updates the container-level metadata (`modified`, optional `flags`/`app_version`, and a `format` default).

##### `replace_entry_in_container(container_path, meta, entry_index, new_data_path, master_key, flags, *, progress_cb=None, stop_event=None, app_version=None) -> dict`

Replaces a single vault entry with the content of `new_data_path` by rebuilding the container atomically into a temporary file and replacing the original only on success. Unchanged blobs are copied verbatim and the salt is preserved so the master key stays valid. On cancel or error the original container remains untouched. Returns the new metadata with updated offsets/lengths.

---

#### `RewriteEntryWorker(QObject)`

Background worker that calls `replace_entry_in_container`. Signals: `progress(int)`, `finished(object)` (new metadata), `error(str)`. Used by the in-vault editing flow.

**Space Complexity:** O(1) - uses temporary files

---

## utilities/settings.py

Settings management and configuration UI.

### Constants

```python
CONFIG_DIR = "~/.ancorate" (or platform-specific)
SETTINGS_FILE = "settings.json"
VERSION_YEAR = "27"
VERSION_FULL = "27.0-beta.1"
UPDATE_URL = "https://ancorate.github.io/latest/EncryptHome/latest.json"
```

### Default Settings

```python
DEFAULT_SETTINGS = {
    # Hotkeys
    "o_seq": "Ctrl+E",
    "del_seq": "Del",
    "add_seq": "Ctrl++",
    "vault_o_seq": "Ctrl+O",
    "o_all_seq": "Alt+E",
    "search_seq": "Return",
    "crea_vault_seq": "Ctrl+N",
    "del_vault_seq": "Alt+Del",

    # Design
    "theme": "Standard-dark",

    # Updater
    "update_url": UPDATE_URL,

    # System & Behavior
    "confirm_exit": True,
    "del_source_added": False,

    # Security & Paths
    "deletion_method": "Standard",  # Standard, DoD, Gutmann, ANCORATE ...
}
```

**Theme handling:** Only two themes exist — `Standard-dark` (default) and `Standard-White` (`VALID_THEMES = ("Standard-dark", "Standard-White")`). During `load_settings()`, any legacy or unknown stored theme value is automatically migrated to `Standard-dark`. The mapping of theme name to stylesheet file lives in `app.core.THEMES`, with `DEFAULT_THEME = "Standard-dark"` as fallback. `app.core.APP_STYLE` holds the loaded stylesheet that is applied application-wide.

### Classes

#### `SettingsDialog(QDialog)`

Settings configuration dialog.

**Constructor:**
```python
SettingsDialog.__init__(parent=None)
```

**Tabs:**
- General ("Allgemein"): System behavior, security/deletion method, maintenance
- Shortcuts ("Kurzbefehle"): Keyboard shortcut configuration
- Design: Theme and appearance (Standard-dark / Standard-White)
- Updates: Changelog, update check and install

**Methods:**
- `display_category(row)`: Switch between tabs
- `save()`: Close and confirm the dialog
- `_save_immediate()`, `_save_deletion_method()`, `_save_theme()`, `_save_shortcuts()`: Immediate (auto-save) handlers

---

#### `ChangelogWorker(QThread)`

Background worker for fetching changelog.

**Signals:**
- `finished(dict)`: Changelog data loaded
- `error(str)`: Error occurred

**Process:**
1. HTTP GET to UPDATE_URL
2. Parse JSON response
3. Emit result

**Timeout:** 5 seconds

---

### Functions

#### `load_settings() -> dict`

Loads application settings from file.

**Returns:**
- dict: Settings dictionary

**Process:**
1. Check if settings file exists
2. Load and parse JSON
3. Merge with defaults for missing keys
4. Return settings

**Fallback:** Returns DEFAULT_SETTINGS if file missing or invalid

---

#### `save_settings(settings: dict)`

Saves application settings to file.

**Parameters:**
- `settings` (dict): Settings dictionary to save

**Process:**
1. Serialize to JSON with indentation
2. Write to settings file
3. Handle errors gracefully

**Error Handling:**
- Prints error on failure
- Does not raise exception

---

## utilities/header_utils.py

Container header validation and repair utilities.

### Functions

#### `detect_header_state(data: bytes, header_fmt: str, magic: bytes, header_len: int) -> str`

Detects header state in container data.

**Parameters:**
- `data` (bytes): Container data
- `header_fmt` (str): Struct format string
- `magic` (bytes): Magic bytes to detect
- `header_len` (int): Expected header length

**Returns:**
- str: "none", "partial", or "full"

**States:**
- "none": No header found
- "partial": Incomplete or corrupted header
- "full": Valid complete header

---

#### `restore_header(input_path: str, output_path: str, salt: bytes, flags: int, write_header_func, header_fmt: str, magic: bytes, header_len: int)`

Restores header to container file.

**Parameters:**
- `input_path` (str): Path to damaged container
- `output_path` (str): Path for repaired container
- `salt` (bytes): Salt for header
- `flags` (int): Header flags
- `write_header_func` (callable): Function to write header
- `header_fmt` (str): Struct format string
- `magic` (bytes): Magic bytes
- `header_len` (int): Header length

**Process:**
1. Detect current header state
2. Remove existing header if present
3. Write new header
4. Append original data
5. Write to output path

**States Handled:**
- No header: Adds new header
- Partial header: Removes and replaces
- Full header: Replaces

---

#### `verify_header(path: str, header_fmt: str, magic: bytes, flags_device: int, flags_keyfile: int, header_len: int) -> dict`

Verifies and parses container header.

**Parameters:**
- `path` (str): Path to container file
- `header_fmt` (str): Struct format string
- `magic` (bytes): Expected magic bytes
- `flags_device` (int): Device binding flag value
- `flags_keyfile` (int): Keyfile flag value
- `header_len` (int): Expected header length

**Returns:**
- dict: Parsed header fields or None if invalid

**Dictionary Structure:**
```python
{
    "magic": bytes,
    "version": int,
    "flags": int,
    "salt": bytes,
    "reserved": bytes
}
```

**Process:**
1. Read header bytes
2. Validate length
3. Unpack using struct format
4. Verify magic bytes
5. Return parsed fields

**Error Handling:**
- Returns None on any validation failure

---

## utilities/checksum_check.py

File integrity verification system.

### Constants

```python
CHECKSUM_FILE = "utilities/checksums.json"
CHECKSUM_LOG = "checksum_log.json"
```

### Functions

#### `calculate_checksum(file_path: str) -> str`

Calculates SHA-256 checksum of file.

**Parameters:**
- `file_path` (str): Path to file

**Returns:**
- str: Hexadecimal SHA-256 checksum

**Process:**
1. Open file in binary mode
2. Read in 4KB blocks
3. Update hash with each block
4. Return hexadecimal digest

**Block Size:** 4096 bytes

---

#### `verify_file_integrity(file_path: str = None, update=False)`

Verifies file integrity against stored checksums.

**Parameters:**
- `file_path` (str, optional): Path to file (defaults to executable)
- `update` (bool): Whether to update stored checksum

**Process:**
1. Load stored checksums
2. Calculate current checksum
3. Compare checksums
4. Notify user of changes
5. Log verification result
6. Optionally update stored checksum

**User Interaction:**
- Shows warning on mismatch
- Asks confirmation before update
- Exits on user rejection

**Log Entry:**
```python
{
    "timestamp": str,
    "file": str,
    "old_checksum": str,
    "new_checksum": str,
    "action": str
}
```

**Actions:**
- "verified": Checksum matched
- "updated": Checksum updated
- "user_rejected": User rejected change
- "registered": New file registered

---

#### `load_checksums() -> dict`

Loads stored checksums from file.

**Returns:**
- dict: Checksum dictionary {filename: checksum}

**Error Handling:**
- Returns empty dict if file missing or invalid

---

#### `save_checksums(data: dict)`

Saves checksums to file.

**Parameters:**
- `data` (dict): Checksum dictionary to save

**Format:**
```json
{
    "filename1": "checksum1",
    "filename2": "checksum2"
}
```

---

#### `log_checksum_action(filename: str, old_checksum: str, new_checksum: str, action: str)`

Logs checksum verification action.

**Parameters:**
- `filename` (str): File name
- `old_checksum` (str): Previous checksum
- `new_checksum` (str): Current checksum
- `action` (str): Action performed

**Log Format:**
```json
{
    "timestamp": "ISO-8601",
    "file": "filename",
    "old_checksum": "old",
    "new_checksum": "new",
    "action": "action"
}
```

**Append Mode:** Adds to existing log file

---

## utilities/sos_delete.py

Emergency vault scanner and wiper.

### Class

#### `SaltScannerUI(QWidget)`

Scans all mounted drives for `.salt` vaults and deletes them in an emergency.

**Methods:**
- `run_scan()`: Starts a background scan of all drives for `.salt` files
- `emergency_delete()`: Unconditionally deletes all listed vaults
- `_update_ui_progress()`, `_scan_complete()`, `_scan_error()`, `_delete_complete()`: UI callbacks

### Functions

- `get_all_drives() -> list`: Lists existing drive mount points (via psutil)
- `search_salt_files(start_dir) -> list`: Walks a directory tree collecting `.salt` paths

> The actual secure-overwrite deletion methods are implemented in `main.py._secure_overwrite`
> (Standard / DoD 5220.22-M / Gutmann / ANCORATE Vaporizer 1 / Furnace Max / Shatterer Ultra).

---

## utilities/updater.py

Application update mechanism.

### Class

#### `EncryptHomeUpdater`

Downloads and launches the EncryptHome installer.

**Constructor:**
```python
EncryptHomeUpdater(current_version: str, update_json_url: str)
```

**Methods:**
- `run() -> dict`: Checks the update feed; returns `{"status": "NO_UPDATE" | "UPDATE_AVAILABLE", "data": ...}`
- `start_update()`: Downloads the installer, verifies its SHA-256, launches it (UAC on Windows) and exits
- `_fetch_latest_json()`, `_download_file()`, `_verify_sha256()`: Internal helpers

---

This API reference covers all public APIs and important internal functions. For implementation details, refer to the source code.

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
