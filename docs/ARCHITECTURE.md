# EncryptHome Architecture Documentation

## System Architecture Overview

EncryptHome follows a modular architecture with clear separation of concerns between encryption, user interface, and utility functions. The system is designed around a secure vault container format with device-bound encryption capabilities.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Interface Layer                    │
│                    (PyQt6 - main.py)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ├─────────────────┐
                         │                 │
                         ▼                 ▼
┌─────────────────────────────────┐  ┌──────────────────────┐
│      Encryption Engine          │  │   Utility Modules    │
│  ┌───────────────────────────┐  │  │                      │
│  │ base.py                  │  │  │ settings.py          │
│  │ - Key derivation         │  │  │ header_utils.py      │
│  │ - HKDF functions         │  │  │ checksum_check.py    │
│  ├───────────────────────────┤  │  │ sos_delete.py        │
│  │ encrypt.py               │  │  │ updater.py           │
│  │ - File encryption        │  │  └──────────────────────┘
│  │ - Metadata encryption     │  │
│  ├───────────────────────────┤  │
│  │ decrypt.py               │  │
│  │ - File decryption        │  │
│  │ - Blob handling          │  │
│  ├───────────────────────────┤  │
│  │ decrypt_preview.py       │  │
│  │ - In-memory preview      │  │
│  └───────────────────────────┘  │
└─────────────────────────────────┘
```

## Component Architecture

### 1. Main Application (main.py)

**Responsibilities:**
- GUI orchestration and window management
- User interaction handling
- Vault lifecycle management
- Device binding operations
- File encryption/decryption coordination

**Key Classes:**
- `App(QWidget)` - Main application window
- `SetupDialog(QDialog)` - Device (PC-key) registration upon first run
- `LoginDialog(QDialog)` - Device-based login/authentication
- `FileDropList(QListWidget)` - Custom file list widget with drag-and-drop
- `FreshStartup(QWidget)` - Animated splash/startup screen
- `WelcomeOverlay`, `TermsOfServiceDialog`, `UpdateNewsDialog`, `DetailDialog`, `AboutDialog` - Supporting dialogs
- Various worker objects for background operations

**Data Flow:**
```
User Action → GUI Event → Validation → Worker Thread → 
Encryption/Decryption → Metadata Update → Container Update → UI Refresh
```

### 2. Encryption Engine

#### base.py (Cryptographic Foundation)
**Purpose:** Core cryptographic operations and key derivation

**Key Functions:**
```python
derive_subkey(master_key: bytes, file_nonce: bytes, filename: str) -> bytes
```
- Uses HKDF-SHA256 for per-file key derivation
- Ensures unique encryption keys for each file
- Prevents cross-file cryptographic attacks

#### encrypt.py (Encryption Operations)
**Purpose:** File and metadata encryption

**Key Functions:**
- `encrypt_meta(meta: dict, master_key: bytes) -> bytes`
  - Encrypts vault metadata using AES-GCM
  - Structure: nonce(12) + ciphertext + tag + hmac(32)
  
- `encrypt_file_to_blob(src_path: str, out_fh, master_key: bytes, ...)`
  - Encrypts individual files to encrypted blobs
  - Progress callback support
  - Cancellation support via stop_event

**File Encryption Process:**
```
File → Read in 128KB chunks → AES-GCM encryption → 
HMAC calculation → Write to blob → Append tag and HMAC
```

#### decrypt.py (Decryption Operations)
**Purpose:** File and metadata decryption

**Key Functions:**
- `decrypt_meta(blob: bytes, master_key: bytes) -> dict`
  - Decrypts vault metadata
  - Verifies HMAC integrity
  - Returns parsed metadata dictionary

- `decrypt_blob_range(fh, out_path: str, blob_len: int, master_key: bytes, ...)`
  - Decrypts file blobs from container
  - Temporary file handling
  - Integrity verification

**Decryption Process:**
```
Blob → Read nonce → Verify HMAC → Derive subkey → 
AES-GCM decryption → Write temporary file → Atomic rename
```

#### decrypt_preview.py (Preview System)
**Purpose:** In-memory file preview without disk writes

**Key Components:**
- `PreviewDecryptWorker(QObject)` - Background preview decryption
- `decrypt_entry_to_bytes(...)` - Main preview decryption logic
- Preview size limits (512 MB per file, 200 MB total cache)
- LRU cache management

**Preview Process:**
```
File Request → Check Cache → If miss: Decrypt to RAM → 
Apply size limits → Display in UI → Update LRU cache
```

### 3. Utility Modules

#### settings.py (Configuration Management)
**Responsibilities:**
- Application settings storage and retrieval
- Settings UI dialog
- Keyboard shortcut management
- Theme configuration
- Update mechanism integration

**Configuration Storage:**
- Linux: `~/.config/ANCORATE/settings.json`
- Windows: `%APPDATA%\ANCORATE\settings.json`

#### header_utils.py (Container Header Management)
**Responsibilities:**
- Header validation and verification
- Header repair functionality
- Container format compliance checking

**Key Functions:**
- `detect_header_state(...)` - Determines header presence/completeness
- `restore_header(...)` - Repairs damaged headers
- `verify_header(...)` - Validates header structure

#### checksum_check.py (Integrity Verification)
**Responsibilities:**
- System file integrity verification
- SHA-256 checksum calculation and storage
- Tamper detection and user notification
- Audit logging

**Verification Process:**
```
Application Start → Load stored checksums → Calculate current checksums → 
Compare → Notify user of changes → Log verification results
```

#### sos_delete.py (Emergency Vault Wiper)
**Responsibilities:**
- Scan all mounted drives for `.salt` vault containers (`SaltScannerUI`)
- Emergency deletion of all found vaults
- Used for the "Alle Tresore löschen" maintenance action in Settings

> Note: The secure overwrite algorithms (Standard, DoD 5220.22-M, Gutmann,
> ANCORATE Vaporizer 1 (100x), ANCORATE Furnace Max (200x),
> ANCORATE Shatterer Ultra (300x)) are implemented in `main.py._secure_overwrite`
> and are used when deleting a single file or the whole container from within the app.

## Data Flow Architecture

### Vault Creation Flow
```
User initiates vault creation
    ↓
choose_container(2) selects location and a name
    ↓
Get password (with strength requirements)
    ↓
Generate random salt (16 bytes)
    ↓
Derive master key (Argon2id + HKDF, optional device binding)
    ↓
Build empty metadata {"files": [], "created": ..., "flags": flags}
    ↓
Encrypt and write metadata
    ↓
Save container file
```

### File Encryption Flow
```
User adds files via drag-and-drop
    ↓
Validate file paths and permissions
    ↓
Create AddWorker thread
    ↓
For each file:
    - Generate file nonce (16 bytes)
    - Derive file-specific subkey
    - Encrypt file with AES-GCM
    - Calculate HMAC
    - Append to container
    - Update metadata
    ↓
Re-encrypt metadata with new file list
    ↓
Write metadata length and encrypted metadata
    ↓
Update UI with progress
```

### File Decryption Flow
```
User selects files and triggers export
    ↓
Validate decryption permissions
    ↓
Create ExportWorker thread
    ↓
For each file:
    - Read file blob from container
    - Verify HMAC integrity
    - Derive subkey from file nonce
    - Decrypt with AES-GCM
    - Verify GCM tag
    - Write to destination
    - Delete source if configured
    ↓
Update UI with progress
```

### Password Change Flow
```
User initiates password change
    ↓
Verify new password meets strength requirements
    ↓
Generate new salt
    ↓
Derive new master key with new password (and device key if bound)
    ↓
For each file blob in container:
    - Decrypt blob with old master key (decrypt_blob_range)
    - Re-encrypt with new master key (encrypt_file_to_blob)
    - Record new blob length/offset
    ↓
Write new header (with new salt)
    ↓
Write all re-encrypted blobs
    ↓
Re-encrypt metadata with new master key
    ↓
Atomic rewrite of the container
```

## Container Format Architecture

### Header Structure (28 bytes)
```
Offset | Size | Description
-------|------|-------------
0      | 4    | Magic bytes (ANC0)
4      | 1    | Version (0x09)
5      | 1    | Flags (device, keyfile, pro)
6      | 16   | Salt
22     | 6    | Reserved (future use)
```

### Data Layout
```
[Header 28B]
[File Blob 1]
[File Blob 2]
...
[File Blob N]
[Meta Length 8B]
[Encrypted Metadata]
```

### File Blob Structure
```
Offset | Size | Description
-------|------|-------------
0      | 16   | File nonce
16     | 12   | GCM nonce
28     | var  | Ciphertext
-      | 16   | GCM tag
-      | 32   | HMAC
```

## Memory Architecture

### Memory Management Strategy
- **Preview Cache**: LRU cache with 200 MB total limit
- **Per-File Limit**: 512 MB maximum per preview
- **Chunk Size**: 128 KB for encryption/decryption operations
- **Temporary Files**: Secure cleanup after operations
- **Garbage Collection**: Periodic cleanup every 10 seconds

### Key Storage
- **Master Key**: Exists in memory only during session
- **Device Key**: Generated deterministically at runtime
- **File Subkeys**: Derived on-demand, not stored
- **No Plaintext Storage**: Keys never written to disk

## Threading Architecture

### Worker Threads
- **AddWorker**: Handles file encryption into the container
- **ExportWorker**: Handles single file decryption
- **ExportBatchWorker**: Handles batch file decryption
- **PreviewDecryptWorker**: Handles in-memory preview decryption
- **ChangelogWorker**: Fetches the changelog for the Settings dialog
- **StartupUpdateWorker**: Checks for updates in the background on startup
### Thread Safety
- PyQt6 signals/slots for cross-thread communication
- Stop events for cancellation support
- Mutex protection for shared resources
- Atomic file operations

## Error Handling Architecture

### Error Categories
1. **Cryptographic Errors**: Invalid password, corrupted/tampered data (HMAC/GCM failures)
2. **I/O Errors**: File access issues, disk full, unexpected EOF
3. **Authentication Errors**: Device mismatch (wrong device key)
4. **Validation Errors**: Invalid container format, corrupted headers, pro-vault flag present

### Error Recovery
- Graceful degradation where possible
- User notification with actionable messages
- Automatic cleanup of temporary files
- State preservation on error

## Extension Points

### Planned Features
- Network sharing (discovery modules commented out)
- Multi-factor authentication
- Cloud storage integration
- Advanced preview formats
- Plugin system

### Customization Points
- Keyboard shortcuts (configurable)
- Theme system (configurable)
- Deletion methods (selectable)
- Update sources (configurable)

## Performance Considerations

### Optimization Strategies
- Chunked processing (128 KB blocks)
- Background threading for I/O operations
- LRU caching for frequently accessed previews
- Lazy key derivation
- Progress callbacks for responsive UI

### Resource Limits
- Maximum file size: Limited by available memory
- Preview cache: 200 MB total
- Per-file preview: 512 MB
- Encryption chunk size: 128 KB
- Auto-lock timeout: 5 minutes

## Security Architecture Integration

### Layered Security
1. **Application Layer**: Authentication, access control
2. **Encryption Layer**: AES-GCM, HKDF, Argon2id
3. **Integrity Layer**: HMAC verification, checksum validation
4. **Device Layer**: Hardware fingerprinting, device binding
5. **Storage Layer**: Secure deletion, temporary file cleanup

### Defense in Depth
- Multiple independent security mechanisms
- No single point of failure
- Graceful degradation on component failure
- Comprehensive error handling and logging

This architecture ensures strong security while maintaining usability and performance across different platforms and use cases.
