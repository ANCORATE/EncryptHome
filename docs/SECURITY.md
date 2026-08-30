# EncryptHome Security Documentation

## Security Overview

EncryptHome implements a multi-layered security architecture designed to protect user data through strong encryption, device-bound authentication, and comprehensive integrity verification. This document details the security model, cryptographic implementation, and threat analysis.

## Security Principles

### Core Security Priorities
1. **Security** - All design decisions prioritize security
2. **Reliability** - Consistent and predictable security behavior
3. **Compatibility** - Maintain backward compatibility with user data
4. **Maintainability** - Security features must be maintainable
5. **User Experience** - Security should not compromise usability

### Non-Negotiable Security Requirements
- Never disable encryption
- Never reduce cryptographic strength
- Never store secrets in plaintext
- Never log sensitive information
- Never bypass authentication
- Never introduce insecure defaults
- Never circumvent security checks

## Cryptographic Architecture

### Encryption Stack

```
User Password
    ↓
Project Pepper (fixed, appended to password)
    ↓
Argon2id Key Derivation
    ├─ Time Cost: 3
    ├─ Memory Cost: 128 MB
    ├─ Parallelism: 4
    └─ Output: 32 bytes
    ↓
Password-derived key (32 bytes)
    ↓
Device Key hash (SHA-256) if device-bound
    ↓
HKDF-SHA256 (salt=salt, info=HKDF_INFO) → Master Key (32 bytes)
    ↓
HKDF-SHA256 (per-file)
    ├─ Salt: File nonce (16 bytes)
    ├─ Info: Filename
    └─ Output: 32 bytes
    ↓
File Subkey (32 bytes)
    ↓
AES-256-GCM Encryption
    ├─ Nonce: 12 bytes
    ├─ Authentication Tag: 16 bytes
    └─ Ciphertext
    ↓
HMAC-SHA256 (integrity)
    └─ Output: 32 bytes
```

### Cryptographic Parameters

#### Argon2id Parameters
- **Algorithm**: Argon2id (hybrid of Argon2i and Argon2d)
- **Time Cost**: 3 iterations
- **Memory Cost**: 131,072 KiB (128 MB)
- **Parallelism**: 4 threads
- **Output Length**: 32 bytes
- **Salt Length**: 16 bytes

**Rationale**: These parameters provide strong protection against:
- GPU/ASIC attacks (high memory cost)
- Side-channel attacks (Argon2id hybrid)
- Dictionary attacks (high iteration count)

#### AES-256-GCM Parameters
- **Key Size**: 256 bits
- **Block Size**: 128 bits
- **Nonce Size**: 96 bits (12 bytes)
- **Authentication Tag**: 128 bits (16 bytes)

**Rationale**: 
- AES-256 provides 256-bit security level
- GCM mode provides authenticated encryption
- 96-bit nonce balances collision risk and security

#### HKDF Parameters
- **Hash Function**: SHA-256
- **Input Key Material**: Master key (32 bytes)
- **Salt**: File nonce (16 bytes)
- **Info**: Filename (UTF-8 encoded)
- **Output Length**: 32 bytes

**Rationale**:
- HKDF provides cryptographically strong key derivation
- Per-file unique keys prevent cross-file cryptographic attacks
- File nonce ensures deterministic but unique key derivation

### Constants and Magic Values

```python
MAGIC = b"ANC0"                    # Container identifier
VERSION = 0x09                     # Current format version
SALT_LEN = 16                      # Salt length in bytes
CHUNK = 128 * 1024                 # Encryption chunk size (128 KB)
ARGON2_TIME = 3                    # Argon2 time cost
ARGON2_MEM_KIB = 131072            # Argon2 memory cost (128 MB)
ARGON2_PAR = 4                     # Argon2 parallelism
ARGON2_OUT = 32                    # Argon2 output length
PROJECT_PEPPER = b"ANCORATE_734912285612843967510042198831607952451"
HKDF_INFO = b"ANCORATE-MASTER-26"
HKDF_LENGTH = 32                   # HKDF output length
```

## Device Binding Architecture

### Device Fingerprinting

Device fingerprinting provides hardware-based security by binding vaults to specific physical devices.

### Fingerprint Components

#### MAC Address
- **Source**: UUID.getnode()
- **Format**: 6 bytes, big-endian
- **Uniqueness**: Network interface hardware identifier
- **Spoofing Difficulty**: Moderate (can be changed in software)

#### CPU ID
- **Windows**: `wmic cpu get ProcessorId`
- **macOS**: `sysctl -n machdep.cpu.brand_string`
- **Linux**: `/proc/cpuinfo` model name
- **Format**: Variable-length string
- **Uniqueness**: CPU hardware identifier
- **Spoofing Difficulty**: High (requires CPU replacement)

#### Disk Serial
- **Windows**: `wmic diskdrive get SerialNumber`
- **macOS**: `diskutil info / | grep 'Volume UUID'`
- **Linux**: `lsblk -d -o serial -n`
- **Format**: Variable-length string
- **Uniqueness**: Disk hardware identifier
- **Spoofing Difficulty**: Moderate-High (can be cloned)

### Fingerprint Generation

```python
def device_fingerprint() -> bytes:
    raw = b"|".join([
        b"MAC", mac_bytes,
        b"CPU", cpu_id.encode("utf-8"),
        b"DSK", disk_serial.encode("utf-8")
    ])
    return hashlib.sha256(raw).digest()
```

### Device Key Generation

```python
def generate_device_key() -> bytes:
    fp = device_fingerprint()
    seed = b"ANCORATE_DEVICE_KEY_SEED_2026_STABLE"
    return hashlib.sha256(fp + seed).digest()
```

**Security Properties**:
- Deterministic: Same device generates same key
- No storage: Key generated at runtime, not persisted
- Combined with master key: Requires both password and device
- Fallback: Graceful degradation if fingerprint fails

### Device Binding Flags

```python
FLAG_DEVICE = 0x01    # Container requires device binding
FLAG_KEYFILE = 0x02   # Container uses keyfile authentication
FLAG_PRO_VAULT = 0x04 # Container created with EncryptPro
```

## Container Security

### Container Format Security

#### Header Integrity
```
Magic (4B) | Version (1B) | Flags (1B) | Salt (16B) | Reserved (6B)
```

**Security Features**:
- Magic bytes prevent format confusion attacks
- Version ensures compatibility checking
- Flags control security features
- Random salt prevents rainbow table attacks
- Reserved bytes for future security enhancements

#### File Blob Security
```
File Nonce (16B) | GCM Nonce (12B) | Ciphertext | GCM Tag (16B) | HMAC (32B)
```

**Security Features**:
- Per-file nonce ensures unique encryption
- GCM provides authenticated encryption
- HMAC provides additional integrity layer
- Dual verification prevents tampering

#### Metadata Security
```
Nonce (12B) | Encrypted Metadata | GCM Tag | HMAC (32B)
```

**Security Features**:
- Encrypted file list prevents information leakage
- Integrity verification prevents metadata tampering
- Single point of metadata prevents partial corruption

## Integrity Verification

### Multi-Layer Integrity Checks

#### 1. HMAC Verification
- **Algorithm**: HMAC-SHA256
- **Scope**: All ciphertext data
- **Purpose**: Detect data tampering
- **Location**: Per-file and metadata

#### 2. GCM Tag Verification
- **Algorithm**: AES-GCM authentication tag
- **Scope**: Per-file ciphertext
- **Purpose**: Authenticated encryption
- **Location**: During decryption

#### 3. System File Checksums
- **Algorithm**: SHA-256
- **Scope**: Application executable and system files
- **Purpose**: Detect application tampering
- **Storage**: `utilities/checksums.json`

#### 4. Header Validation
- **Algorithm**: Structural validation
- **Scope**: Container header
- **Purpose**: Detect format corruption
- **Implementation**: `header_utils.py`

### Checksum System

```python
def verify_file_integrity(file_path: str = None, update=False):
    # Load stored checksums
    checksums = load_checksums()
    
    # Calculate current checksum
    new_checksum = calculate_checksum(file_path)
    
    # Compare and notify user of changes
    if checksums[filename] != new_checksum:
        show_warning("File has been modified")
        log_checksum_action(filename, old_checksum, new_checksum, "verified")
```

**Security Benefits**:
- Detects malicious application modification
- Prevents execution of tampered binaries
- Audit trail of all changes
- User confirmation on updates

## Memory Security

### Key Management

#### Master Key Storage
- **Location**: Memory only (RAM)
- **Lifetime**: Session duration
- **Cleanup**: Overwritten on logout
- **Persistence**: Never written to disk

#### Device Key Storage
- **Location**: Generated at runtime
- **Lifetime**: Operation duration
- **Derivation**: Deterministic from hardware
- **Persistence**: Not stored

#### File Subkeys
- **Location**: Derived on-demand
- **Lifetime**: Operation duration
- **Derivation**: HKDF from master key
- **Persistence**: Not stored

### Memory Protection

#### Preview Cache
- **Type**: LRU (Least Recently Used)
- **Total Limit**: 200 MB
- **Per-File Limit**: 512 MB
- **Content**: Decrypted file data
- **Cleanup**: Automatic eviction

#### Temporary Files
- **Location**: System temp directory
- **Lifetime**: Operation duration
- **Cleanup**: Secure deletion
- **Naming**: Random temporary names

#### Garbage Collection
- **Frequency**: Every 10 seconds
- **Scope**: Python objects and file handles
- **Purpose**: Prevent memory leaks
- **Implementation**: `gc.collect()`

### Memory Security Best Practices
- No plaintext keys in swap space (system-dependent)
- Zeroization of sensitive data when possible
- Limited preview caching reduces exposure
- Regular garbage collection prevents accumulation

## Authentication Security

### Password Policy

#### Password Requirements
- **Minimum Length**: 8 characters (enforced)
- **Complexity**: At least one uppercase letter, lowercase letter, digit and special character (enforced via `validate_password_strength`)
- **Storage**: Never stored in plaintext
- **Derivation**: Argon2id with strong parameters + HKDF-SHA256

#### Authentication Flow
```
User enters password
    ↓
Derive master key using password + salt (+ device key if bound)
    ↓
Attempt to decrypt metadata
    ↓
If success: Unlock vault
If failure: Show a password/device error
```

#### Attempt Limiting
- **Maximum Attempts**: Not enforced by the application (the `MAX_ATTEMPTS` constant exists but no active lockout is wired); protection relies on strong Argon2id KDF parameters
- **Purpose**: Offline brute-force resistance is provided by the expensive KDF rather than an in-app counter

### Device Authentication

#### Device Verification
```python
if flags & FLAG_DEVICE:
    device_key = load_device_key()
    # Combine with password-derived key
    master_key = derive_master_key(password, salt, True, device_key)
```

#### Device Change Detection
- Automatic detection of hardware changes
- Graceful degradation on failure
- User notification of device mismatch
- Recovery through password-only mode (if enabled)

## Secure Deletion

Secure deletion overwrites the target data in-place before it is removed. Each pass writes cryptographically random bytes (via `os.urandom`), and data is `fsync`ed between passes.

### Deletion Methods

#### Standard
- **Passes**: 1
- **Speed**: Fast
- **Security**: Basic protection

#### DoD 5220.22-M (3x)
- **Passes**: 3
- **Speed**: Medium
- **Security**: Government-standard erasure

#### Gutmann (35x)
- **Passes**: 35
- **Speed**: Slow
- **Security**: High overwrite count

#### ANCORATE Vaporizer 1 (100x)
- **Passes**: 100
- **Speed**: Very slow (>1 minute)
- **Security**: Heavy multi-pass overwrite

#### ANCORATE Furnace Max (200x)
- **Passes**: 200
- **Speed**: Very slow (>5 minutes)
- **Security**: Intended for large files

#### ANCORATE Shatterer Ultra (300x)
- **Passes**: 300
- **Speed**: Extremely slow (>10 minutes)
- **Security**: Warning issued — should not be used on HDDs (risk of physical damage)

> The pass count is selected in `App._secure_overwrite` based on the configured `deletion_method`.
> `utilities/sos_delete.py` provides a separate *Emergency Data Wiper* that scans for and deletes whole
> vault files (used for the "Alle Tresore löschen" settings action).

## Threat Analysis

### Protected Against

#### 1. Brute Force Attacks
- **Protection**: Argon2id with high memory cost
- **Effectiveness**: High
- **Limit**: Maximum 3 attempts per session

#### 2. Dictionary Attacks
- **Protection**: Strong key derivation parameters
- **Effectiveness**: High
- **Limit**: Project pepper adds unpredictability

#### 3. Rainbow Table Attacks
- **Protection**: Per-container random salt
- **Effectiveness**: Complete
- **Limit**: Salt must remain secret

#### 4. Container Tampering
- **Protection**: HMAC and GCM authentication
- **Effectiveness**: High
- **Limit**: Requires key compromise to forge

#### 5. Data Recovery
- **Protection**: Secure deletion options
- **Effectiveness**: Variable (depends on method)
- **Limit**: Physical disk characteristics

#### 6. Memory Extraction
- **Protection**: Limited caching, no disk storage
- **Effectiveness**: Moderate
- **Limit**: Requires live memory access

#### 7. Device Cloning
- **Protection**: Multi-factor device fingerprint
- **Effectiveness**: Moderate-High
- **Limit**: Hardware spoofing possible

#### 8. Application Tampering
- **Protection**: Checksum verification
- **Effectiveness**: High
- **Limit**: User can override warnings

### Security Limitations

#### 1. Physical Access
- **Risk**: Physical access to running system
- **Mitigation**: Full disk encryption recommended
- **Impact**: Memory extraction possible

#### 2. Advanced Attackers
- **Risk**: State-sponsored actors
- **Mitigation**: Use EncryptPro with enhanced security
- **Impact**: Hardware fingerprint spoofing possible

#### 3. User Error
- **Risk**: Weak passwords, password reuse
- **Mitigation**: User education
- **Impact**: Password compromise

#### 4. Supply Chain
- **Risk**: Compromised dependencies
- **Mitigation**: Regular updates, dependency verification
- **Impact**: Complete system compromise

## Security Best Practices

### For Users
1. Use strong, unique passwords
2. Enable device binding for sensitive vaults
3. Use secure deletion for sensitive files
4. Keep application updated
5. Verify checksum warnings
6. Use on trusted systems only
7. Enable full disk encryption
8. Backup vaults securely

### For Developers
1. Never disable security features
2. Maintain cryptographic parameter strength
3. Test all security changes thoroughly
4. Follow secure coding practices
5. Document security-critical code
6. Implement defense in depth
7. Test for common vulnerabilities
8. Keep dependencies updated

### For Administrators
1. Monitor checksum verification logs
2. Enforce password policies where possible
3. Regular security audits
4. Incident response planning
5. User security training
6. Secure backup procedures
7. Access control policies
8. Update management

## Security Compliance

### Design Principles
- **Defense in Depth**: Multiple security layers
- **Least Privilege**: Minimal required access
- **Fail Secure**: Secure by default, fail to secure state
- **Secure by Design**: Security built in, not added on
- **Transparency**: Open security architecture (implementation proprietary)

### Standards Alignment
- **NIST**: Cryptographic standards compliance
- **FIPS**: Approved algorithms (AES, SHA-256)
- **DoD**: Secure deletion standards
- **Industry**: Best practices for encryption software

## Incident Response

### Security Incident Categories
1. **Compromised Password**: Change password, rekey vault
2. **Device Theft**: Device binding prevents access
3. **Application Tampering**: Verify checksums, reinstall
4. **Container Corruption**: Use header repair utilities
5. **Memory Compromise**: System reboot, key rotation

### Recovery Procedures
1. **Password Recovery**: Not available (security by design)
2. **Device Recovery**: Re-register on new device
3. **Data Recovery**: From secure backups
4. **System Recovery**: Clean reinstall from trusted source

## Future Security Enhancements

### Planned Features
- Multi-factor authentication integration
- Hardware security module (HSM) support
- Biometric authentication integration
- Secure enclave integration
- Advanced key management
- Zero-knowledge encryption options

### Research Areas
- Post-quantum cryptography
- Homomorphic encryption
- Secure multi-party computation
- Advanced device fingerprinting
- Behavioral biometrics

## Security Contact

For security concerns or vulnerability reports, contact the ANCORATE security team through official channels.

**Important**: This security documentation is for authorized developers and security professionals only. Unauthorized distribution or modification is prohibited.

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
