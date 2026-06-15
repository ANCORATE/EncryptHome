# EncryptHome Developer Documentation

Welcome to the EncryptHome developer documentation. This section contains comprehensive technical documentation for developers working on the ANCORATE EncryptHome project.

## About EncryptHome

EncryptHome is a security-focused desktop application designed to securely store, manage, and protect user data through strong encryption based on device-bound authentication and reliable software architecture.

**Version**: 26.2  
**Edition**: EncryptHome Citadel  
**Language**: Python 3 with PyQt6  
**License**: Proprietary - © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin

## Documentation Structure

### Core Documentation
- **[Architecture](ARCHITECTURE.md)** - System architecture, component design, and data flow
- **[Security](SECURITY.md)** - Security model, cryptographic implementation, and threat analysis
- **[API Reference](API_REFERENCE.md)** - Complete API documentation for all modules
- **[Development Guide](DEVELOPMENT.md)** - Development setup, build process, and testing
- **[Contributing](CONTRIBUTING.md)** - Contribution guidelines and coding standards

### Quick Links
- [Project Overview](#project-overview)
- [Getting Started](#getting-started)
- [Key Components](#key-components)
- [Security Architecture](#security-architecture)

## Project Overview

EncryptHome implements a vault-based encryption system with the following key features:

### Core Features
- **Device-Bound Encryption**: Optional hardware-based security using device fingerprinting
- **Strong Cryptography**: AES-256-GCM with Argon2id key derivation
- **Secure Vault Format**: Custom .salt container format with integrity verification
- **Cross-Platform**: Support for Windows, Linux, and macOS
- **User-Friendly GUI**: PyQt6-based interface with drag-and-drop support
- **File Preview**: In-memory encrypted file preview system
- **Secure Deletion**: Multiple secure file deletion methods

### Security Priorities
1. Security
2. Reliability
3. Compatibility
4. Maintainability
5. User Experience

## Getting Started

### Prerequisites
- Python 3.8 or higher
- PyQt6
- argon2-cffi
- cryptography
- requests

### Installation
```bash
# Install dependencies
pip install PyQt6 argon2-cffi cryptography requests

# Run the application
python main.py
```

See [Development Guide](DEVELOPMENT.md) for detailed setup instructions.

## Key Components

### Encryption Engine
- **base.py** - Cryptographic primitives and key derivation
- **encrypt.py** - File and metadata encryption operations
- **decrypt.py** - Decryption operations and blob handling
- **decrypt_preview.py** - In-memory preview functionality

### User Interface
- **main.py** - Main application with GUI orchestration
- **utilities/settings.py** - Settings management and configuration UI

### Utilities
- **utilities/header_utils.py** - Container header validation and repair
- **utilities/checksum_check.py** - File integrity verification
- **utilities/sos_delete.py** - Secure file deletion
- **utilities/updater.py** - Application update mechanism

## Security Architecture

### Encryption Stack
```
Password
    ↓
Argon2id (t=3, m=128MB, p=4)
    ↓
Master Key (32 bytes)
    ↓
HKDF-SHA256 (per-file)
    ↓
File Subkey (32 bytes)
    ↓
AES-256-GCM
    ↓
Encrypted File
```

### Device Binding
- MAC address (6 bytes)
- CPU ID (platform-specific)
- Disk serial (platform-specific)
- SHA-256 fingerprint
- Deterministic device key generation

### Container Format
```
[Header 28B][File Blob 1][File Blob 2]...[Meta Length 8B][Encrypted Meta]
```

See [Security Documentation](SECURITY.md) for complete security details.

## Development Workflow

### Code Standards
- Follow existing code style and conventions
- Maintain security-first approach
- Write clear, single-purpose functions
- Document security-critical code
- Test all meaningful changes

### Testing
- Verify encryption/decryption operations
- Test device binding functionality
- Validate container format compatibility
- Check memory management
- Test error handling

### Release Process
1. Update version numbers
2. Run full test suite
3. Verify checksums
4. Update documentation
5. Create distribution package

## Support

For technical questions or issues, refer to the project maintainers.

## License

This code is proprietary software. Unauthorized reproduction, reuse, modification, or distribution is strictly prohibited.

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
