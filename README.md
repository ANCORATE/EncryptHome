# EncryptHome

<div align="center">

**Secure Device-Bound Encryption Vault**

Version 26.2 | EncryptHome Citadel Edition

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin

</div>

---

## Overview

EncryptHome is a security-focused desktop application designed to securely store, manage, and protect user data through strong encryption based on device-bound authentication and reliable software architecture.

### Key Features

-  **Device-Bound Encryption** - Optional hardware-based security using device fingerprinting
-  **Strong Cryptography** - AES-256-GCM with Argon2id key derivation
-  **Secure Vault Format** - Custom .salt container format with integrity verification
-  **Cross-Platform** - Support for Windows, Linux, and macOS
-  **User-Friendly GUI** - PyQt6-based interface with drag-and-drop support
-  **File Preview** - In-memory encrypted file preview system
-  **Secure Deletion** - Multiple secure file deletion methods

## Quick Start

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

### Basic Usage

1. **Create a Vault**: Press `Ctrl+N` to create a new encrypted vault
2. **Add Files**: Drag and drop files into the vault or use `Ctrl++`
3. **Export Files**: Select files and press `Ctrl+E` to decrypt and export
4. **Preview Files**: Double-click any file for in-memory preview
5. **Search**: Use the search bar to find files in your vault

## Security Architecture

EncryptHome implements a multi-layered security approach:

### Encryption Stack
```
Password → Argon2id → Master Key → HKDF-SHA256 → File Subkey → AES-256-GCM
```

### Security Features
- **Argon2id** key derivation with 128 MB memory cost
- **AES-256-GCM** authenticated encryption
- **Device fingerprinting** using MAC, CPU, and disk identifiers
- **HMAC integrity verification** for all data
- **Secure deletion** with multiple erasure methods
- **In-memory preview** without disk writes

## Documentation

Comprehensive documentation is available in the `docs/` directory:

- **[Developer Documentation](docs/README.md)** - Complete technical documentation
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and data flow
- **[Security](docs/SECURITY.md)** - Security model and implementation details
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation
- **[Development Guide](docs/DEVELOPMENT.md)** - Development setup and build process
- **[Contributing](docs/CONTRIBUTING.md)** - Contribution guidelines and coding standards

## Project Structure

```
EncryptHome/
├── main.py                 # Main application and GUI
├── base.py                 # Cryptographic foundation
├── encrypt.py              # Encryption operations
├── decrypt.py              # Decryption operations
├── decrypt_preview.py      # Preview system
├── utilities/
│   ├── settings.py         # Settings management
│   ├── header_utils.py     # Header utilities
│   ├── checksum_check.py   # Integrity verification
│   ├── sos_delete.py       # Secure deletion
│   └── updater.py          # Update mechanism
├── docs/                   # Documentation
│   ├── README.md
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   ├── API_REFERENCE.md
│   ├── DEVELOPMENT.md
│   └── CONTRIBUTING.md
├── AGENTS.md              # Development guidelines
└── README.md              # This file
```

## Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Create New Vault | `Ctrl+N` |
| Open Existing Vault | `Ctrl+O` |
| Add Files | `Ctrl++` |
| Export Selected | `Ctrl+E` |
| Export All | `Alt+E` |
| Delete Selected | `Del` |
| Delete Container | `Alt+Del` |
| Search Files | `Return` |
| Recent Containers | `Ctrl+R` |

## Configuration

Settings are stored in platform-specific locations:

- **Linux**: `~/.config/ANCORATE/settings.json`
- **Windows**: `%APPDATA%\ANCORATE\settings.json`
- **macOS**: `~/Library/Application Support/ANCORATE/settings.json`

### Key Settings

- **Theme**: Choose between light and dark themes
- **Keyboard Shortcuts**: Customize all shortcuts
- **Auto-Lock**: Configure inactivity timeout
- **Secure Deletion**: Choose deletion method (Standard/DoD/Gutmann)
- **Source Deletion**: Auto-delete original files after encryption

## Security Best Practices

1. **Use Strong Passwords** - Minimum 12 characters with mixed types
2. **Enable Device Binding** - For enhanced security on trusted devices
3. **Use Secure Deletion** - DoD or Gutmann method for sensitive files
4. **Regular Backups** - Keep secure backups of important vaults
5. **Keep Updated** - Install security updates promptly
6. **Verify Checksums** - Pay attention to integrity warnings
7. **Use Trusted Systems** - Only run on secure, trusted computers

## Container Format

EncryptHome uses a custom `.salt` container format:

```
[Header 28B][File Blob 1][File Blob 2]...[Meta Length 8B][Encrypted Meta]
```

### Header Structure
- **Magic**: 4 bytes (`ANC0`)
- **Version**: 1 byte (`0x09`)
- **Flags**: 1 byte (device binding, keyfile, pro vault)
- **Salt**: 16 bytes (random per container)
- **Reserved**: 6 bytes (future use)

## Development

### Setup Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install PyQt6 argon2-cffi cryptography requests

# Install development tools (optional)
pip install black pylint mypy pytest pytest-cov PyInstaller
```

### Running from Source

```bash
python main.py
```

### Building Executable

```bash
pip install pyinstaller
pyinstaller --onefile --windowed main.py
```

See [Development Guide](docs/DEVELOPMENT.md) for detailed build instructions.

## Requirements

### Minimum Requirements
- **Python**: 3.8+
- **RAM**: 4 GB
- **Disk**: 100 MB free space
- **OS**: Windows 10+, Ubuntu 18.04+, macOS 10.15+

### Recommended
- **Python**: 3.10+
- **RAM**: 8 GB
- **Disk**: 500 MB free space

## License

This is proprietary software. All rights reserved.

**Copyright © 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin.**

Unauthorized reproduction, reuse, modification, or distribution is strictly prohibited.

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and non-infringement.

In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

## Support

For technical support, questions, or security concerns, please refer to the project maintainers through official channels.

## Acknowledgments

EncryptHome uses the following open-source projects:

- **PyQt6** - Python GUI framework
- **argon2-cffi** - Argon2 password hashing
- **cryptography** - Cryptographic primitives
- **requests** - HTTP library

---

<div align="center">

**EncryptHome - Security Through Strong Encryption**

[Documentation](docs/README.md) | [Security](docs/SECURITY.md) | [Architecture](docs/ARCHITECTURE.md)

</div>
