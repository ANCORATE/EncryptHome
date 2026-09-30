# EncryptHome Development Guide

Complete guide for setting up and developing EncryptHome.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Development Environment Setup](#development-environment-setup)
- [Building from Source](#building-from-source)
- [Testing](#testing)
- [Debugging](#debugging)
- [Release Process](#release-process)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Software

#### Python
- **Version**: Python 3.10 or higher (uses PEP 604 union types, e.g. `str | None`)
- **Recommended**: Python 3.13+ (the app is distributed with a modified Python 3.13 PyInstaller build)
- **Download**: [python.org](https://python.org)

#### System Requirements
- **RAM**: 1 GB minimum, 8 GB recommended
- **Disk**: 100 MB free space for development
- **OS**: Windows 10+, Ubuntu 18.04+, macOS 10.15+

### Required Python Packages

```bash
# Core dependencies
PyQt6>=6.0.0
argon2-cffi>=21.0.0
cryptography>=3.4.0
requests>=2.25.0
```

### Optional Development Tools

```bash
# Code quality
black>=21.0.0
pylint>=2.8.0
mypy>=0.910

# Testing
pytest>=6.2.0
pytest-cov>=2.12.0

# Build tools
PyInstaller>=4.5
```

## Development Environment Setup

### 1. Clone Repository

```bash
# Clone the repository
git clone <repository-url>
cd EncryptHome
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate

# On Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
# Install core dependencies
pip install PyQt6 argon2-cffi cryptography requests

# Install development tools (optional)
pip install black pylint mypy pytest pytest-cov PyInstaller
```

### 4. Verify Installation

```bash
# Verify Python version
python --version

# Verify PyQt6 installation
python -c "from PyQt6.QtWidgets import QApplication; print('PyQt6 OK')"

# Verify cryptographic libraries
python -c "from cryptography.hazmat.primitives.ciphers import Cipher; print('Cryptography OK')"
python -c "import argon2; print('Argon2 OK')"
```

### 5. Run Application

```bash
# Run from source
python main.py
```

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
│   ├── sos_delete.py       # Emergency vault scanner/wiper
│   ├── updater.py          # Update mechanism
│   └── themes/             # Central Qt stylesheets (standard-dark.css / standard-white.css)
├── docs/                   # Documentation
├── AGENTS.md              # Development guidelines
└── README.md              # Project readme
```

## Building from Source

### Development Build

For development purposes, running directly from source is recommended:

```bash
python main.py
```

### Production Build

For creating distributable executables, use PyInstaller:

#### 1. Install PyInstaller

```bash
pip install pyinstaller
```

#### 2. Use the Project Spec File

The repository ships a ready-made spec file (`ANCORATE_EncryptHome_26.2_Build_0009.spec`). It bundles the
application together with `utilities/`, `docs/`, `TOS.txt` and `README.md`, and declares the
required hidden imports (PyQt6, cryptography, argon2, requests, sqlite3, fitz):

```python
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('utilities', 'utilities'), ('docs', 'docs'),
           ('TOS.txt', '.'), ('README.md', '.')],
    hiddenimports=['PyQt6', 'PyQt6.QtCore', 'PyQt6.QtWidgets', 'PyQt6.QtGui', 'cryptography',
                   'argon2', 'requests', 'sqlite3', 'fitz'],
    ...
)
exe = EXE(
    pyz,
    a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='ANCORATE_EncryptHome_26.2_Build_0009',
    console=False,
    icon=['utilities\\assets\\app\\icon.ico'],
)
```

#### 3. Build Executable

```bash
pyinstaller ANCORATE_EncryptHome_26.2_Build_0009.spec
```

#### 4. Platform-Specific Considerations

**Windows:**
- Icon: `.ico` format
- Console: Disable for GUI app
- UAC: May require admin for device fingerprinting

**Linux:**
- Icon: `.png` format
- Dependencies: PyQt6 system packages
- Desktop file: Create for menu integration

**macOS:**
- Icon: `.icns` format
- Code signing: Required for distribution
- Notarization: Required for macOS 10.15+

## Testing

### Test Structure

Create test files in a `tests/` directory:

```
tests/
├── test_base.py
├── test_encrypt.py
├── test_decrypt.py
├── test_integration.py
└── conftest.py
```

### Unit Tests

```python
# tests/test_base.py
import pytest
from base import derive_subkey

def test_derive_subkey():
    master_key = b'\x00' * 32
    file_nonce = b'\x00' * 16
    filename = "test.txt"
    
    subkey = derive_subkey(master_key, file_nonce, filename)
    
    assert len(subkey) == 32
    assert subkey != master_key  # Should be different
```

### Integration Tests

```python
# tests/test_integration.py
import pytest
import tempfile
import os
from main import App

def test_vault_creation():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_path = os.path.join(tmpdir, "test.salt")
        # Test vault creation logic
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_base.py

# Run with verbose output
pytest -v
```

## Debugging

### Debug Mode

Enable console output for debugging:

```python
# In main.py, modify if __name__ == "__main__":
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = App()
    window.show()
    sys.exit(app.exec())
```

Or run with console enabled in PyInstaller:

```bash
pyinstaller --onefile --console EncryptHome.spec
```

### Logging

Add debug logging:

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='debug.log'
)

logger = logging.getLogger(__name__)
logger.debug("Debug message")
```

### Common Debugging Scenarios

#### Encryption/Decryption Issues

```python
# Add debug prints in encrypt.py/decrypt.py
print(f"[DEBUG] Master key length: {len(master_key)}")
print(f"[DEBUG] File nonce: {file_nonce.hex()}")
print(f"[DEBUG] Ciphertext length: {len(ciphertext)}")
```

#### Device Binding Problems

```python
# Debug device fingerprinting
from main import device_fingerprint, get_mac_bytes, get_cpu_id, get_disk_serial

print(f"[DEBUG] MAC: {get_mac_bytes().hex()}")
print(f"[DEBUG] CPU: {get_cpu_id()}")
print(f"[DEBUG] Disk: {get_disk_serial()}")
print(f"[DEBUG] Fingerprint: {device_fingerprint().hex()}")
```

#### Header Issues

```python
# Debug header parsing
from utilities.header_utils import verify_header
from main import HEADER_FMT, MAGIC, HEADER_LEN

result = verify_header("container.salt", HEADER_FMT, MAGIC, FLAG_DEVICE, FLAG_KEYFILE, HEADER_LEN)
print(f"[DEBUG] Header: {result}")
```

### IDE Configuration

#### VS Code

Create `.vscode/launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Python: EncryptHome",
            "type": "python",
            "request": "launch",
            "program": "${workspaceFolder}/main.py",
            "console": "integratedTerminal",
            "env": {
                "PYTHONPATH": "${workspaceFolder}"
            }
        }
    ]
}
```

#### PyCharm

1. Run → Edit Configurations
2. Add new Python configuration
3. Script path: `main.py`
4. Working directory: `$ProjectFileDir$`

## Code Quality

### Code Formatting with Black

```bash
# Format all Python files
black .

# Check formatting without making changes
black --check .

# Format specific file
black main.py
```

### Linting with Pylint

```bash
# Lint all files
pylint **/*.py

# Lint specific file
pylint main.py

# Generate score report
pylint --output-format=text main.py
```

### Type Checking with MyPy

```bash
# Type check all files
mypy .

# Type check specific file
mypy main.py

# Ignore missing imports
mypy --ignore-missing-imports main.py
```

## Release Process

### Pre-Release Checklist

1. **Version Update**
   - Update version in `main.py`
   - Update version in `utilities/settings.py`
   - Update AGENTS.md if needed

2. **Testing**
   - Run full test suite
   - Test encryption/decryption
   - Test device binding
   - Test on all target platforms

3. **Documentation**
   - Update CHANGELOG.md
   - Update version in docs
   - Review API documentation

4. **Security**
   - Verify checksums
   - Review security parameters
   - Check for known vulnerabilities

5. **Build**
   - Create clean build
   - Test built executable
   - Verify package contents

### Release Steps

#### 1. Update Version Numbers

```python
# In main.py
version = "26.3"  # Update version
version_year = "26"

# In utilities/settings.py
VERSION_FULL = "26.3"
```

#### 2. Build Distribution

```bash
# Clean previous builds
rm -rf build dist

# Build executable
pyinstaller --onefile --windowed EncryptHome.spec

# Test executable
dist/EncryptHome
```

#### 3. Generate Checksums

```bash
# Generate SHA-256 checksum
sha256sum dist/EncryptHome > dist/EncryptHome.sha256

# Update checksums.json
python -c "
import hashlib
import json
with open('dist/EncryptHome', 'rb') as f:
    checksum = hashlib.sha256(f.read()).hexdigest()
data = {'EncryptHome': checksum}
with open('utilities/checksums.json', 'w') as f:
    json.dump(data, f, indent=4)
"
```

#### 4. Create Release Package

```bash
# Create release directory
mkdir -p release

# Copy executable
cp dist/EncryptHome release/

# Copy documentation
cp -r docs release/

# Create archive
cd release
zip -r EncryptHome-26.3.zip EncryptHome docs
cd ..
```

#### 5. Tag Release

```bash
git tag -a v26.3 -m "Release version 26.3"
git push origin v26.3
```

## Troubleshooting

### Common Issues

#### PyQt6 Import Errors

**Problem:** `ImportError: No module named 'PyQt6'`

**Solution:**
```bash
pip install PyQt6
# or
pip install --upgrade PyQt6
```

#### Argon2 Installation Issues

**Problem:** `argon2-cffi` installation fails

**Solution:**
```bash
# Install system dependencies first
# Ubuntu/Debian:
sudo apt-get install build-essential libffi-dev python3-dev

# Then install
pip install argon2-cffi
```

#### Device Fingerprinting Failures

**Problem:** Device fingerprint returns "unknown-cpu" or "unknown-disk"

**Solution:**
- Check system permissions
- Verify platform-specific commands work manually
- Check that subprocess can execute system commands
- Review hardware detection code in `main.py`

#### Permission Errors

**Problem:** Cannot access device fingerprinting information

**Solution:**
- Run as administrator/sudo for development
- Check file permissions on container files
- Verify config directory is writable

#### Memory Issues

**Problem:** Application runs out of memory with large files

**Solution:**
- Reduce preview cache size in `main.py`
- Process files individually instead of batch
- Increase system swap space
- Use 64-bit Python version

### Platform-Specific Issues

#### Windows

**Issue:** Window doesn't appear

**Solution:**
- Ensure PyQt6 platform plugins are installed
- Check for display scaling issues
- Run with `--console` flag to see errors

#### Linux

**Issue:** Missing system libraries

**Solution:**
```bash
# Install required system packages
sudo apt-get install python3-pyqt6 libxcb-xinerama0
```

#### macOS

**Issue:** Code signing errors

**Solution:**
- Install Xcode command line tools
- Sign application with valid certificate
- Disable Gatekeeper for development only

## Development Best Practices

### 1. Security First

- Never hardcode keys or passwords
- Always validate user input
- Use constant-time comparison for secrets
- Never log sensitive information
- Follow the principle of least privilege

### 2. Code Organization

- Keep functions small and focused
- Use descriptive variable names
- Add comments for complex logic
- Follow existing code style
- Maintain backward compatibility

### 3. Testing

- Write tests for new features
- Test error conditions
- Verify cryptographic operations
- Test on multiple platforms
- Use continuous integration if possible

### 4. Documentation

- Update API documentation
- Document security-critical code
- Maintain AGENTS.md guidelines
- Keep README current
- Document breaking changes

## Performance Optimization

### Profiling

```python
import cProfile
import pstats

# Profile specific function
pr = cProfile.Profile()
pr.enable()
# ... code to profile ...
pr.disable()

# Print statistics
stats = pstats.Stats(pr)
stats.sort_stats('cumulative')
stats.print_stats(10)
```

### Memory Profiling

```bash
pip install memory_profiler

# Run with memory profiler
python -m memory_profiler main.py
```

### Optimization Tips

1. **Chunk Size**: Adjust CHUNK size for I/O performance
2. **Thread Count**: Balance worker threads for CPU vs I/O
3. **Cache Size**: Tune preview cache for memory constraints
4. **Key Derivation**: Adjust Argon2 parameters for performance vs security

## Continuous Integration

### GitHub Actions Example

```yaml
name: CI

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.10'
    - name: Install dependencies
      run: |
        pip install pytest black pylint
        pip install PyQt6 argon2-cffi cryptography requests
    - name: Run tests
      run: pytest
    - name: Check formatting
      run: black --check .
    - name: Lint
      run: pylint **/*.py
```

## Getting Help

### Resources
- [PyQt6 Documentation](https://www.riverbankcomputing.com/static/Docs/PyQt6/)
- [Cryptography Documentation](https://cryptography.io/)
- [Argon2 Documentation](https://argon2-cffi.readthedocs.io/)

### Internal Resources
- AGENTS.md for development guidelines
- Architecture documentation
- Security documentation
- API reference

This development guide provides comprehensive information for setting up and working with the EncryptHome codebase. Follow the AGENTS.md guidelines for all development work.

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
