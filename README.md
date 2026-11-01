# ANCORATE EncryptHome

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/ANCORATE/EncryptHome/actions/workflows/ci.yml/badge.svg)](https://github.com/ANCORATE/EncryptHome/actions/workflows/ci.yml)

**EncryptHome 27 Beta 1 — Capsule**  
A local desktop app for encrypted `.salt` vaults: file management, device binding, preview, secure deletion, and integrity checks.

## Quick start

```bash
pip install PyQt6 cryptography argon2-cffi requests
python main.py
```

## Highlights

- AES-256-GCM + HMAC-SHA256 integrity
- Argon2id key derivation, optional device binding
- `.salt` container format (`0x09`)
- Drag-and-drop import, folders, search, batch export
- In-memory LRU preview cache (200 MiB)
- 4 themes, configurable shortcuts, auto-lock
- Secure deletion (Standard to 300-pass)
- Emergency vault scanner/wiper

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security](docs/SECURITY.md)
- [API Reference](docs/API_REFERENCE.md)
- [Development](docs/DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)

Full docs are also maintained in the GitHub Wiki.

## Development

```bash
pytest
```

## License

MIT © 2026 Samuel J. Tirwa & Gabriel Leiria-Roussin. See [LICENSE](LICENSE).