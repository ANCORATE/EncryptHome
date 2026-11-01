# EncryptHome Developer Docs

Developer documentation for the ANCORATE EncryptHome desktop app.

## Quick facts

- **Entry point:** `main.py`
- **UI:** PyQt6
- **Language:** Python 3
- **Edition:** EncryptHome Capsule
- **Container:** `.salt`
- **License:** MIT

## Docs

- [Architecture](ARCHITECTURE.md)
- [Security](SECURITY.md)
- [API Reference](API_REFERENCE.md)
- [Development](DEVELOPMENT.md)
- [Contributing](CONTRIBUTING.md)

## Core modules

- `base.py`, `encrypt.py`, `decrypt.py`, `decrypt_preview.py`
- `app/` — core, passwords, workers, dialogs, main window
- `utilities/` — settings, themes, container ops, updater, etc.

## Run

```bash
python main.py
pytest
```

Documentation is also mirrored in the GitHub Wiki.