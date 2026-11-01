# Contributing to EncryptHome

Thank you for your interest in contributing to EncryptHome.

## Where to start

- Read [AGENTS.md](AGENTS.md) for mandatory development guidelines.
- Read [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full contribution process.
- Read [docs/SECURITY.md](docs/SECURITY.md) before touching cryptographic or security-related code.
- Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the module structure.

## Ground rules

- Security takes priority over convenience, performance, and UX.
- Never weaken encryption, key derivation, or authentication.
- Never store secrets in plaintext or log sensitive information.
- Preserve backward compatibility with existing `.salt` vaults unless a migration is explicitly planned.
- Prefer the smallest correct change and avoid large refactors without justification.

## Development setup

```bash
pip install PyQt6 cryptography argon2-cffi requests
python main.py
```

## Tests

```bash
pytest
```

All changes should keep the existing tests passing and add tests for new behavior where practical.

## Security vulnerabilities

Do not open public issues for security vulnerabilities. Report them privately to the maintainers. See [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the [MIT License](LICENSE).