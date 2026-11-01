# Security Policy

## Supported versions

EncryptHome 27 Beta 1 is the current development line. Security fixes are applied to the latest code on the default branch.

## Reporting a vulnerability

If you discover a security vulnerability, **do not** open a public issue and **do not** disclose it publicly.

Instead, report it privately to the maintainers through the project's official security contact. Include:

- A description of the vulnerability
- Steps to reproduce
- Impact analysis
- A suggested mitigation (if available)

The maintainers will acknowledge receipt, investigate, and coordinate a disclosure timeline.

## Security model

EncryptHome is a local desktop application. Its security model is documented in detail in [docs/SECURITY.md](docs/SECURITY.md), including:

- Argon2id key derivation
- AES-256-GCM authenticated encryption
- Per-file HKDF-SHA256 subkeys
- HMAC-SHA256 integrity checks
- Optional device binding
- Encrypted metadata
- Secure deletion options

## Security expectations for contributors

Contributors must not:

- Disable or weaken encryption
- Reduce cryptographic strength
- Store secrets in plaintext
- Log sensitive information
- Bypass authentication or security checks
- Introduce insecure defaults

See [AGENTS.md](AGENTS.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the full rules.