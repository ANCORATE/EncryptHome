# EncryptHome Contributing Guidelines

Guidelines for contributing to the EncryptHome project.

## Code of Conduct

### Professional Standards
- Be respectful and constructive in all interactions
- Focus on what is best for the project
- Show empathy towards other contributors
- Accept feedback gracefully
- Assume good intentions

### Security Ethics
- Never compromise security for convenience
- Report security vulnerabilities responsibly
- Follow responsible disclosure practices
- Respect user privacy and data protection
- Maintain integrity of cryptographic implementations

## Contribution Process

### 1. Understanding the Project

Before contributing, ensure you understand:

- **Security Model**: Read SECURITY.md thoroughly
- **Architecture**: Review ARCHITECTURE.md
- **API**: Study API_REFERENCE.md
- **Guidelines**: Read AGENTS.md completely
- **Priorities**: Security > Reliability > Compatibility > Maintainability > UX

### 2. Types of Contributions

#### Bug Fixes
- Identify root cause, not symptoms
- Write test demonstrating the bug
- Fix with minimal changes
- Verify fix doesn't break existing functionality
- Update documentation if needed

#### New Features
- Propose feature for discussion first
- Ensure alignment with security priorities
- Consider backward compatibility
- Implement incrementally if complex
- Add comprehensive tests
- Update documentation

#### Documentation
- Keep technical accuracy
- Follow existing documentation style
- Include code examples where helpful
- Update related sections consistently
- Proofread for clarity

#### Security Improvements
- Justify security benefits
- Analyze performance impact
- Consider user experience implications
- Document threat model changes
- Update security documentation

### 3. Workflow

#### Fork and Branch
```bash
# Fork the repository
# Create feature branch
git checkout -b feature/your-feature-name
```

#### Development
- Follow coding standards
- Write tests for new code
- Run existing tests
- Update documentation
- Commit with clear messages

#### Commit Guidelines

**Commit Message Format:**
```
type(scope): brief description

Detailed description (optional)
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test changes
- `security`: Security-related changes
- `perf`: Performance improvements

**Examples:**
```
fix(encryption): correct HMAC verification in decrypt_blob_range
feat(ui): add keyboard shortcut for settings dialog
docs(security): update device binding documentation
security(backend): strengthen Argon2 parameters
```

#### Pull Request Process

1. **Title**: Clear and descriptive
2. **Description**: Explain changes and rationale
3. **Testing**: Describe tests performed
4. **Documentation**: List documentation updates
5. **Security**: Highlight security implications
6. **Backward Compatibility**: Note any breaking changes

**Pull Request Template:**
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing performed

## Security Considerations
- Security impact analysis
- Threat model changes
- Parameter changes

## Backward Compatibility
- Compatible with existing vaults?
- User data migration needed?
- Configuration changes required?

## Documentation
- [ ] API documentation updated
- [ ] Security documentation updated
- [ ] Architecture documentation updated
- [ ] AGENTS.md updated if needed
```

## Coding Standards

### Python Style

Follow PEP 8 with project-specific modifications:

#### Naming Conventions
- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private**: `_leading_underscore`
- **Really Private**: `__double_underscore`

#### Formatting
```python
# Good
def encrypt_file(source_path: str, dest_path: str, master_key: bytes) -> None:
    """Encrypts a file with AES-GCM."""
    pass

# Avoid
def encryptFile(src,dest,key):
    pass
```

#### Comments
```python
# Security-critical: Document why
def derive_master_key(password: str, salt: bytes, device_bound: bool, device_key: bytes) -> bytes:
    """
    Derives master key using Argon2id with optional device binding.
    
    Security: Argon2id parameters chosen for resistance to GPU/ASIC attacks.
    Device binding adds hardware-based security factor.
    """
    pass
```

### Security Coding Standards

#### NEVER
- Disable encryption
- Reduce cryptographic strength
- Store secrets in plaintext
- Log sensitive information
- Bypass authentication
- Introduce insecure defaults
- Circumvent security checks

#### ALWAYS
- Validate user input
- Use constant-time comparison for secrets
- Clean up temporary files
- Zeroize sensitive data when possible
- Follow cryptographic best practices
- Test error conditions
- Document security assumptions

#### Cryptographic Code
```python
# Good: Use established libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Avoid: Custom crypto implementations
def custom_aes_encrypt(data, key):
    # Don't implement crypto yourself
    pass
```

#### Error Handling
```python
# Good: Specific error handling
try:
    decrypt_blob_range(fh, out_path, blob_len, master_key, filename)
except ValueError as e:
    logger.error(f"Decryption failed: {e}")
    raise SecurityError("Invalid container format")
except IOError as e:
    logger.error(f"I/O error: {e}")
    raise

# Avoid: Bare except
try:
    decrypt_blob_range(...)
except:
    pass
```

## Testing Requirements

### Test Coverage

- **New Features**: 100% coverage of new code
- **Bug Fixes**: Test that reproduces the bug
- **Security Changes**: Comprehensive security testing
- **Refactoring**: Maintain existing coverage

### Test Types

#### Unit Tests
```python
def test_derive_subkey():
    """Test key derivation produces consistent, unique keys."""
    master_key = b'\x00' * 32
    file_nonce = b'\x00' * 16
    filename = "test.txt"
    
    subkey = derive_subkey(master_key, file_nonce, filename)
    
    assert len(subkey) == 32
    assert subkey != master_key  # Should be different
```

#### Integration Tests
```python
def test_full_encryption_decryption():
    """Test complete encryption-decryption workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test file
        test_file = os.path.join(tmpdir, "test.txt")
        with open(test_file, "w") as f:
            f.write("Test content")
        
        # Encrypt
        container = os.path.join(tmpdir, "test.salt")
        # ... encryption code ...
        
        # Decrypt
        output = os.path.join(tmpdir, "output.txt")
        # ... decryption code ...
        
        # Verify
        with open(output, "r") as f:
            assert f.read() == "Test content"
```

#### Security Tests
```python
def test_device_binding():
    """Test device binding prevents unauthorized access."""
    # Test with correct device
    assert login_with_device(password, correct_device_key)
    
    # Test with wrong device
    assert not login_with_device(password, wrong_device_key)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=. --cov-report=html

# Run specific test file
pytest tests/test_encrypt.py

# Run with verbose output
pytest -v
```

## Documentation Requirements

### Code Documentation

#### Docstrings
```python
def complex_function(param1: str, param2: bytes) -> dict:
    """
    Brief description of function.
    
    Detailed description if needed.
    
    Args:
        param1: Description of param1
        param2: Description of param2
    
    Returns:
        Description of return value
    
    Raises:
        ValueError: When param1 is invalid
        SecurityError: When security check fails
    
    Security:
        Security considerations here.
    """
    pass
```

#### Inline Comments
```python
# Generate random salt for key derivation
# Security: 16 bytes provides 128-bit security
salt = secrets.token_bytes(SALT_LEN)

# Derive master key with strong parameters
# Security: Argon2id parameters chosen for resistance to GPU attacks
master_key = argon2id_hash(password, salt, t=3, m=128MB, p=4)
```

### API Documentation

- Update API_REFERENCE.md for public API changes
- Document all new functions/classes
- Update parameter descriptions
- Document return values and exceptions
- Note security implications

### Architecture Documentation

- Update ARCHITECTURE.md for structural changes
- Document new components
- Update data flow diagrams
- Note performance implications

### Security Documentation

- Update SECURITY.md for security changes
- Document new security features
- Update threat analysis
- Note security assumptions
- Document parameter changes

## Review Process

### Self-Review Checklist

Before submitting, verify:

- [ ] Code follows AGENTS.md guidelines
- [ ] Security implications considered
- [ ] Backward compatibility maintained
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] No hardcoded secrets
- [ ] Error handling comprehensive
- [ ] Performance impact acceptable
- [ ] User experience considered
- [ ] Follows project coding standards

### Security Review

Security-focused contributions require:

1. **Threat Analysis**: Identify new attack vectors
2. **Impact Assessment**: Evaluate security impact
3. **Mitigation**: Document mitigation strategies
4. **Testing**: Security-specific test cases
5. **Documentation**: Update security documentation

### Code Review Expectations

- Be responsive to feedback
- Address security concerns promptly
- Justify security trade-offs
- Update documentation as requested
- Re-test after changes
- Maintain clean commit history

## Security Vulnerability Reporting

### Responsible Disclosure

If you discover a security vulnerability:

1. **Do NOT** create public issue
2. **Do NOT** disclose publicly
3. **DO** report privately to maintainers
4. **DO** include detailed analysis
5. **DO** suggest mitigation

### Reporting Process

1. Prepare detailed vulnerability report
2. Send through official security channel
3. Await acknowledgment from maintainers
4. Coordinate disclosure timeline
5. Receive credit for discovery

### Report Contents

- Vulnerability description
- Steps to reproduce
- Impact analysis
- Suggested mitigation
- Proof of concept (if safe)

## Release Contribution

### Release Criteria

Contributions for releases must:

- Pass all tests
- Have documentation updated
- Security review completed
- Backward compatibility verified
- Performance tested
- Multi-platform tested

### Release Process

1. **Feature Freeze**: No new features after freeze
2. **Testing Focus**: Comprehensive testing period
3. **Security Audit**: Final security review
4. **Documentation**: Final documentation update
5. **Release Candidate**: Test build
6. **Final Release**: Public distribution

## Communication

### Channels

- **Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Discussions**: Design discussions
- **Security**: Private vulnerability reports

### Expectations

- **Response Time**: Maintainers will respond within reasonable time
- **Constructive Feedback**: All feedback should be constructive
- **Patience**: Review process takes time
- **Professionalism**: Maintain professional conduct

### Language

- **Documentation**: English preferred
- **Code Comments**: English preferred
- **Variable Names**: English required
- **User Messages**: German (existing codebase)

## Recognition

### Contributor Credit

- Contributors credited in release notes
- Significant contributions acknowledged
- Security researchers recognized
- Documentation contributors noted

### Recognition Process

1. Maintainer tracks contributions
2. Credit included in releases
3. Annual contributor recognition
4. Security hall of fame

## License and Rights

### Code Ownership

- All code remains property of ANCORATE
- Contributors retain authorship credit
- No code relicensing without explicit permission
- Proprietary software restrictions apply

### Contribution Rights

By contributing, you agree to:

- Your contribution becomes property of ANCORATE
- Your contribution follows the same license
- Your contribution may be used commercially
- Your contribution is not to be distributed elsewhere

### Copyright

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.

Unauthorized distribution or modification is prohibited.

## Getting Started

### First Contribution

1. Read AGENTS.md completely
2. Read this contributing guide
3. Study existing code patterns
4. Start with small, well-defined changes
5. Ask questions if unsure
6. Seek feedback early

### Good First Contributions

- Documentation improvements
- Bug fixes with clear tests
- Small feature additions
- Performance optimizations
- Test coverage improvements

### Questions and Support

- Read existing documentation first
- Search for similar issues/PRs
- Ask specific, technical questions
- Provide context for your question
- Be patient for responses

## Project Governance

### Maintainer Responsibilities

- Security code review
- Release management
- Community moderation
- Documentation oversight
- Architecture decisions

### Decision Process

- Security decisions require maintainer approval
- Major changes require discussion
- Breaking changes require consensus
- Security changes take priority
- User safety is paramount

### Conflict Resolution

1. Technical discussion first
2. Seek additional opinions if needed
3. Maintainer makes final decision
4. Decision documented
5. Move forward constructively

## Additional Resources

### Internal Documentation
- AGENTS.md - Mandatory development guidelines
- ARCHITECTURE.md - System architecture
- SECURITY.md - Security model
- API_REFERENCE.md - Complete API documentation
- DEVELOPMENT.md - Development setup

### External Resources
- PyQt6 Documentation
- Python Cryptography Documentation
- Argon2 Documentation
- Security Best Practices

Thank you for your interest in contributing to EncryptHome. Your contributions help make the software more secure, reliable, and user-friendly.

Remember: Security is not an afterthought—it's the foundation of everything we do.

© 2026 by Samuel J. Tirwa & Gabriel Leiria-Roussin. All rights reserved.
