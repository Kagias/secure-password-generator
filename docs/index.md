# Secure Password Generator Documentation

## Overview

The Secure Password Generator is a production-quality Python toolkit designed with security as the primary concern. This documentation provides comprehensive information about the project's architecture, security model, and usage.

## Table of Contents

1. [Security Architecture](#security-architecture)
2. [Threat Model](#threat-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Best Practices](#best-practices)
5. [API Documentation](#api-documentation)

## Security Architecture

### Randomness Source

All cryptographic operations requiring randomness use Python's `secrets` module, which provides:

- Access to the operating system's cryptographically secure random number generator (`os.urandom()`)
- Suitable for managing data such as passwords, account authentication, security tokens, and related secrets
- NOT the `random` module, which is designed for modeling and simulation, not security

### Key Derivation Functions

Three memory-hard key derivation functions are provided:

1. **Argon2id** (Recommended)
   - Winner of the Password Hashing Competition
   - Hybrid mode combining resistance to both side-channel and GPU attacks
   - Configurable time cost, memory cost, and parallelism

2. **bcrypt**
   - Industry standard since 1999
   - Based on the Blowfish cipher
   - Adaptive: can be made slower as computers get faster

3. **scrypt**
   - Memory-hard function requiring large amounts of RAM
   - Makes hardware brute-force attacks expensive
   - Configurable CPU and memory costs

### Vault Encryption

The encrypted vault uses Fernet, which provides:

- **Symmetric encryption**: AES-128 in CBC mode
- **Authentication**: HMAC-SHA256 to prevent tampering
- **Timestamping**: Built-in timestamp for expiration support
- **Security**: Protected against padding oracle attacks

Master password is derived using PBKDF2-HMAC-SHA256 with:
- 480,000 iterations (OWASP 2023 recommendation)
- Random 16-byte salt per vault
- 256-bit output key

## Threat Model

### What We Protect Against

1. **Brute-Force Attacks**
   - High entropy passwords (80+ bits recommended)
   - Memory-hard hashing slows down attacks

2. **Dictionary Attacks**
   - Diceware-style passphrases from large wordlist (7776 words)
   - Pattern detection in password auditor

3. **Rainbow Table Attacks**
   - Unique random salt for each password hash
   - Salt stored with hash

4. **Timing Attacks**
   - Constant-time comparison for verification
   - Prevents information leakage through timing

5. **Weak Randomness**
   - CSPRNG only (`secrets` module)
   - No use of `random` module for security purposes

6. **GPU/ASIC Attacks**
   - Memory-hard functions (Argon2, scrypt)
   - Computationally expensive operations

### What We Don't Protect Against

1. **Malware/Keyloggers**
   - Cannot prevent capture of passwords during entry
   - Recommendation: Use trusted, malware-free systems

2. **Physical Access**
   - Cannot prevent access to unlocked systems
   - Recommendation: Lock workstations when away

3. **Memory Dumps**
   - Passwords may exist in memory during use
   - Recommendation: Minimize password retention time

4. **Social Engineering**
   - Cannot prevent user disclosure of passwords
   - Recommendation: Security awareness training

5. **Compromised OS**
   - Security depends on OS integrity
   - Recommendation: Keep systems updated

## Cryptographic Primitives

### Hash Functions

- **SHA-256**: Used in PBKDF2 for key derivation
- **SHA-512**: Used internally by some algorithms
- **HMAC-SHA256**: Used in Fernet for authentication

### Symmetric Encryption

- **AES-128**: Used in Fernet encryption
- **Mode**: CBC (Cipher Block Chaining)
- **Authentication**: HMAC-SHA256

### Password Hashing

- **Argon2id**: PHC winner, hybrid security
- **bcrypt**: Blowfish-based, industry standard
- **scrypt**: Memory-hard, sequential computation

## Best Practices

### Password Generation

1. **Minimum Length**: 12 characters for passwords, 6 words for passphrases
2. **Character Diversity**: Use all available character classes
3. **Uniqueness**: Never reuse passwords across services
4. **Randomness**: Let the tool generate passwords, don't create patterns

### Password Storage

1. **Hash Before Storage**: Always use KDFs, never store plaintext
2. **Algorithm Choice**: Prefer Argon2id for new implementations
3. **Parameter Selection**: Balance security with performance
4. **Salt Handling**: Let the library handle salt generation

### Vault Usage

1. **Master Password**: Use a strong passphrase (7+ words)
2. **Backup**: Export encrypted vault regularly
3. **Physical Security**: Store vault files securely
4. **Access Control**: Limit who can access vault files

### Entropy Requirements

Different use cases require different entropy levels:

- **User Accounts** (Online attacks, rate-limited): 40-50 bits
- **Encryption Keys** (Offline attacks, fast): 80-128 bits
- **Long-Term Secrets** (Maximum security): 128+ bits

### Password Rotation

1. **Frequency**: Rotate critical passwords every 90 days
2. **Breach Response**: Immediately rotate if service compromised
3. **Planned Rotation**: Schedule regular updates for sensitive accounts

## Security Updates

### Dependency Management

All dependencies are pinned with minimum versions:
- `cryptography>=41.0.0` - Security updates
- `argon2-cffi>=23.1.0` - Latest stable Argon2
- `bcrypt>=4.0.0` - Latest bcrypt

### Vulnerability Scanning

The project uses:
- **Bandit**: Static security analysis
- **GitHub Advisory Database**: Dependency vulnerability checks
- **CodeQL**: Advanced semantic code analysis

### Reporting Security Issues

Please report security vulnerabilities to: security@example.com

Do not open public issues for security problems.

## Compliance

This project follows guidelines from:

- **OWASP** (Open Web Application Security Project)
- **NIST** (National Institute of Standards and Technology)
- **IETF** (Internet Engineering Task Force)

## References

1. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
2. [Password Hashing Competition](https://www.password-hashing.net/)
3. [EFF Dice-Generated Passphrases](https://www.eff.org/dice)
4. [NIST Special Publication 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html)
5. [Fernet Specification](https://github.com/fernet/spec/)

## License

This documentation is part of the Secure Password Generator project and is licensed under the MIT License.
