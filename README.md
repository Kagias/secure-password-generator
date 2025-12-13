# Secure Password & Passphrase Generator

![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)

Production-quality, cybersecurity-focused Python toolkit for generating secure passwords and passphrases with comprehensive security analysis, password auditing, and encrypted vault functionality.

## 🔒 Security First

This project is built with security as the primary concern:

- **CSPRNG Only**: Uses Python's `secrets` module (cryptographically secure) - NEVER `random`
- **Memory-Hard KDFs**: Argon2id, bcrypt, scrypt for password hashing
- **Authenticated Encryption**: Fernet (AES-128-CBC + HMAC-SHA256) for vault
- **Constant-Time Operations**: Prevents timing attacks in verification
- **No Sensitive Data Logging**: Built-in secure logging system
- **Input Validation**: All user inputs are validated

## 📋 Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Usage](#cli-usage)
- [API Usage](#api-usage)
- [Cryptographic Details](#cryptographic-details)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)

## ✨ Features

### Core Functionality

1. **Secure Password Generation**
   - Cryptographically secure random generation
   - Customizable length and character classes
   - Exclude ambiguous characters option
   - Entropy calculation

2. **Diceware-Style Passphrases**
   - Uses EFF large wordlist (7776 words)
   - Configurable word count and separators
   - Optional capitalization and numbers
   - High entropy for memorability

3. **Password Strength Auditing**
   - Entropy evaluation
   - Character class diversity analysis
   - Pattern detection (sequences, repeats, keyboard patterns)
   - Dictionary word detection
   - Security score (0-100) and recommendations

4. **Secure Password Hashing**
   - Argon2id (PHC winner - recommended)
   - bcrypt (industry standard)
   - scrypt (memory-hard alternative)
   - Verification with constant-time comparison

5. **Encrypted Password Vault**
   - Master password protected
   - Fernet authenticated encryption
   - PBKDF2-HMAC-SHA256 key derivation
   - Export and import capabilities

6. **Entropy Analysis**
   - Bit-level entropy calculation
   - Strength classification
   - Crack time estimation

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Interface                        │
│                        (Click-based)                         │
└────────────────┬────────────────────────────────────────────┘
                 │
    ┌────────────┼────────────┐
    │            │            │
    ▼            ▼            ▼
┌─────────┐  ┌─────────┐  ┌──────┐
│Password │  │Passphrase│  │Audit │
│Generator│  │Generator │  │System│
└────┬────┘  └────┬─────┘  └──┬───┘
     │            │            │
     └────────┬───┴────────────┘
              │
              ▼
      ┌───────────────┐
      │    Entropy    │
      │  Calculator   │
      └───────────────┘
              │
    ┌─────────┼─────────┐
    │         │         │
    ▼         ▼         ▼
┌────────┐ ┌──────┐ ┌──────────┐
│Argon2id│ │bcrypt│ │Vault     │
│Hasher  │ │Hasher│ │(Fernet)  │
└────────┘ └──────┘ └──────────┘
              │
              ▼
      ┌───────────────┐
      │ Secure Logger │
      └───────────────┘
```

## 📦 Installation

### From Source

```bash
# Clone repository
git clone https://github.com/Kagias/secure-password-generator.git
cd secure-password-generator

# Install with pip (editable mode)
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

### Dependencies

Core dependencies:
- `click>=8.1.0` - CLI framework
- `cryptography>=41.0.0` - Fernet encryption
- `argon2-cffi>=23.1.0` - Argon2 hashing
- `bcrypt>=4.0.0` - bcrypt hashing

## 🚀 Quick Start

### Command Line

```bash
# Generate a secure password
passwordgen generate

# Generate a passphrase
passwordgen passphrase

# Audit password strength
passwordgen audit "MyP@ssw0rd"

# Create encrypted vault
passwordgen vault init myvault.vault
```

### Python API

```python
from passwordgen import PasswordGenerator, PassphraseGenerator

# Generate password
gen = PasswordGenerator(length=16, symbols=True)
password = gen.generate()
print(f"Password: {password}")
print(f"Entropy: {gen.entropy_bits:.1f} bits")

# Generate passphrase
passgen = PassphraseGenerator(word_count=6)
passphrase = passgen.generate()
print(f"Passphrase: {passphrase}")
print(f"Entropy: {passgen.entropy_bits:.1f} bits")
```

## 💻 CLI Usage

### Password Generation

```bash
# Basic password (default: 16 characters)
passwordgen generate

# Custom length
passwordgen generate --length 24

# Without symbols
passwordgen generate --no-symbols

# Exclude ambiguous characters (0, O, 1, l, I)
passwordgen generate --exclude-ambiguous

# Generate multiple passwords
passwordgen generate --count 5

# Show entropy information
passwordgen generate --show-entropy
```

### Passphrase Generation

```bash
# Basic passphrase (default: 6 words)
passwordgen passphrase

# Custom word count
passwordgen passphrase --words 8

# Custom separator
passwordgen passphrase --separator "_"

# Capitalize words
passwordgen passphrase --capitalize

# Include random number
passwordgen passphrase --include-number

# Show entropy
passwordgen passphrase --show-entropy
```

### Password Auditing

```bash
# Audit a password
passwordgen audit "MyPassword123!"

# Output includes:
# - Strength rating (Very Weak to Very Strong)
# - Entropy in bits
# - Security score (0-100)
# - Character class analysis
# - Detected issues
# - Recommendations
```

### Password Hashing

```bash
# Hash with Argon2id (recommended)
passwordgen hash "mypassword"

# Hash with bcrypt
passwordgen hash "mypassword" --algorithm bcrypt

# Hash with scrypt
passwordgen hash "mypassword" --algorithm scrypt

# Verify password
passwordgen verify "mypassword" "$argon2id$..."
```

### Encrypted Vault

```bash
# Initialize new vault
passwordgen vault init myvault.vault

# Add entry
passwordgen vault add myvault.vault gmail

# Add with generated password
passwordgen vault add myvault.vault github --generate

# List entries
passwordgen vault list myvault.vault

# Get entry
passwordgen vault get myvault.vault gmail

# Delete entry
passwordgen vault delete myvault.vault gmail
```

## 🔧 API Usage

### Password Generation

```python
from passwordgen import PasswordGenerator

# Create generator with custom settings
gen = PasswordGenerator(
    length=20,
    uppercase=True,
    lowercase=True,
    digits=True,
    symbols=True,
    exclude_ambiguous=True
)

# Generate passwords
password = gen.generate()
passwords = gen.generate_multiple(10)

# Access properties
print(f"Charset size: {len(gen.charset)}")
print(f"Entropy: {gen.entropy_bits:.2f} bits")
```

### Passphrase Generation

```python
from passwordgen import PassphraseGenerator

# Create generator
gen = PassphraseGenerator(
    word_count=6,
    separator="-",
    capitalize=True,
    include_number=True
)

# Generate passphrases
passphrase = gen.generate()
passphrases = gen.generate_multiple(5)

# Access properties
print(f"Wordlist size: {gen.wordlist_size}")
print(f"Entropy: {gen.entropy_bits:.2f} bits")
```

### Entropy Calculation

```python
from passwordgen.entropy import (
    calculate_password_entropy,
    calculate_passphrase_entropy,
    entropy_to_strength,
    estimate_crack_time
)

# Calculate entropy
entropy = calculate_password_entropy("MyP@ssw0rd!")
print(f"Entropy: {entropy:.2f} bits")

# Get strength rating
strength = entropy_to_strength(entropy)
print(f"Strength: {strength}")

# Estimate crack time
time_str = estimate_crack_time(entropy)
print(f"Estimated crack time: {time_str}")
```

### Password Auditing

```python
from passwordgen import PasswordAuditor

auditor = PasswordAuditor()
result = auditor.audit("MyP@ssw0rd!")

print(f"Strength: {result.strength}")
print(f"Score: {result.score}/100")
print(f"Entropy: {result.entropy_bits:.2f} bits")

for issue in result.issues:
    print(f"Issue: {issue}")

for rec in result.recommendations:
    print(f"Recommendation: {rec}")
```

### Secure Hashing

```python
from passwordgen import SecureHasher

hasher = SecureHasher()

# Hash passwords
argon2_hash = hasher.hash_argon2("mypassword")
bcrypt_hash = hasher.hash_bcrypt("mypassword")
scrypt_hash = hasher.hash_scrypt("mypassword")

# Verify passwords
is_valid = hasher.verify_argon2("mypassword", argon2_hash)
print(f"Valid: {is_valid}")
```

### Encrypted Vault

```python
from passwordgen import SecureVault
from pathlib import Path

# Create vault
vault = SecureVault(Path("myvault.vault"), "master_password")

# Add entries
vault.add_entry("gmail", "mypassword123", 
                metadata={"email": "user@gmail.com"})

# Get entry
entry = vault.get_entry("gmail")
print(f"Password: {entry['password']}")

# List entries
entries = vault.list_entries()

# Delete entry
vault.delete_entry("gmail")

# Change master password
vault.change_master_password("new_master_password")

# Export vault
vault.export_encrypted(Path("backup.vault"))
```

## 🔐 Cryptographic Details

### Randomness Source

All password and passphrase generation uses Python's `secrets` module, which provides:
- Access to the OS's cryptographically secure random number generator
- `secrets.choice()` for selection from character sets/wordlists
- `secrets.randbelow()` for bounded integer generation
- Suitable for security-sensitive applications (unlike `random` module)

### Entropy Formulas

**Password Entropy:**
```
entropy = length × log₂(charset_size)

Example: 16-char password with 94 characters
entropy = 16 × log₂(94) ≈ 105.1 bits
```

**Passphrase Entropy:**
```
entropy = word_count × log₂(wordlist_size)

Example: 6 words from EFF list (7776 words)
entropy = 6 × log₂(7776) ≈ 77.5 bits
```

### Hashing Algorithms

#### Argon2id (Recommended)

- **Winner of Password Hashing Competition (PHC)**
- **Type**: Memory-hard key derivation function
- **Parameters**:
  - Time cost: 3 iterations (default)
  - Memory cost: 64 MiB (default)
  - Parallelism: 4 threads (default)
- **Benefits**: Best resistance to GPU/ASIC attacks

#### bcrypt

- **Industry Standard** since 1999
- **Type**: Blowfish-based key derivation
- **Parameters**: Cost factor 12 (default) = 2¹² = 4096 iterations
- **Benefits**: Battle-tested, widely supported
- **Limitation**: 72-byte password maximum

#### scrypt

- **Type**: Memory-hard key derivation function
- **Parameters**:
  - N: 2¹⁴ = 16384 (CPU/memory cost)
  - r: 8 (block size)
  - p: 1 (parallelization)
- **Memory usage**: 128 × N × r = 16 MiB
- **Benefits**: High memory requirement deters hardware attacks

### Vault Encryption (Fernet)

**Fernet provides:**
- AES-128 encryption in CBC mode
- HMAC-SHA256 for authentication
- Timestamp for expiration support
- Safe against padding oracle attacks

**Key Derivation:**
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 480,000 (OWASP 2023 recommendation)
- Salt: 16 bytes (randomly generated per vault)
- Output: 32 bytes (256 bits)

## 🛡️ Security Considerations

### Threat Model

**Protected Against:**
- Brute-force attacks (high entropy)
- Dictionary attacks (pattern detection, Diceware)
- Rainbow tables (unique salts per hash)
- Timing attacks (constant-time comparisons)
- Weak randomness (CSPRNG only)
- GPU/ASIC attacks (memory-hard KDFs)

**NOT Protected Against:**
- Keyloggers or screen capture
- Memory dumps of running processes
- Physical access to unlocked systems
- Compromised operating systems
- Side-channel attacks on hardware

### Best Practices

1. **Password Storage**: Always hash passwords before storage
2. **Master Passwords**: Use passphrases (easier to remember, high entropy)
3. **Vault Files**: Keep encrypted vaults on encrypted storage
4. **Regular Updates**: Rotate passwords periodically
5. **Unique Passwords**: Never reuse passwords across services

### Attack Model

#### Online Attacks (Rate-Limited)

```
Attempts per second: 10-100
Minimum entropy: 28 bits (hours to crack)
Recommended: 40+ bits (years to crack)
```

#### Offline Attacks (Hash Cracking)

```
GPU cluster: ~1e12 guesses/second
Minimum entropy: 60 bits (decades to crack)
Recommended: 80+ bits (centuries to crack)
```

#### Passphrase vs Password

For same entropy:
- **Password**: Harder to remember, shorter
- **Passphrase**: Easier to remember, longer

Example:
- `Tr!0k#mP2$sQ` (random) ≈ 77 bits
- `correct-horse-battery-staple-lamp-river` (6 words) ≈ 77 bits

## 🧪 Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=passwordgen --cov-report=html

# Run specific test file
pytest tests/test_password.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Type checking
mypy src/

# Security scanning
bandit -r src/
```

### Project Structure

```
secure-password-generator/
├── src/passwordgen/          # Main package
│   ├── __init__.py           # Package exports
│   ├── password.py           # Password generator
│   ├── passphrase.py         # Passphrase generator
│   ├── entropy.py            # Entropy calculations
│   ├── audit.py              # Password auditor
│   ├── crypto.py             # Hashing & verification
│   ├── vault.py              # Encrypted vault
│   ├── logging_secure.py     # Secure logging
│   └── cli.py                # CLI interface
├── tests/                    # Test suite
├── wordlists/                # EFF wordlist
├── docs/                     # Documentation
├── pyproject.toml            # Package configuration
└── README.md                 # This file
```

## 📚 Documentation

- **API Reference**: See `docs/api_reference.md`
- **Security Guide**: See `docs/index.md`
- **Contributing**: See `CONTRIBUTING.md`

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure all tests pass
5. Run security scanning with Bandit
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **EFF** for the large wordlist used in passphrase generation
- **Password Hashing Competition** for Argon2
- **OWASP** for security guidelines and best practices
- **cryptography.io** for excellent Python cryptography library

## 📧 Contact

For security issues, please email: security@example.com

For general inquiries: kagias@example.com

---

**Remember**: A strong password is your first line of defense. Use this tool to generate secure, unique passwords for all your accounts!
