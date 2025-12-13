# API Reference

Complete API documentation for the Secure Password Generator package.

## passwordgen.password

### PasswordGenerator

```python
class PasswordGenerator(
    length: int = 16,
    uppercase: bool = True,
    lowercase: bool = True,
    digits: bool = True,
    symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_symbols: Optional[str] = None
)
```

Generate cryptographically secure random passwords.

**Parameters:**
- `length` (int): Password length. Default: 16
- `uppercase` (bool): Include uppercase letters (A-Z). Default: True
- `lowercase` (bool): Include lowercase letters (a-z). Default: True
- `digits` (bool): Include digits (0-9). Default: True
- `symbols` (bool): Include symbols/punctuation. Default: True
- `exclude_ambiguous` (bool): Exclude ambiguous characters (0, O, 1, l, I). Default: False
- `custom_symbols` (str, optional): Custom symbol set to use instead of default

**Methods:**

#### generate()

```python
def generate() -> str
```

Generate a single secure random password.

**Returns:** String containing the generated password

**Example:**
```python
gen = PasswordGenerator(length=20)
password = gen.generate()
```

#### generate_multiple()

```python
def generate_multiple(count: int) -> list[str]
```

Generate multiple secure random passwords.

**Parameters:**
- `count` (int): Number of passwords to generate

**Returns:** List of generated passwords

**Raises:** `ValueError` if count < 1

#### Properties

- `charset` (str): The character set used for generation
- `entropy_bits` (float): Calculated entropy in bits

---

## passwordgen.passphrase

### PassphraseGenerator

```python
class PassphraseGenerator(
    word_count: int = 6,
    separator: str = "-",
    capitalize: bool = False,
    include_number: bool = False,
    wordlist_path: Optional[Path] = None
)
```

Generate Diceware-style passphrases using word lists.

**Parameters:**
- `word_count` (int): Number of words in passphrase. Default: 6
- `separator` (str): String to separate words. Default: "-"
- `capitalize` (bool): Capitalize first letter of each word. Default: False
- `include_number` (bool): Append random number (0-999). Default: False
- `wordlist_path` (Path, optional): Path to custom wordlist file

**Methods:**

#### generate()

```python
def generate() -> str
```

Generate a single secure random passphrase.

**Returns:** String containing the generated passphrase

#### generate_multiple()

```python
def generate_multiple(count: int) -> list[str]
```

Generate multiple secure random passphrases.

**Parameters:**
- `count` (int): Number of passphrases to generate

**Returns:** List of generated passphrases

#### Properties

- `wordlist_size` (int): Number of words in the wordlist
- `entropy_bits` (float): Calculated entropy in bits

---

## passwordgen.entropy

### Functions

#### calculate_password_entropy()

```python
def calculate_password_entropy(password: str) -> float
```

Calculate entropy of a password based on character composition.

**Parameters:**
- `password` (str): The password to analyze

**Returns:** Entropy in bits (float)

**Example:**
```python
from passwordgen.entropy import calculate_password_entropy

entropy = calculate_password_entropy("MyP@ssw0rd!")
print(f"Entropy: {entropy:.2f} bits")
```

#### calculate_passphrase_entropy()

```python
def calculate_passphrase_entropy(word_count: int, wordlist_size: int) -> float
```

Calculate entropy of a Diceware-style passphrase.

**Parameters:**
- `word_count` (int): Number of words in passphrase
- `wordlist_size` (int): Size of wordlist used

**Returns:** Entropy in bits (float)

**Raises:**
- `ValueError` if word_count < 1
- `ValueError` if wordlist_size < 1

#### entropy_to_strength()

```python
def entropy_to_strength(entropy_bits: float) -> str
```

Convert entropy bits to human-readable strength rating.

**Parameters:**
- `entropy_bits` (float): Entropy in bits

**Returns:** Strength rating:
- "Very Weak" (< 28 bits)
- "Weak" (28-35 bits)
- "Fair" (36-59 bits)
- "Strong" (60-127 bits)
- "Very Strong" (≥ 128 bits)

#### estimate_crack_time()

```python
def estimate_crack_time(
    entropy_bits: float,
    guesses_per_second: float = 1e12
) -> str
```

Estimate time to crack password given its entropy.

**Parameters:**
- `entropy_bits` (float): Entropy in bits
- `guesses_per_second` (float): Attack speed. Default: 1 trillion

**Returns:** Human-readable time estimate (e.g., "3.2 years")

---

## passwordgen.audit

### AuditResult

```python
@dataclass
class AuditResult:
    entropy_bits: float
    strength: str
    character_classes: dict[str, bool]
    issues: list[str]
    score: int  # 0-100
    recommendations: list[str]
```

Result of password security audit.

### PasswordAuditor

```python
class PasswordAuditor()
```

Comprehensive password security auditor.

**Methods:**

#### audit()

```python
def audit(password: str) -> AuditResult
```

Perform comprehensive security audit on a password.

**Parameters:**
- `password` (str): Password to audit

**Returns:** `AuditResult` with detailed analysis

**Example:**
```python
from passwordgen.audit import PasswordAuditor

auditor = PasswordAuditor()
result = auditor.audit("MyP@ssw0rd!")

print(f"Strength: {result.strength}")
print(f"Score: {result.score}/100")
for issue in result.issues:
    print(f"Issue: {issue}")
```

---

## passwordgen.crypto

### SecureHasher

```python
class SecureHasher()
```

Secure password hashing using memory-hard KDFs.

**Static Methods:**

#### hash_argon2()

```python
@staticmethod
def hash_argon2(
    password: str,
    time_cost: int = 3,
    memory_cost: int = 65536,
    parallelism: int = 4
) -> str
```

Hash password using Argon2id algorithm.

**Parameters:**
- `password` (str): Password to hash
- `time_cost` (int): Number of iterations. Default: 3
- `memory_cost` (int): Memory in KiB. Default: 64 MiB
- `parallelism` (int): Degree of parallelism. Default: 4

**Returns:** Encoded hash string

**Raises:** `ValueError` if password is empty

#### hash_bcrypt()

```python
@staticmethod
def hash_bcrypt(password: str, rounds: int = 12) -> str
```

Hash password using bcrypt algorithm.

**Parameters:**
- `password` (str): Password to hash
- `rounds` (int): Cost factor (4-31). Default: 12

**Returns:** bcrypt hash string

**Raises:**
- `ValueError` if password is empty
- `ValueError` if rounds not in 4-31

**Note:** bcrypt truncates passwords at 72 bytes.

#### hash_scrypt()

```python
@staticmethod
def hash_scrypt(
    password: str,
    n: int = 2**14,
    r: int = 8,
    p: int = 1
) -> str
```

Hash password using scrypt algorithm.

**Parameters:**
- `password` (str): Password to hash
- `n` (int): CPU/memory cost (must be power of 2). Default: 16384
- `r` (int): Block size. Default: 8
- `p` (int): Parallelization factor. Default: 1

**Returns:** Base64-encoded hash string

**Raises:**
- `ValueError` if password is empty
- `ValueError` if n is not a power of 2

#### verify_argon2()

```python
@staticmethod
def verify_argon2(password: str, hash_str: str) -> bool
```

Verify password against Argon2 hash.

**Parameters:**
- `password` (str): Password to verify
- `hash_str` (str): Hash string from `hash_argon2()`

**Returns:** True if password matches, False otherwise

#### verify_bcrypt()

```python
@staticmethod
def verify_bcrypt(password: str, hash_str: str) -> bool
```

Verify password against bcrypt hash.

#### verify_scrypt()

```python
@staticmethod
def verify_scrypt(password: str, hash_str: str) -> bool
```

Verify password against scrypt hash.

---

## passwordgen.vault

### SecureVault

```python
class SecureVault(vault_path: Path, master_password: str)
```

Encrypted password vault using Fernet.

**Parameters:**
- `vault_path` (Path): Path to vault file
- `master_password` (str): Master password for encryption

**Raises:**
- `ValueError` if master password is empty
- `PermissionError` if wrong password or cannot access file

**Methods:**

#### add_entry()

```python
def add_entry(
    name: str,
    password: str,
    metadata: Optional[dict[str, Any]] = None
) -> None
```

Add a password entry to the vault.

**Parameters:**
- `name` (str): Entry name (must be unique)
- `password` (str): Password to store
- `metadata` (dict, optional): Additional metadata

**Raises:**
- `ValueError` if name is empty or already exists
- `ValueError` if password is empty

#### get_entry()

```python
def get_entry(name: str) -> dict[str, Any]
```

Retrieve a password entry from the vault.

**Parameters:**
- `name` (str): Entry name

**Returns:** Dictionary with password, created, modified, and metadata

**Raises:** `KeyError` if entry not found

#### list_entries()

```python
def list_entries() -> list[str]
```

List all entry names in the vault.

**Returns:** Sorted list of entry names

#### delete_entry()

```python
def delete_entry(name: str) -> None
```

Delete a password entry from the vault.

**Raises:** `KeyError` if entry not found

#### change_master_password()

```python
def change_master_password(new_password: str) -> None
```

Change the vault's master password.

**Parameters:**
- `new_password` (str): New master password

**Raises:** `ValueError` if new password is empty

#### export_encrypted()

```python
def export_encrypted(output_path: Path) -> None
```

Export the encrypted vault to another location.

**Parameters:**
- `output_path` (Path): Destination path

---

## passwordgen.logging_secure

### SecureLogger

```python
class SecureLogger()
```

Secure logger that prevents sensitive data leakage.

**Class Methods:**

#### get_logger()

```python
@classmethod
def get_logger(cls, name: str, level: int = logging.INFO) -> logging.Logger
```

Get or create a secure logger instance.

**Parameters:**
- `name` (str): Logger name
- `level` (int): Logging level. Default: INFO

**Returns:** Configured logger with sensitive data filtering

**Example:**
```python
from passwordgen.logging_secure import SecureLogger

logger = SecureLogger.get_logger("my_module")
logger.info("User logged in")  # Safe
logger.info("Password: secret123")  # Auto-redacted
```

#### redact_sensitive_data()

```python
@staticmethod
def redact_sensitive_data(data: Any) -> Any
```

Manually redact sensitive data from any object.

**Parameters:**
- `data` (Any): Data to redact (string, dict, list, etc.)

**Returns:** Data with sensitive information redacted

---

## CLI Reference

See README.md for complete CLI documentation.

### Main Commands

- `passwordgen generate` - Generate passwords
- `passwordgen passphrase` - Generate passphrases
- `passwordgen audit` - Audit password strength
- `passwordgen hash` - Hash passwords
- `passwordgen verify` - Verify password hashes
- `passwordgen entropy` - Calculate entropy
- `passwordgen vault` - Manage encrypted vault

### Getting Help

```bash
passwordgen --help
passwordgen generate --help
passwordgen vault --help
```

---

## Examples

### Complete Workflow

```python
from passwordgen import (
    PasswordGenerator,
    PassphraseGenerator,
    PasswordAuditor,
    SecureHasher,
    SecureVault
)
from pathlib import Path

# Generate a password
gen = PasswordGenerator(length=20, symbols=True)
password = gen.generate()
print(f"Generated: {password}")
print(f"Entropy: {gen.entropy_bits:.1f} bits")

# Audit it
auditor = PasswordAuditor()
result = auditor.audit(password)
print(f"Strength: {result.strength}")
print(f"Score: {result.score}/100")

# Hash it
hasher = SecureHasher()
hash_str = hasher.hash_argon2(password)
print(f"Hash: {hash_str}")

# Store in vault
vault = SecureVault(Path("my.vault"), "master_pass")
vault.add_entry("example", password, {"url": "https://example.com"})
print("Stored in vault")

# Retrieve later
entry = vault.get_entry("example")
print(f"Retrieved: {entry['password']}")
```

## Error Handling

All functions may raise exceptions. Always handle errors appropriately:

```python
try:
    vault = SecureVault(Path("vault.vault"), "password")
    entry = vault.get_entry("nonexistent")
except KeyError:
    print("Entry not found")
except PermissionError:
    print("Wrong password or cannot access vault")
except ValueError as e:
    print(f"Invalid input: {e}")
```

## Type Hints

All code uses Python type hints for better IDE support and type checking:

```python
from typing import Optional, List, Dict, Any

def process_password(
    password: str,
    options: Optional[Dict[str, Any]] = None
) -> List[str]:
    ...
```

Use `mypy` for static type checking:

```bash
mypy src/
```
