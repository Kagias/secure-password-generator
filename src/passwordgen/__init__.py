"""
Secure Password and Passphrase Generator

A production-quality, cybersecurity-focused Python package for generating
secure passwords and passphrases with entropy analysis, password auditing,
and encrypted vault functionality.

All randomness uses the secrets module (CSPRNG) for cryptographic security.
"""

__version__ = "1.0.0"
__author__ = "Kagias"

from passwordgen.password import PasswordGenerator
from passwordgen.passphrase import PassphraseGenerator
from passwordgen.entropy import (
    calculate_password_entropy,
    calculate_passphrase_entropy,
    entropy_to_strength,
    estimate_crack_time,
)
from passwordgen.audit import PasswordAuditor, AuditResult
from passwordgen.crypto import SecureHasher
from passwordgen.vault import SecureVault

__all__ = [
    "PasswordGenerator",
    "PassphraseGenerator",
    "calculate_password_entropy",
    "calculate_passphrase_entropy",
    "entropy_to_strength",
    "estimate_crack_time",
    "PasswordAuditor",
    "AuditResult",
    "SecureHasher",
    "SecureVault",
]
