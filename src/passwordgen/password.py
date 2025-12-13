"""
Secure password generation module using cryptographically secure randomness.

This module uses the secrets module (CSPRNG) instead of the random module
to ensure cryptographic security. The secrets module uses os.urandom() which
provides randomness suitable for security purposes.
"""

import math
import secrets
import string
from typing import Optional


class PasswordGenerator:
    """
    Generate cryptographically secure random passwords.
    
    Uses the secrets module for CSPRNG-based random selection, ensuring
    passwords are suitable for security purposes.
    """

    # Ambiguous characters that can be confused: 0/O, 1/l/I, etc.
    AMBIGUOUS_CHARS = "0O1lI"

    def __init__(
        self,
        length: int = 16,
        uppercase: bool = True,
        lowercase: bool = True,
        digits: bool = True,
        symbols: bool = True,
        exclude_ambiguous: bool = False,
        custom_symbols: Optional[str] = None,
    ):
        """
        Initialize the password generator with specified character classes.
        
        Args:
            length: Password length (default: 16)
            uppercase: Include uppercase letters A-Z
            lowercase: Include lowercase letters a-z
            digits: Include digits 0-9
            symbols: Include symbols
            exclude_ambiguous: Exclude ambiguous characters (0, O, 1, l, I)
            custom_symbols: Custom symbol set (overrides default symbols)
            
        Raises:
            ValueError: If length < 1 or no character classes selected
        """
        if length < 1:
            raise ValueError("Password length must be at least 1")

        self.length = length
        self.uppercase = uppercase
        self.lowercase = lowercase
        self.digits = digits
        self.symbols = symbols
        self.exclude_ambiguous = exclude_ambiguous
        self.custom_symbols = custom_symbols

        # Build character set
        self._charset = self._build_charset()

        if not self._charset:
            raise ValueError("At least one character class must be enabled")

    def _build_charset(self) -> str:
        """Build the character set based on configuration."""
        chars = ""

        if self.lowercase:
            chars += string.ascii_lowercase
        if self.uppercase:
            chars += string.ascii_uppercase
        if self.digits:
            chars += string.digits
        if self.symbols:
            if self.custom_symbols is not None:
                chars += self.custom_symbols
            else:
                chars += string.punctuation

        # Remove ambiguous characters if requested
        if self.exclude_ambiguous:
            chars = "".join(c for c in chars if c not in self.AMBIGUOUS_CHARS)

        return chars

    @property
    def charset(self) -> str:
        """Return the character set used for password generation."""
        return self._charset

    @property
    def entropy_bits(self) -> float:
        """
        Calculate the entropy of passwords generated with this configuration.
        
        Entropy formula: log2(charset_size^length) = length * log2(charset_size)
        
        Returns:
            Entropy in bits
        """
        if not self._charset:
            return 0.0
        return self.length * math.log2(len(self._charset))

    def generate(self) -> str:
        """
        Generate a single secure random password.
        
        Uses secrets.choice() which provides cryptographically strong random
        selection from the character set. This is secure because secrets uses
        os.urandom() as its randomness source.
        
        Returns:
            A cryptographically secure random password
        """
        # Use secrets.choice for CSPRNG-based selection
        # secrets.choice uses os.urandom() internally for security
        return "".join(secrets.choice(self._charset) for _ in range(self.length))

    def generate_multiple(self, count: int) -> list[str]:
        """
        Generate multiple secure random passwords.
        
        Args:
            count: Number of passwords to generate
            
        Returns:
            List of cryptographically secure random passwords
            
        Raises:
            ValueError: If count < 1
        """
        if count < 1:
            raise ValueError("Count must be at least 1")

        return [self.generate() for _ in range(count)]
