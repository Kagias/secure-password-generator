"""
Secure passphrase generation using Diceware-style word selection.

This module generates passphrases using the EFF large wordlist (7776 words)
and cryptographically secure random selection via the secrets module.
"""

import math
import secrets
from pathlib import Path
from typing import Optional


class PassphraseGenerator:
    """
    Generate cryptographically secure random passphrases using word lists.
    
    Implements Diceware-style passphrase generation with the EFF large wordlist.
    Uses secrets module for CSPRNG-based word selection.
    """

    DEFAULT_WORDLIST = Path(__file__).parent.parent.parent / "wordlists" / "eff_large_wordlist.txt"

    def __init__(
        self,
        word_count: int = 6,
        separator: str = "-",
        capitalize: bool = False,
        include_number: bool = False,
        wordlist_path: Optional[Path] = None,
    ):
        """
        Initialize the passphrase generator.
        
        Args:
            word_count: Number of words in the passphrase (default: 6)
            separator: String to separate words (default: "-")
            capitalize: Capitalize the first letter of each word
            include_number: Append a random number (0-999) to the passphrase
            wordlist_path: Path to custom wordlist file (one word per line)
            
        Raises:
            ValueError: If word_count < 1
            FileNotFoundError: If wordlist file not found
        """
        if word_count < 1:
            raise ValueError("Word count must be at least 1")

        self.word_count = word_count
        self.separator = separator
        self.capitalize = capitalize
        self.include_number = include_number

        # Load wordlist
        wordlist_file = wordlist_path or self.DEFAULT_WORDLIST
        if not wordlist_file.exists():
            raise FileNotFoundError(f"Wordlist not found: {wordlist_file}")

        with open(wordlist_file, "r", encoding="utf-8") as f:
            # Strip whitespace and filter empty lines
            self._wordlist = [line.strip() for line in f if line.strip()]

        if not self._wordlist:
            raise ValueError("Wordlist is empty")

    @property
    def wordlist_size(self) -> int:
        """Return the number of words in the wordlist."""
        return len(self._wordlist)

    @property
    def entropy_bits(self) -> float:
        """
        Calculate the entropy of passphrases generated with this configuration.
        
        For Diceware-style passphrases:
        - Base entropy: word_count * log2(wordlist_size)
        - Additional entropy from number: log2(1000) ≈ 9.97 bits
        
        Capitalization doesn't add entropy when applied uniformly.
        
        Returns:
            Entropy in bits
        """
        base_entropy = self.word_count * math.log2(len(self._wordlist))
        
        # Add entropy from random number if included
        if self.include_number:
            base_entropy += math.log2(1000)  # Numbers 0-999
            
        return base_entropy

    def generate(self) -> str:
        """
        Generate a single secure random passphrase.
        
        Uses secrets.choice() for cryptographically secure random word selection.
        The secrets module uses os.urandom() for security.
        
        Returns:
            A cryptographically secure random passphrase
        """
        # Use secrets.choice for CSPRNG-based selection
        words = [secrets.choice(self._wordlist) for _ in range(self.word_count)]

        # Apply capitalization if requested
        if self.capitalize:
            words = [word.capitalize() for word in words]

        # Join words with separator
        passphrase = self.separator.join(words)

        # Add random number if requested (0-999)
        if self.include_number:
            # Use secrets.randbelow for secure random number generation
            random_num = secrets.randbelow(1000)
            passphrase += self.separator + str(random_num)

        return passphrase

    def generate_multiple(self, count: int) -> list[str]:
        """
        Generate multiple secure random passphrases.
        
        Args:
            count: Number of passphrases to generate
            
        Returns:
            List of cryptographically secure random passphrases
            
        Raises:
            ValueError: If count < 1
        """
        if count < 1:
            raise ValueError("Count must be at least 1")

        return [self.generate() for _ in range(count)]
