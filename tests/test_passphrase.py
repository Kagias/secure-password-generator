"""Tests for passphrase generation module."""

import pytest
from pathlib import Path

from passwordgen.passphrase import PassphraseGenerator


class TestPassphraseGenerator:
    """Test PassphraseGenerator class."""

    def test_default_initialization(self) -> None:
        """Test default initialization."""
        gen = PassphraseGenerator()
        assert gen.word_count == 6
        assert gen.separator == "-"
        assert gen.capitalize is False
        assert gen.include_number is False

    def test_custom_word_count(self) -> None:
        """Test custom word count."""
        gen = PassphraseGenerator(word_count=4)
        passphrase = gen.generate()
        words = passphrase.split("-")
        assert len(words) == 4

    def test_custom_separator(self) -> None:
        """Test custom separator."""
        gen = PassphraseGenerator(separator="_")
        passphrase = gen.generate()
        assert "_" in passphrase
        assert "-" not in passphrase

    def test_capitalize(self) -> None:
        """Test capitalization."""
        gen = PassphraseGenerator(capitalize=True)
        passphrase = gen.generate()
        words = passphrase.split("-")
        for word in words:
            assert word[0].isupper()

    def test_include_number(self) -> None:
        """Test including a number."""
        gen = PassphraseGenerator(include_number=True)
        passphrase = gen.generate()
        parts = passphrase.split("-")
        # Last part should be a number
        assert parts[-1].isdigit()
        number = int(parts[-1])
        assert 0 <= number < 1000

    def test_generate_multiple(self) -> None:
        """Test generating multiple passphrases."""
        gen = PassphraseGenerator()
        passphrases = gen.generate_multiple(5)
        assert len(passphrases) == 5
        # Most should be unique (small chance of collision)
        assert len(set(passphrases)) >= 4

    def test_entropy_calculation(self) -> None:
        """Test entropy calculation."""
        gen = PassphraseGenerator(word_count=6)
        entropy = gen.entropy_bits
        assert entropy > 0
        # Should be approximately 6 * log2(7776) ≈ 77.5 bits
        assert 75 < entropy < 80

    def test_entropy_with_number(self) -> None:
        """Test entropy calculation with number."""
        gen = PassphraseGenerator(word_count=6, include_number=True)
        entropy = gen.entropy_bits
        # Should be higher than without number (adds ~9.97 bits)
        assert 85 < entropy < 90

    def test_wordlist_size_property(self) -> None:
        """Test wordlist size property."""
        gen = PassphraseGenerator()
        size = gen.wordlist_size
        assert size == 7776

    def test_invalid_word_count(self) -> None:
        """Test invalid word count."""
        with pytest.raises(ValueError):
            PassphraseGenerator(word_count=0)

    def test_invalid_count(self) -> None:
        """Test invalid count for generate_multiple."""
        gen = PassphraseGenerator()
        with pytest.raises(ValueError):
            gen.generate_multiple(0)

    def test_nonexistent_wordlist(self) -> None:
        """Test error with nonexistent wordlist."""
        with pytest.raises(FileNotFoundError):
            PassphraseGenerator(wordlist_path=Path("/nonexistent/path.txt"))

    def test_randomness(self) -> None:
        """Test that generated passphrases are different."""
        gen = PassphraseGenerator()
        passphrases = [gen.generate() for _ in range(50)]
        # Most should be unique
        unique_count = len(set(passphrases))
        assert unique_count >= 45  # Allow for small chance of collision

    def test_minimum_word_count(self) -> None:
        """Test minimum word count."""
        gen = PassphraseGenerator(word_count=1)
        passphrase = gen.generate()
        words = passphrase.split("-")
        assert len(words) == 1

    def test_large_word_count(self) -> None:
        """Test large word count."""
        gen = PassphraseGenerator(word_count=20)
        passphrase = gen.generate()
        words = passphrase.split("-")
        assert len(words) == 20

    def test_empty_separator(self) -> None:
        """Test empty separator."""
        gen = PassphraseGenerator(separator="")
        passphrase = gen.generate()
        # Should be a single concatenated string
        assert " " not in passphrase
        assert "-" not in passphrase

    def test_space_separator(self) -> None:
        """Test space as separator."""
        gen = PassphraseGenerator(separator=" ")
        passphrase = gen.generate()
        words = passphrase.split(" ")
        assert len(words) == 6
