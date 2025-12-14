"""Tests for password generation module."""

import pytest
import string

from passwordgen.password import PasswordGenerator


class TestPasswordGenerator:
    """Test PasswordGenerator class."""

    def test_default_initialization(self) -> None:
        """Test default initialization."""
        gen = PasswordGenerator()
        assert gen.length == 16
        assert gen.uppercase is True
        assert gen.lowercase is True
        assert gen.digits is True
        assert gen.symbols is True
        assert gen.exclude_ambiguous is False

    def test_custom_length(self) -> None:
        """Test custom password length."""
        gen = PasswordGenerator(length=24)
        password = gen.generate()
        assert len(password) == 24

    def test_uppercase_only(self) -> None:
        """Test uppercase-only passwords."""
        gen = PasswordGenerator(lowercase=False, digits=False, symbols=False)
        password = gen.generate()
        assert all(c in string.ascii_uppercase for c in password)

    def test_lowercase_only(self) -> None:
        """Test lowercase-only passwords."""
        gen = PasswordGenerator(uppercase=False, digits=False, symbols=False)
        password = gen.generate()
        assert all(c in string.ascii_lowercase for c in password)

    def test_digits_only(self) -> None:
        """Test digits-only passwords."""
        gen = PasswordGenerator(uppercase=False, lowercase=False, symbols=False)
        password = gen.generate()
        assert all(c in string.digits for c in password)

    def test_symbols_only(self) -> None:
        """Test symbols-only passwords."""
        gen = PasswordGenerator(uppercase=False, lowercase=False, digits=False)
        password = gen.generate()
        assert all(c in string.punctuation for c in password)

    def test_exclude_ambiguous(self) -> None:
        """Test exclusion of ambiguous characters."""
        gen = PasswordGenerator(exclude_ambiguous=True)
        password = gen.generate()
        for char in PasswordGenerator.AMBIGUOUS_CHARS:
            assert char not in password

    def test_custom_symbols(self) -> None:
        """Test custom symbol set."""
        custom = "!@#$"
        gen = PasswordGenerator(
            uppercase=False, lowercase=False, digits=False, custom_symbols=custom
        )
        password = gen.generate()
        assert all(c in custom for c in password)

    def test_generate_multiple(self) -> None:
        """Test generating multiple passwords."""
        gen = PasswordGenerator()
        passwords = gen.generate_multiple(5)
        assert len(passwords) == 5
        assert len(set(passwords)) == 5  # All unique

    def test_entropy_calculation(self) -> None:
        """Test entropy calculation."""
        gen = PasswordGenerator(length=16)
        entropy = gen.entropy_bits
        assert entropy > 0
        # Should be approximately 16 * log2(94) ≈ 105 bits
        assert 100 < entropy < 110

    def test_charset_property(self) -> None:
        """Test charset property."""
        gen = PasswordGenerator()
        charset = gen.charset
        assert len(charset) > 0
        assert isinstance(charset, str)

    def test_invalid_length(self) -> None:
        """Test invalid password length."""
        with pytest.raises(ValueError):
            PasswordGenerator(length=0)

    def test_no_character_classes(self) -> None:
        """Test error when no character classes enabled."""
        with pytest.raises(ValueError):
            PasswordGenerator(uppercase=False, lowercase=False, digits=False, symbols=False)

    def test_invalid_count(self) -> None:
        """Test invalid count for generate_multiple."""
        gen = PasswordGenerator()
        with pytest.raises(ValueError):
            gen.generate_multiple(0)

    def test_randomness(self) -> None:
        """Test that generated passwords are different."""
        gen = PasswordGenerator()
        passwords = [gen.generate() for _ in range(100)]
        # All should be unique (extremely high probability)
        assert len(set(passwords)) == 100

    def test_minimum_length(self) -> None:
        """Test minimum password length."""
        gen = PasswordGenerator(length=1)
        password = gen.generate()
        assert len(password) == 1

    def test_very_long_password(self) -> None:
        """Test generating very long passwords."""
        gen = PasswordGenerator(length=1000)
        password = gen.generate()
        assert len(password) == 1000
