"""Tests for cryptographic hashing module."""

import pytest

from passwordgen.crypto import SecureHasher


class TestSecureHasher:
    """Test SecureHasher class."""

    def test_hash_argon2(self) -> None:
        """Test Argon2 password hashing."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_argon2(password)
        
        assert hash_str is not None
        assert isinstance(hash_str, str)
        assert hash_str.startswith("$argon2")
        assert len(hash_str) > 50

    def test_hash_bcrypt(self) -> None:
        """Test bcrypt password hashing."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_bcrypt(password)
        
        assert hash_str is not None
        assert isinstance(hash_str, str)
        assert hash_str.startswith("$2")
        assert len(hash_str) == 60

    def test_hash_scrypt(self) -> None:
        """Test scrypt password hashing."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_scrypt(password)
        
        assert hash_str is not None
        assert isinstance(hash_str, str)
        assert "$" in hash_str
        parts = hash_str.split("$")
        assert len(parts) == 5

    def test_verify_argon2_correct(self) -> None:
        """Test Argon2 verification with correct password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_argon2(password)
        
        assert hasher.verify_argon2(password, hash_str) is True

    def test_verify_argon2_incorrect(self) -> None:
        """Test Argon2 verification with incorrect password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_argon2(password)
        
        assert hasher.verify_argon2("wrong_password", hash_str) is False

    def test_verify_bcrypt_correct(self) -> None:
        """Test bcrypt verification with correct password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_bcrypt(password)
        
        assert hasher.verify_bcrypt(password, hash_str) is True

    def test_verify_bcrypt_incorrect(self) -> None:
        """Test bcrypt verification with incorrect password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_bcrypt(password)
        
        assert hasher.verify_bcrypt("wrong_password", hash_str) is False

    def test_verify_scrypt_correct(self) -> None:
        """Test scrypt verification with correct password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_scrypt(password)
        
        assert hasher.verify_scrypt(password, hash_str) is True

    def test_verify_scrypt_incorrect(self) -> None:
        """Test scrypt verification with incorrect password."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_scrypt(password)
        
        assert hasher.verify_scrypt("wrong_password", hash_str) is False

    def test_argon2_different_hashes(self) -> None:
        """Test that same password produces different hashes (due to salt)."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash1 = hasher.hash_argon2(password)
        hash2 = hasher.hash_argon2(password)
        
        assert hash1 != hash2

    def test_bcrypt_different_hashes(self) -> None:
        """Test that same password produces different hashes (due to salt)."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash1 = hasher.hash_bcrypt(password)
        hash2 = hasher.hash_bcrypt(password)
        
        assert hash1 != hash2

    def test_scrypt_different_hashes(self) -> None:
        """Test that same password produces different hashes (due to salt)."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash1 = hasher.hash_scrypt(password)
        hash2 = hasher.hash_scrypt(password)
        
        assert hash1 != hash2

    def test_hash_argon2_custom_parameters(self) -> None:
        """Test Argon2 with custom parameters."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_argon2(password, time_cost=2, memory_cost=32768, parallelism=2)
        
        assert hash_str is not None
        assert hasher.verify_argon2(password, hash_str) is True

    def test_hash_bcrypt_custom_rounds(self) -> None:
        """Test bcrypt with custom rounds."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_bcrypt(password, rounds=10)
        
        assert hash_str is not None
        assert hasher.verify_bcrypt(password, hash_str) is True

    def test_hash_scrypt_custom_parameters(self) -> None:
        """Test scrypt with custom parameters."""
        hasher = SecureHasher()
        password = "test_password_123"
        hash_str = hasher.hash_scrypt(password, n=2**12, r=4, p=1)
        
        assert hash_str is not None
        assert hasher.verify_scrypt(password, hash_str) is True

    def test_hash_empty_password_argon2(self) -> None:
        """Test hashing empty password with Argon2."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_argon2("")

    def test_hash_empty_password_bcrypt(self) -> None:
        """Test hashing empty password with bcrypt."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_bcrypt("")

    def test_hash_empty_password_scrypt(self) -> None:
        """Test hashing empty password with scrypt."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_scrypt("")

    def test_verify_empty_password(self) -> None:
        """Test verification with empty password."""
        hasher = SecureHasher()
        assert hasher.verify_argon2("", "fake_hash") is False
        assert hasher.verify_bcrypt("", "fake_hash") is False
        assert hasher.verify_scrypt("", "fake_hash") is False

    def test_verify_empty_hash(self) -> None:
        """Test verification with empty hash."""
        hasher = SecureHasher()
        assert hasher.verify_argon2("password", "") is False
        assert hasher.verify_bcrypt("password", "") is False
        assert hasher.verify_scrypt("password", "") is False

    def test_verify_invalid_hash_format(self) -> None:
        """Test verification with invalid hash format."""
        hasher = SecureHasher()
        assert hasher.verify_argon2("password", "invalid_hash") is False
        assert hasher.verify_bcrypt("password", "invalid_hash") is False
        assert hasher.verify_scrypt("password", "invalid_hash") is False

    def test_bcrypt_invalid_rounds(self) -> None:
        """Test bcrypt with invalid rounds."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_bcrypt("password", rounds=3)
        with pytest.raises(ValueError):
            hasher.hash_bcrypt("password", rounds=32)

    def test_scrypt_invalid_n(self) -> None:
        """Test scrypt with invalid n parameter."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_scrypt("password", n=3)  # Not power of 2

    def test_scrypt_invalid_r(self) -> None:
        """Test scrypt with invalid r parameter."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_scrypt("password", r=0)

    def test_scrypt_invalid_p(self) -> None:
        """Test scrypt with invalid p parameter."""
        hasher = SecureHasher()
        with pytest.raises(ValueError):
            hasher.hash_scrypt("password", p=0)

    def test_unicode_password(self) -> None:
        """Test hashing unicode passwords."""
        hasher = SecureHasher()
        password = "pāssw0rd™"
        
        hash_argon2 = hasher.hash_argon2(password)
        hash_bcrypt = hasher.hash_bcrypt(password)
        hash_scrypt = hasher.hash_scrypt(password)
        
        assert hasher.verify_argon2(password, hash_argon2) is True
        assert hasher.verify_bcrypt(password, hash_bcrypt) is True
        assert hasher.verify_scrypt(password, hash_scrypt) is True

    def test_long_password(self) -> None:
        """Test hashing very long passwords."""
        hasher = SecureHasher()
        password = "a" * 1000
        
        hash_argon2 = hasher.hash_argon2(password)
        hash_bcrypt = hasher.hash_bcrypt(password)
        hash_scrypt = hasher.hash_scrypt(password)
        
        assert hasher.verify_argon2(password, hash_argon2) is True
        assert hasher.verify_bcrypt(password, hash_bcrypt) is True
        assert hasher.verify_scrypt(password, hash_scrypt) is True
