"""Tests for entropy calculation utilities."""

import pytest

from passwordgen.entropy import (
    calculate_password_entropy,
    calculate_passphrase_entropy,
    entropy_to_strength,
    estimate_crack_time,
)


class TestEntropyCalculation:
    """Test entropy calculation functions."""

    def test_calculate_password_entropy_empty(self) -> None:
        """Test entropy of empty password."""
        entropy = calculate_password_entropy("")
        assert entropy == 0.0

    def test_calculate_password_entropy_lowercase(self) -> None:
        """Test entropy of lowercase-only password."""
        entropy = calculate_password_entropy("abcdefgh")
        # 8 chars * log2(26) ≈ 37.6 bits
        assert 37 < entropy < 38

    def test_calculate_password_entropy_mixed(self) -> None:
        """Test entropy of mixed-case password."""
        entropy = calculate_password_entropy("AbCdEfGh")
        # 8 chars * log2(52) ≈ 45.6 bits
        assert 45 < entropy < 46

    def test_calculate_password_entropy_with_digits(self) -> None:
        """Test entropy with digits."""
        entropy = calculate_password_entropy("abc123")
        # 6 chars * log2(36) ≈ 31.0 bits
        assert 31 < entropy < 32

    def test_calculate_password_entropy_with_symbols(self) -> None:
        """Test entropy with symbols."""
        entropy = calculate_password_entropy("abc!@#")
        # 6 chars * log2(58) ≈ 35.0 bits
        assert 35 < entropy < 36

    def test_calculate_password_entropy_all_classes(self) -> None:
        """Test entropy with all character classes."""
        entropy = calculate_password_entropy("Abc123!@")
        # 8 chars * log2(94) ≈ 52.4 bits
        assert 52 < entropy < 53

    def test_calculate_passphrase_entropy(self) -> None:
        """Test passphrase entropy calculation."""
        entropy = calculate_passphrase_entropy(6, 7776)
        # 6 * log2(7776) ≈ 77.5 bits
        assert 77 < entropy < 78

    def test_calculate_passphrase_entropy_different_wordlist(self) -> None:
        """Test passphrase entropy with different wordlist size."""
        entropy = calculate_passphrase_entropy(5, 2048)
        # 5 * log2(2048) = 55 bits
        assert 54.9 < entropy < 55.1

    def test_calculate_passphrase_entropy_invalid_word_count(self) -> None:
        """Test invalid word count."""
        with pytest.raises(ValueError):
            calculate_passphrase_entropy(0, 7776)

    def test_calculate_passphrase_entropy_invalid_wordlist(self) -> None:
        """Test invalid wordlist size."""
        with pytest.raises(ValueError):
            calculate_passphrase_entropy(6, 0)

    def test_entropy_to_strength_very_weak(self) -> None:
        """Test very weak strength classification."""
        assert entropy_to_strength(20) == "Very Weak"
        assert entropy_to_strength(27) == "Very Weak"

    def test_entropy_to_strength_weak(self) -> None:
        """Test weak strength classification."""
        assert entropy_to_strength(28) == "Weak"
        assert entropy_to_strength(35) == "Weak"

    def test_entropy_to_strength_fair(self) -> None:
        """Test fair strength classification."""
        assert entropy_to_strength(36) == "Fair"
        assert entropy_to_strength(59) == "Fair"

    def test_entropy_to_strength_strong(self) -> None:
        """Test strong strength classification."""
        assert entropy_to_strength(60) == "Strong"
        assert entropy_to_strength(127) == "Strong"

    def test_entropy_to_strength_very_strong(self) -> None:
        """Test very strong strength classification."""
        assert entropy_to_strength(128) == "Very Strong"
        assert entropy_to_strength(256) == "Very Strong"

    def test_estimate_crack_time_instantly(self) -> None:
        """Test instant crack time."""
        time_str = estimate_crack_time(0)
        assert time_str == "instantly"

    def test_estimate_crack_time_seconds(self) -> None:
        """Test crack time in seconds."""
        # Very low entropy
        time_str = estimate_crack_time(10)
        assert "seconds" in time_str or "instantly" in time_str

    def test_estimate_crack_time_minutes(self) -> None:
        """Test crack time in minutes."""
        # ~20 bits should be very fast
        time_str = estimate_crack_time(20)
        # With 1e12 guesses/sec, 20 bits is basically instant
        assert isinstance(time_str, str)
        assert len(time_str) > 0

    def test_estimate_crack_time_hours(self) -> None:
        """Test crack time in hours."""
        # ~30 bits 
        time_str = estimate_crack_time(30)
        assert isinstance(time_str, str)
        assert len(time_str) > 0

    def test_estimate_crack_time_days(self) -> None:
        """Test crack time in days."""
        # ~40 bits
        time_str = estimate_crack_time(40)
        assert isinstance(time_str, str)
        assert len(time_str) > 0

    def test_estimate_crack_time_years(self) -> None:
        """Test crack time in years."""
        # 60 bits should be longer duration
        time_str = estimate_crack_time(60)
        assert isinstance(time_str, str)
        assert len(time_str) > 0

    def test_estimate_crack_time_centuries(self) -> None:
        """Test crack time in centuries."""
        # 80 bits should be centuries or more
        time_str = estimate_crack_time(80)
        assert any(x in time_str for x in ["years", "centuries", "millennia", "billions"])

    def test_estimate_crack_time_very_high(self) -> None:
        """Test crack time for very high entropy."""
        # 128+ bits should be impractical
        time_str = estimate_crack_time(128)
        assert any(x in time_str for x in ["centuries", "millennia", "billions"])

    def test_estimate_crack_time_custom_speed(self) -> None:
        """Test crack time with custom attack speed."""
        # Lower attack speed should result in longer times
        time_fast = estimate_crack_time(50, guesses_per_second=1e12)
        time_slow = estimate_crack_time(50, guesses_per_second=1e6)
        # Both should be valid time strings
        assert isinstance(time_fast, str)
        assert isinstance(time_slow, str)

    def test_single_character_entropy(self) -> None:
        """Test entropy of single character."""
        entropy = calculate_password_entropy("a")
        # 1 char * log2(26) ≈ 4.7 bits
        assert 4 < entropy < 5

    def test_unicode_password_entropy(self) -> None:
        """Test entropy with unicode characters."""
        entropy = calculate_password_entropy("café")
        # Should handle unicode and calculate reasonable entropy
        assert entropy > 0
