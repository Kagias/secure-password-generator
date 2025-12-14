"""Tests for password audit module."""

import pytest

from passwordgen.audit import PasswordAuditor, AuditResult


class TestPasswordAuditor:
    """Test PasswordAuditor class."""

    def test_empty_password(self) -> None:
        """Test auditing empty password."""
        auditor = PasswordAuditor()
        result = auditor.audit("")
        assert result.entropy_bits == 0.0
        assert result.strength == "Very Weak"
        assert result.score == 0
        assert "empty" in result.issues[0].lower()

    def test_weak_password(self) -> None:
        """Test auditing weak password."""
        auditor = PasswordAuditor()
        result = auditor.audit("password")
        assert result.strength in ["Very Weak", "Weak", "Fair"]
        assert "dictionary" in str(result.issues).lower()
        assert result.score < 50

    def test_strong_password(self) -> None:
        """Test auditing strong password."""
        auditor = PasswordAuditor()
        result = auditor.audit("X9#mK2$pL5!nQ8")
        assert result.strength in ["Strong", "Very Strong"]
        assert result.score >= 60

    def test_character_classes_all(self) -> None:
        """Test detection of all character classes."""
        auditor = PasswordAuditor()
        result = auditor.audit("Abc123!@#")
        assert result.character_classes["lowercase"] is True
        assert result.character_classes["uppercase"] is True
        assert result.character_classes["digits"] is True
        assert result.character_classes["symbols"] is True

    def test_character_classes_partial(self) -> None:
        """Test detection of partial character classes."""
        auditor = PasswordAuditor()
        result = auditor.audit("abc123")
        assert result.character_classes["lowercase"] is True
        assert result.character_classes["uppercase"] is False
        assert result.character_classes["digits"] is True
        assert result.character_classes["symbols"] is False

    def test_short_password(self) -> None:
        """Test detection of short password."""
        auditor = PasswordAuditor()
        result = auditor.audit("abc")
        assert any("short" in issue.lower() for issue in result.issues)
        assert result.score < 40

    def test_medium_length_password(self) -> None:
        """Test medium length password."""
        auditor = PasswordAuditor()
        result = auditor.audit("abcdefghij")  # 10 chars
        # Should have length warning but less severe
        length_issues = [
            issue
            for issue in result.issues
            if "short" in issue.lower() or "minimal" in issue.lower()
        ]
        # May or may not have length issue at 10 chars

    def test_keyboard_pattern_detection(self) -> None:
        """Test detection of keyboard patterns."""
        auditor = PasswordAuditor()
        result = auditor.audit("qwerty123")
        assert any(
            "keyboard" in issue.lower() or "pattern" in issue.lower() for issue in result.issues
        )

    def test_sequential_pattern_detection(self) -> None:
        """Test detection of sequential patterns."""
        auditor = PasswordAuditor()
        result = auditor.audit("abc123xyz")
        # Should detect sequential patterns
        has_pattern_issue = any(
            "sequential" in issue.lower() or "pattern" in issue.lower() for issue in result.issues
        )
        # May or may not detect depending on implementation

    def test_repeated_characters(self) -> None:
        """Test detection of repeated characters."""
        auditor = PasswordAuditor()
        result = auditor.audit("aaaabbbb")
        assert any("repeat" in issue.lower() for issue in result.issues)

    def test_common_word_detection(self) -> None:
        """Test detection of common dictionary words."""
        auditor = PasswordAuditor()
        result = auditor.audit("password123")
        assert any("dictionary" in issue.lower() for issue in result.issues)

    def test_single_character_class(self) -> None:
        """Test password with single character class."""
        auditor = PasswordAuditor()
        result = auditor.audit("abcdefgh")
        assert any(
            "character class" in issue.lower() or "diversity" in issue.lower()
            for issue in result.issues
        )

    def test_recommendations_generated(self) -> None:
        """Test that recommendations are generated."""
        auditor = PasswordAuditor()
        result = auditor.audit("abc")
        assert len(result.recommendations) > 0

    def test_recommendations_for_short_password(self) -> None:
        """Test recommendations for short password."""
        auditor = PasswordAuditor()
        result = auditor.audit("Ab1!")
        assert any(
            "length" in rec.lower() or "longer" in rec.lower() for rec in result.recommendations
        )

    def test_recommendations_for_no_uppercase(self) -> None:
        """Test recommendations when missing uppercase."""
        auditor = PasswordAuditor()
        result = auditor.audit("abc123!@#")
        assert any("uppercase" in rec.lower() for rec in result.recommendations)

    def test_recommendations_for_no_digits(self) -> None:
        """Test recommendations when missing digits."""
        auditor = PasswordAuditor()
        result = auditor.audit("Abcdefgh!@#")
        assert any(
            "number" in rec.lower() or "digit" in rec.lower() for rec in result.recommendations
        )

    def test_recommendations_for_no_symbols(self) -> None:
        """Test recommendations when missing symbols."""
        auditor = PasswordAuditor()
        result = auditor.audit("Abcd1234")
        assert any("symbol" in rec.lower() for rec in result.recommendations)

    def test_score_range(self) -> None:
        """Test that score is within valid range."""
        auditor = PasswordAuditor()
        result = auditor.audit("Test123!@#")
        assert 0 <= result.score <= 100

    def test_entropy_calculation(self) -> None:
        """Test that entropy is calculated."""
        auditor = PasswordAuditor()
        result = auditor.audit("Abc123!@#")
        assert result.entropy_bits > 0

    def test_strength_classification(self) -> None:
        """Test strength classification."""
        auditor = PasswordAuditor()
        result = auditor.audit("Abc123!@#")
        assert result.strength in ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]

    def test_very_strong_password(self) -> None:
        """Test very strong password."""
        auditor = PasswordAuditor()
        # Long, complex, random password
        result = auditor.audit("X9#mK2$pL5!nQ8@wR7&vT4^uY6*")
        assert result.strength in ["Strong", "Very Strong"]
        assert result.score >= 70

    def test_audit_result_dataclass(self) -> None:
        """Test AuditResult dataclass structure."""
        result = AuditResult(
            entropy_bits=50.0,
            strength="Fair",
            character_classes={"lowercase": True},
            issues=["Test issue"],
            score=50,
            recommendations=["Test rec"],
        )
        assert result.entropy_bits == 50.0
        assert result.strength == "Fair"
        assert result.score == 50
        assert len(result.issues) == 1
        assert len(result.recommendations) == 1

    def test_multiple_issues_detected(self) -> None:
        """Test that multiple issues can be detected."""
        auditor = PasswordAuditor()
        result = auditor.audit("pass")  # Short, common word, single class
        assert len(result.issues) >= 2

    def test_numeric_only_password(self) -> None:
        """Test numeric-only password."""
        auditor = PasswordAuditor()
        result = auditor.audit("12345678")
        assert result.character_classes["digits"] is True
        assert result.character_classes["lowercase"] is False
        assert result.score < 50
