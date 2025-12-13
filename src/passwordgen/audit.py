"""
Password strength auditor with pattern detection and security analysis.

Performs comprehensive security audits on passwords including:
- Entropy calculation
- Character class diversity analysis
- Common pattern detection (sequences, repeats, keyboard patterns)
- Dictionary word detection
- Security recommendations
"""

import re
import string
from dataclasses import dataclass, field
from pathlib import Path

from passwordgen.entropy import calculate_password_entropy, entropy_to_strength


@dataclass
class AuditResult:
    """
    Result of password security audit.
    
    Attributes:
        entropy_bits: Calculated entropy in bits
        strength: Strength rating ("Very Weak" to "Very Strong")
        character_classes: Dict of character class presence
        issues: List of security issues found
        score: Overall security score (0-100)
        recommendations: List of improvement recommendations
    """

    entropy_bits: float
    strength: str
    character_classes: dict[str, bool]
    issues: list[str] = field(default_factory=list)
    score: int = 0
    recommendations: list[str] = field(default_factory=list)


class PasswordAuditor:
    """
    Comprehensive password security auditor.
    
    Analyzes passwords for:
    - Entropy and strength
    - Character class diversity
    - Common patterns and weaknesses
    - Dictionary words
    - Provides security score and recommendations
    """

    # Common keyboard patterns
    KEYBOARD_PATTERNS = [
        "qwerty",
        "asdf",
        "zxcv",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890",
        "0987654321",
    ]

    # Common password patterns
    COMMON_PATTERNS = [
        r"(.)\1{2,}",  # Character repeated 3+ times
        r"(012|123|234|345|456|567|678|789|890)",  # Numeric sequences
        r"(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)",
    ]

    # Common dictionary words to check (basic set)
    COMMON_WORDS = [
        "password",
        "admin",
        "user",
        "login",
        "welcome",
        "letmein",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "princess",
        "football",
        "shadow",
        "michael",
        "jennifer",
        "computer",
        "secret",
        "summer",
        "winter",
        "spring",
    ]

    def audit(self, password: str) -> AuditResult:
        """
        Perform comprehensive security audit on a password.
        
        Args:
            password: The password to audit
            
        Returns:
            AuditResult with detailed analysis
        """
        if not password:
            return AuditResult(
                entropy_bits=0.0,
                strength="Very Weak",
                character_classes={},
                issues=["Password is empty"],
                score=0,
                recommendations=["Create a password"],
            )

        # Calculate entropy
        entropy_bits = calculate_password_entropy(password)
        strength = entropy_to_strength(entropy_bits)

        # Analyze character classes
        character_classes = {
            "lowercase": any(c in string.ascii_lowercase for c in password),
            "uppercase": any(c in string.ascii_uppercase for c in password),
            "digits": any(c in string.digits for c in password),
            "symbols": any(c in string.punctuation for c in password),
        }

        # Collect issues
        issues: list[str] = []
        issues.extend(self._check_length(password))
        issues.extend(self._check_patterns(password))
        issues.extend(self._check_sequences(password))
        issues.extend(self._check_dictionary(password))
        issues.extend(self._check_repeats(password))
        issues.extend(self._check_character_classes(character_classes))

        # Calculate score (0-100)
        score = self._calculate_score(entropy_bits, character_classes, issues)

        # Generate recommendations
        recommendations = self._generate_recommendations(
            password, entropy_bits, character_classes, issues
        )

        return AuditResult(
            entropy_bits=entropy_bits,
            strength=strength,
            character_classes=character_classes,
            issues=issues,
            score=score,
            recommendations=recommendations,
        )

    def _check_length(self, password: str) -> list[str]:
        """Check password length requirements."""
        issues = []
        if len(password) < 8:
            issues.append("Password is too short (minimum 8 characters recommended)")
        elif len(password) < 12:
            issues.append("Password length is minimal (12+ characters recommended)")
        return issues

    def _check_patterns(self, password: str) -> list[str]:
        """Check for common patterns."""
        issues = []
        password_lower = password.lower()

        # Check keyboard patterns
        for pattern in self.KEYBOARD_PATTERNS:
            if pattern in password_lower:
                issues.append(f"Contains keyboard pattern: {pattern}")

        return issues

    def _check_sequences(self, password: str) -> list[str]:
        """Check for sequential patterns."""
        issues = []
        password_lower = password.lower()

        for pattern_regex in self.COMMON_PATTERNS:
            matches = re.findall(pattern_regex, password_lower)
            if matches:
                issues.append("Contains sequential or repeated patterns")
                break

        return issues

    def _check_dictionary(self, password: str) -> list[str]:
        """Check for common dictionary words."""
        issues = []
        password_lower = password.lower()

        for word in self.COMMON_WORDS:
            if word in password_lower:
                issues.append(f"Contains common dictionary word: {word}")

        return issues

    def _check_repeats(self, password: str) -> list[str]:
        """Check for excessive character repetition."""
        issues = []

        # Check for 4+ consecutive identical characters
        for i in range(len(password) - 3):
            if password[i] == password[i + 1] == password[i + 2] == password[i + 3]:
                issues.append("Contains excessive character repetition")
                break

        return issues

    def _check_character_classes(self, character_classes: dict[str, bool]) -> list[str]:
        """Check character class diversity."""
        issues = []

        classes_used = sum(character_classes.values())
        if classes_used < 2:
            issues.append("Uses only one character class (use mixed case, numbers, symbols)")
        elif classes_used < 3:
            issues.append("Limited character diversity (add more character types)")

        return issues

    def _calculate_score(
        self, entropy_bits: float, character_classes: dict[str, bool], issues: list[str]
    ) -> int:
        """
        Calculate overall security score (0-100).
        
        Scoring factors:
        - Base score from entropy (50%)
        - Character class diversity (25%)
        - Issue penalties (25%)
        """
        # Entropy score (0-50 points)
        # 128+ bits = 50 points, linear scale
        entropy_score = min(50, (entropy_bits / 128) * 50)

        # Character class score (0-25 points)
        classes_used = sum(character_classes.values())
        class_score = (classes_used / 4) * 25

        # Issue penalty (0-25 points deducted)
        issue_penalty = min(25, len(issues) * 5)

        # Total score
        score = int(entropy_score + class_score - issue_penalty)
        return max(0, min(100, score))

    def _generate_recommendations(
        self,
        password: str,
        entropy_bits: float,
        character_classes: dict[str, bool],
        issues: list[str],
    ) -> list[str]:
        """Generate security recommendations."""
        recommendations = []

        # Length recommendations
        if len(password) < 12:
            recommendations.append("Increase password length to at least 12 characters")

        # Entropy recommendations
        if entropy_bits < 60:
            recommendations.append("Increase password complexity for stronger security")

        # Character class recommendations
        if not character_classes["uppercase"]:
            recommendations.append("Add uppercase letters")
        if not character_classes["lowercase"]:
            recommendations.append("Add lowercase letters")
        if not character_classes["digits"]:
            recommendations.append("Add numbers")
        if not character_classes["symbols"]:
            recommendations.append("Add symbols")

        # Pattern recommendations
        if any("pattern" in issue.lower() or "sequential" in issue.lower() for issue in issues):
            recommendations.append("Avoid predictable patterns and sequences")

        # Dictionary recommendations
        if any("dictionary" in issue.lower() for issue in issues):
            recommendations.append("Avoid common words and phrases")

        # General recommendation
        if not recommendations:
            recommendations.append("Password appears secure, but consider using a passphrase")

        return recommendations
