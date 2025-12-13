"""
Entropy calculation utilities for passwords and passphrases.

Provides functions to calculate entropy, estimate security strength,
and predict crack times for passwords and passphrases.
"""

import math
import string
from typing import Set


def calculate_password_entropy(password: str) -> float:
    """
    Calculate the entropy of a password based on its character composition.
    
    This function determines which character classes are present in the password
    and calculates entropy based on the formula:
        entropy = length * log2(charset_size)
    
    Character classes detected:
    - Lowercase letters (a-z): 26 chars
    - Uppercase letters (A-Z): 26 chars
    - Digits (0-9): 10 chars
    - Symbols/punctuation: 32 chars
    
    Args:
        password: The password to analyze
        
    Returns:
        Entropy in bits
        
    Note:
        This is an estimate based on character composition. It doesn't account
        for patterns, dictionary words, or predictability.
    """
    if not password:
        return 0.0

    # Determine character classes present
    has_lowercase = any(c in string.ascii_lowercase for c in password)
    has_uppercase = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_symbols = any(c in string.punctuation for c in password)

    # Calculate charset size
    charset_size = 0
    if has_lowercase:
        charset_size += 26
    if has_uppercase:
        charset_size += 26
    if has_digits:
        charset_size += 10
    if has_symbols:
        charset_size += 32

    # Handle other characters (non-ASCII, etc.)
    all_standard_chars: Set[str] = set(string.ascii_letters + string.digits + string.punctuation)
    has_other = any(c not in all_standard_chars for c in password)
    if has_other:
        # Estimate additional charset for Unicode/special chars
        charset_size += 128

    if charset_size == 0:
        return 0.0

    # Calculate entropy
    return len(password) * math.log2(charset_size)


def calculate_passphrase_entropy(word_count: int, wordlist_size: int) -> float:
    """
    Calculate the entropy of a Diceware-style passphrase.
    
    For passphrases composed of randomly selected words from a wordlist,
    the entropy formula is:
        entropy = word_count * log2(wordlist_size)
    
    For the EFF large wordlist (7776 words):
        entropy = word_count * log2(7776) ≈ word_count * 12.925 bits
    
    Args:
        word_count: Number of words in the passphrase
        wordlist_size: Size of the wordlist used
        
    Returns:
        Entropy in bits
        
    Raises:
        ValueError: If word_count or wordlist_size < 1
    """
    if word_count < 1:
        raise ValueError("Word count must be at least 1")
    if wordlist_size < 1:
        raise ValueError("Wordlist size must be at least 1")

    return word_count * math.log2(wordlist_size)


def entropy_to_strength(entropy_bits: float) -> str:
    """
    Convert entropy bits to a human-readable strength rating.
    
    Strength classifications based on NIST guidelines:
    - < 28 bits: Very Weak (seconds to crack)
    - 28-35 bits: Weak (minutes to hours)
    - 36-59 bits: Fair (days to months)
    - 60-127 bits: Strong (years to centuries)
    - >= 128 bits: Very Strong (impractical to crack)
    
    Args:
        entropy_bits: Entropy in bits
        
    Returns:
        Strength rating: "Very Weak", "Weak", "Fair", "Strong", or "Very Strong"
    """
    if entropy_bits < 28:
        return "Very Weak"
    elif entropy_bits < 36:
        return "Weak"
    elif entropy_bits < 60:
        return "Fair"
    elif entropy_bits < 128:
        return "Strong"
    else:
        return "Very Strong"


def estimate_crack_time(entropy_bits: float, guesses_per_second: float = 1e12) -> str:
    """
    Estimate the time to crack a password given its entropy.
    
    Calculation:
        total_combinations = 2^entropy_bits
        time_seconds = total_combinations / (2 * guesses_per_second)
        
    We divide by 2 for average case (password found at 50% search).
    
    Default assumption: 1 trillion (1e12) guesses per second
    This represents high-end GPU cluster attacks.
    
    Args:
        entropy_bits: Entropy in bits
        guesses_per_second: Attack speed in guesses/second
        
    Returns:
        Human-readable time estimate (e.g., "3.2 years", "centuries")
    """
    if entropy_bits <= 0:
        return "instantly"

    # Calculate total combinations
    total_combinations = 2**entropy_bits

    # Average time to find password (found at 50% of search space)
    avg_combinations = total_combinations / 2

    # Time in seconds
    seconds = avg_combinations / guesses_per_second

    # Convert to human-readable format
    if seconds < 1:
        return "instantly"
    elif seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f} hours"
    elif seconds < 31536000:
        days = seconds / 86400
        return f"{days:.1f} days"
    elif seconds < 3153600000:  # 100 years
        years = seconds / 31536000
        return f"{years:.1f} years"
    elif seconds < 31536000000:  # 1000 years
        centuries = seconds / 3153600000
        return f"{centuries:.1f} centuries"
    elif seconds < 31536000000000:  # 1 million years
        millennia = seconds / 31536000000
        return f"{millennia:.1f} millennia"
    else:
        return "billions of years"
