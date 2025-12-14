"""
Cryptographic hashing and verification module.

Provides secure password hashing using memory-hard key derivation functions:
- Argon2id: Winner of Password Hashing Competition, best overall choice
- bcrypt: Industry standard, good for most applications
- scrypt: Memory-hard alternative to bcrypt

All algorithms are designed to be slow and memory-intensive to resist
brute-force and GPU-based attacks.
"""

import hashlib
import hmac
from base64 import b64decode, b64encode

import argon2
import bcrypt


class SecureHasher:
    """
    Secure password hashing using memory-hard KDFs.

    Supported algorithms:
    - Argon2id: Recommended default, winner of PHC
    - bcrypt: Industry standard
    - scrypt: Memory-hard alternative

    All methods include proper salting and use constant-time comparison
    for verification to prevent timing attacks.
    """

    @staticmethod
    def hash_argon2(
        password: str, time_cost: int = 3, memory_cost: int = 65536, parallelism: int = 4
    ) -> str:
        """
        Hash password using Argon2id algorithm.

        Argon2id is the winner of the Password Hashing Competition and provides
        the best resistance against both side-channel and GPU attacks.

        Parameters chosen for security:
        - time_cost: Number of iterations (default: 3)
        - memory_cost: Memory in KiB (default: 64 MiB)
        - parallelism: Number of parallel threads (default: 4)

        Args:
            password: Password to hash
            time_cost: Number of iterations
            memory_cost: Memory usage in KiB
            parallelism: Degree of parallelism

        Returns:
            Encoded hash string (includes algorithm, parameters, salt, and hash)

        Raises:
            ValueError: If parameters are invalid
        """
        if not password:
            raise ValueError("Password cannot be empty")

        # Use Argon2id (hybrid mode - best overall security)
        ph = argon2.PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID,  # Argon2id
        )

        # Hash the password (includes random salt generation)
        return ph.hash(password)

    @staticmethod
    def hash_bcrypt(password: str, rounds: int = 12) -> str:
        """
        Hash password using bcrypt algorithm.

        bcrypt is an industry-standard password hashing function based on the
        Blowfish cipher. It's been extensively tested and is still considered
        secure when used with appropriate cost factors.

        The cost factor is exponential: 2^rounds iterations.
        - rounds=12: ~250ms on modern CPU
        - rounds=14: ~1s on modern CPU

        Note: bcrypt has a maximum password length of 72 bytes.
        Longer passwords are automatically truncated.

        Args:
            password: Password to hash
            rounds: Cost factor (4-31, default: 12)

        Returns:
            bcrypt hash string (includes algorithm, cost, salt, and hash)

        Raises:
            ValueError: If parameters are invalid
        """
        if not password:
            raise ValueError("Password cannot be empty")
        if not (4 <= rounds <= 31):
            raise ValueError("bcrypt rounds must be between 4 and 31")

        # bcrypt requires bytes input and has 72-byte limit
        password_bytes = password.encode("utf-8")[:72]

        # Hash with bcrypt (includes random salt generation)
        hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(rounds=rounds))

        # Return as string
        return hashed.decode("utf-8")

    @staticmethod
    def hash_scrypt(password: str, n: int = 2**14, r: int = 8, p: int = 1) -> str:
        """
        Hash password using scrypt algorithm.

        scrypt is a memory-hard KDF designed to make hardware brute-force attacks
        expensive by requiring large amounts of memory.

        Parameters:
        - n: CPU/memory cost factor (must be power of 2)
        - r: Block size (affects memory usage)
        - p: Parallelization factor

        Memory usage: 128 * N * r bytes
        Default: 128 * 16384 * 8 = 16 MiB

        Args:
            password: Password to hash
            n: CPU/memory cost factor
            r: Block size parameter
            p: Parallelization parameter

        Returns:
            Base64-encoded string: "salt$hash"

        Raises:
            ValueError: If parameters are invalid
        """
        if not password:
            raise ValueError("Password cannot be empty")
        if n < 2 or (n & (n - 1)) != 0:
            raise ValueError("scrypt n must be a power of 2")
        if r < 1:
            raise ValueError("scrypt r must be >= 1")
        if p < 1:
            raise ValueError("scrypt p must be >= 1")

        # Generate random salt (32 bytes = 256 bits)
        import secrets

        salt = secrets.token_bytes(32)

        # Hash with scrypt
        hashed = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)

        # Encode as: n$r$p$salt$hash
        result = f"{n}${r}${p}${b64encode(salt).decode()}${b64encode(hashed).decode()}"
        return result

    @staticmethod
    def verify_argon2(password: str, hash_str: str) -> bool:
        """
        Verify password against Argon2 hash.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            password: Password to verify
            hash_str: Argon2 hash string from hash_argon2()

        Returns:
            True if password matches, False otherwise
        """
        if not password or not hash_str:
            return False

        try:
            ph = argon2.PasswordHasher()
            # verify() raises exception if password doesn't match
            ph.verify(hash_str, password)
            return True
        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHash):
            return False
        except Exception:
            return False

    @staticmethod
    def verify_bcrypt(password: str, hash_str: str) -> bool:
        """
        Verify password against bcrypt hash.

        Uses constant-time comparison internally to prevent timing attacks.

        Args:
            password: Password to verify
            hash_str: bcrypt hash string from hash_bcrypt()

        Returns:
            True if password matches, False otherwise
        """
        if not password or not hash_str:
            return False

        try:
            # bcrypt has 72-byte password limit
            password_bytes = password.encode("utf-8")[:72]
            hash_bytes = hash_str.encode("utf-8")
            # bcrypt.checkpw uses constant-time comparison
            return bcrypt.checkpw(password_bytes, hash_bytes)
        except Exception:
            return False

    @staticmethod
    def verify_scrypt(password: str, hash_str: str) -> bool:
        """
        Verify password against scrypt hash.

        Uses constant-time comparison via hmac.compare_digest to prevent
        timing attacks.

        Args:
            password: Password to verify
            hash_str: scrypt hash string from hash_scrypt()

        Returns:
            True if password matches, False otherwise
        """
        if not password or not hash_str:
            return False

        try:
            # Parse hash string: n$r$p$salt$hash
            parts = hash_str.split("$")
            if len(parts) != 5:
                return False

            n = int(parts[0])
            r = int(parts[1])
            p = int(parts[2])
            salt = b64decode(parts[3])
            expected_hash = b64decode(parts[4])

            # Hash the provided password with same parameters
            computed_hash = hashlib.scrypt(
                password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32
            )

            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(computed_hash, expected_hash)
        except Exception:
            return False
