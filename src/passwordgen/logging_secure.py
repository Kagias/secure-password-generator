"""
Secure logging system that prevents sensitive data leakage.

This module provides logging facilities that automatically redact or filter
sensitive information like passwords, keys, tokens, and hashes.
"""

import logging
import re
from typing import Any


class SensitiveDataFilter(logging.Filter):
    """
    Logging filter that redacts sensitive data from log messages.

    Patterns detected and redacted:
    - Password-like strings
    - API keys and tokens
    - Hash strings (long hex/base64 strings)
    - Credit card numbers
    - Email addresses (optional)
    """

    # Patterns for sensitive data
    PATTERNS = [
        # Password patterns (case insensitive)
        (re.compile(r'password["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE), "password=***REDACTED***"),
        (re.compile(r'passwd["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE), "passwd=***REDACTED***"),
        (re.compile(r'pwd["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE), "pwd=***REDACTED***"),
        # API keys and tokens
        (
            re.compile(r'api[_-]?key["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE),
            "api_key=***REDACTED***",
        ),
        (re.compile(r'token["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE), "token=***REDACTED***"),
        (re.compile(r'secret["\s]*[:=]["\s]*[^\s"]+', re.IGNORECASE), "secret=***REDACTED***"),
        # Long hex strings (potential hashes)
        (re.compile(r"\b[a-fA-F0-9]{32,}\b"), "***HASH_REDACTED***"),
        # Long base64 strings (potential keys/tokens)
        (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "***TOKEN_REDACTED***"),
        # Credit card numbers (simple pattern)
        (re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"), "***CARD_REDACTED***"),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record and redact sensitive data.

        Args:
            record: Log record to filter

        Returns:
            True (always allow record, but with redacted data)
        """
        # Redact message
        if hasattr(record, "msg"):
            record.msg = self._redact(str(record.msg))

        # Redact arguments
        if hasattr(record, "args") and record.args:
            if isinstance(record.args, dict):
                record.args = {k: self._redact(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self._redact(str(arg)) for arg in record.args)

        return True

    def _redact(self, text: str) -> str:
        """Apply all redaction patterns to text."""
        for pattern, replacement in self.PATTERNS:
            text = pattern.sub(replacement, text)
        return text


class SecureLogger:
    """
    Secure logger that prevents sensitive data leakage.

    Usage:
        logger = SecureLogger.get_logger("my_module")
        logger.info("User logged in")  # Safe
        logger.info("Password: secret123")  # Auto-redacted
    """

    _loggers: dict[str, logging.Logger] = {}

    @classmethod
    def get_logger(cls, name: str, level: int = logging.INFO) -> logging.Logger:
        """
        Get or create a secure logger instance.

        Args:
            name: Logger name
            level: Logging level (default: INFO)

        Returns:
            Configured logger with sensitive data filtering
        """
        if name in cls._loggers:
            return cls._loggers[name]

        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(level)

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()

        # Add console handler
        handler = logging.StreamHandler()
        handler.setLevel(level)

        # Add formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        # Add sensitive data filter
        handler.addFilter(SensitiveDataFilter())

        logger.addHandler(handler)

        # Store logger
        cls._loggers[name] = logger

        return logger

    @staticmethod
    def redact_sensitive_data(data: Any) -> Any:
        """
        Manually redact sensitive data from any object.

        Useful for sanitizing data before logging or display.

        Args:
            data: Data to redact (string, dict, list, etc.)

        Returns:
            Data with sensitive information redacted
        """
        if isinstance(data, str):
            filter_instance = SensitiveDataFilter()
            return filter_instance._redact(data)
        elif isinstance(data, dict):
            return {k: SecureLogger.redact_sensitive_data(v) for k, v in data.items()}
        elif isinstance(data, (list, tuple)):
            return type(data)(SecureLogger.redact_sensitive_data(item) for item in data)
        else:
            return data
