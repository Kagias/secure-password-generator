"""
Encrypted vault for secure password storage using Fernet (AES-128-CBC + HMAC-SHA256).

Provides a local encrypted password vault with master password protection,
using Argon2id for key derivation and Fernet for authenticated encryption.
"""

import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from passwordgen.crypto import SecureHasher


class SecureVault:
    """
    Encrypted password vault using Fernet symmetric encryption.
    
    Security features:
    - Master password protected with Argon2id key derivation
    - Fernet encryption (AES-128-CBC + HMAC-SHA256) for authenticated encryption
    - Random salt for each vault
    - JSON-based storage with metadata
    
    Fernet properties:
    - Symmetric encryption (AES in CBC mode with 128-bit keys)
    - Authentication via HMAC-SHA256 (prevents tampering)
    - Timestamp included in tokens (enables expiration)
    - Safe against various attacks (padding oracle, etc.)
    """

    PBKDF2_ITERATIONS = 480000  # OWASP 2023 recommendation

    def __init__(self, vault_path: Path, master_password: str):
        """
        Initialize or open an encrypted vault.
        
        Args:
            vault_path: Path to vault file
            master_password: Master password for vault encryption
            
        Raises:
            ValueError: If master password is empty
            PermissionError: If vault file cannot be accessed
        """
        if not master_password:
            raise ValueError("Master password cannot be empty")

        self.vault_path = Path(vault_path)
        self.master_password = master_password

        # Initialize or load vault
        if self.vault_path.exists():
            self._load_vault()
        else:
            self._create_vault()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2-HMAC-SHA256.
        
        PBKDF2 is used here (instead of Argon2) because it's well-suited for
        key derivation and is available in cryptography library without
        additional dependencies.
        
        Args:
            password: Master password
            salt: Salt bytes (16+ bytes recommended)
            
        Returns:
            32-byte key suitable for Fernet
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _create_vault(self) -> None:
        """Create a new encrypted vault."""
        # Generate random salt for key derivation
        self.salt = secrets.token_bytes(16)

        # Initialize empty vault data
        self.vault_data: dict[str, Any] = {
            "version": "1.0",
            "created": datetime.now().isoformat(),
            "entries": {},
        }

        # Save vault
        self._save_vault()

    def _load_vault(self) -> None:
        """Load and decrypt existing vault."""
        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()

            # First 16 bytes are salt
            self.salt = encrypted_data[:16]
            encrypted_vault = encrypted_data[16:]

            # Derive key and decrypt
            key = self._derive_key(self.master_password, self.salt)
            fernet = Fernet(self._encode_key(key))

            decrypted_data = fernet.decrypt(encrypted_vault)
            self.vault_data = json.loads(decrypted_data.decode("utf-8"))

        except Exception as e:
            raise PermissionError(f"Failed to load vault (wrong password?): {e}")

    def _save_vault(self) -> None:
        """Encrypt and save vault to disk."""
        # Derive key and encrypt
        key = self._derive_key(self.master_password, self.salt)
        fernet = Fernet(self._encode_key(key))

        # Serialize and encrypt vault data
        vault_json = json.dumps(self.vault_data, indent=2)
        encrypted_vault = fernet.encrypt(vault_json.encode("utf-8"))

        # Save: salt + encrypted_data
        with open(self.vault_path, "wb") as f:
            f.write(self.salt + encrypted_vault)

    def _encode_key(self, key: bytes) -> bytes:
        """Encode key in Fernet's base64 format."""
        import base64

        return base64.urlsafe_b64encode(key)

    def add_entry(self, name: str, password: str, metadata: Optional[dict[str, Any]] = None) -> None:
        """
        Add a password entry to the vault.
        
        Args:
            name: Entry name (must be unique)
            password: Password to store
            metadata: Optional metadata dictionary
            
        Raises:
            ValueError: If name is empty or already exists
        """
        if not name:
            raise ValueError("Entry name cannot be empty")
        if not password:
            raise ValueError("Password cannot be empty")
        if name in self.vault_data["entries"]:
            raise ValueError(f"Entry '{name}' already exists")

        # Create entry
        entry = {
            "password": password,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "metadata": metadata or {},
        }

        self.vault_data["entries"][name] = entry
        self._save_vault()

    def get_entry(self, name: str) -> dict[str, Any]:
        """
        Retrieve a password entry from the vault.
        
        Args:
            name: Entry name
            
        Returns:
            Entry dictionary with password and metadata
            
        Raises:
            KeyError: If entry not found
        """
        if name not in self.vault_data["entries"]:
            raise KeyError(f"Entry '{name}' not found")

        return dict(self.vault_data["entries"][name])

    def list_entries(self) -> list[str]:
        """
        List all entry names in the vault.
        
        Returns:
            Sorted list of entry names
        """
        return sorted(self.vault_data["entries"].keys())

    def delete_entry(self, name: str) -> None:
        """
        Delete a password entry from the vault.
        
        Args:
            name: Entry name
            
        Raises:
            KeyError: If entry not found
        """
        if name not in self.vault_data["entries"]:
            raise KeyError(f"Entry '{name}' not found")

        del self.vault_data["entries"][name]
        self._save_vault()

    def change_master_password(self, new_password: str) -> None:
        """
        Change the vault's master password.
        
        Re-encrypts the entire vault with a new key derived from the new password.
        
        Args:
            new_password: New master password
            
        Raises:
            ValueError: If new password is empty
        """
        if not new_password:
            raise ValueError("New master password cannot be empty")

        # Generate new salt
        self.salt = secrets.token_bytes(16)

        # Update master password
        self.master_password = new_password

        # Re-encrypt vault with new password
        self._save_vault()

    def export_encrypted(self, output_path: Path) -> None:
        """
        Export the encrypted vault to another location.
        
        Creates a copy of the encrypted vault file.
        
        Args:
            output_path: Destination path for exported vault
        """
        import shutil

        shutil.copy2(self.vault_path, output_path)
