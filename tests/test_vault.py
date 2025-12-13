"""Tests for encrypted vault module."""

import pytest
import tempfile
from pathlib import Path

from passwordgen.vault import SecureVault


class TestSecureVault:
    """Test SecureVault class."""

    def test_create_vault(self, tmp_path: Path) -> None:
        """Test creating a new vault."""
        vault_path = tmp_path / "test.vault"
        master_password = "secure_master_pass_123"
        
        vault = SecureVault(vault_path, master_password)
        
        assert vault_path.exists()
        assert vault.vault_path == vault_path

    def test_open_existing_vault(self, tmp_path: Path) -> None:
        """Test opening an existing vault."""
        vault_path = tmp_path / "test.vault"
        master_password = "secure_master_pass_123"
        
        # Create vault
        vault1 = SecureVault(vault_path, master_password)
        vault1.add_entry("test", "password123")
        
        # Open existing vault
        vault2 = SecureVault(vault_path, master_password)
        entry = vault2.get_entry("test")
        
        assert entry["password"] == "password123"

    def test_add_entry(self, tmp_path: Path) -> None:
        """Test adding an entry to the vault."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        vault.add_entry("gmail", "mypassword123")
        entry = vault.get_entry("gmail")
        
        assert entry["password"] == "mypassword123"
        assert "created" in entry
        assert "modified" in entry

    def test_add_entry_with_metadata(self, tmp_path: Path) -> None:
        """Test adding entry with metadata."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        metadata = {"username": "user@example.com", "url": "https://example.com"}
        vault.add_entry("example", "pass123", metadata)
        entry = vault.get_entry("example")
        
        assert entry["password"] == "pass123"
        assert entry["metadata"]["username"] == "user@example.com"
        assert entry["metadata"]["url"] == "https://example.com"

    def test_get_entry(self, tmp_path: Path) -> None:
        """Test retrieving an entry."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        vault.add_entry("test", "password")
        entry = vault.get_entry("test")
        
        assert entry["password"] == "password"

    def test_get_nonexistent_entry(self, tmp_path: Path) -> None:
        """Test retrieving non-existent entry."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        with pytest.raises(KeyError):
            vault.get_entry("nonexistent")

    def test_list_entries(self, tmp_path: Path) -> None:
        """Test listing all entries."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        vault.add_entry("entry1", "pass1")
        vault.add_entry("entry2", "pass2")
        vault.add_entry("entry3", "pass3")
        
        entries = vault.list_entries()
        
        assert len(entries) == 3
        assert "entry1" in entries
        assert "entry2" in entries
        assert "entry3" in entries
        assert entries == sorted(entries)  # Should be sorted

    def test_list_empty_vault(self, tmp_path: Path) -> None:
        """Test listing entries in empty vault."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        entries = vault.list_entries()
        
        assert len(entries) == 0

    def test_delete_entry(self, tmp_path: Path) -> None:
        """Test deleting an entry."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        vault.add_entry("test", "password")
        assert "test" in vault.list_entries()
        
        vault.delete_entry("test")
        assert "test" not in vault.list_entries()

    def test_delete_nonexistent_entry(self, tmp_path: Path) -> None:
        """Test deleting non-existent entry."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        with pytest.raises(KeyError):
            vault.delete_entry("nonexistent")

    def test_change_master_password(self, tmp_path: Path) -> None:
        """Test changing master password."""
        vault_path = tmp_path / "test.vault"
        old_password = "old_master_pass"
        new_password = "new_master_pass"
        
        # Create vault with old password
        vault1 = SecureVault(vault_path, old_password)
        vault1.add_entry("test", "secret123")
        
        # Change password
        vault1.change_master_password(new_password)
        
        # Open with new password
        vault2 = SecureVault(vault_path, new_password)
        entry = vault2.get_entry("test")
        
        assert entry["password"] == "secret123"

    def test_change_master_password_old_fails(self, tmp_path: Path) -> None:
        """Test that old password fails after change."""
        vault_path = tmp_path / "test.vault"
        old_password = "old_master_pass"
        new_password = "new_master_pass"
        
        vault1 = SecureVault(vault_path, old_password)
        vault1.add_entry("test", "secret123")
        vault1.change_master_password(new_password)
        
        # Try to open with old password
        with pytest.raises(PermissionError):
            SecureVault(vault_path, old_password)

    def test_export_encrypted(self, tmp_path: Path) -> None:
        """Test exporting encrypted vault."""
        vault_path = tmp_path / "test.vault"
        export_path = tmp_path / "exported.vault"
        
        vault1 = SecureVault(vault_path, "master_pass")
        vault1.add_entry("test", "password123")
        
        vault1.export_encrypted(export_path)
        
        assert export_path.exists()
        
        # Verify exported vault can be opened
        vault2 = SecureVault(export_path, "master_pass")
        entry = vault2.get_entry("test")
        assert entry["password"] == "password123"

    def test_wrong_master_password(self, tmp_path: Path) -> None:
        """Test opening vault with wrong password."""
        vault_path = tmp_path / "test.vault"
        
        vault1 = SecureVault(vault_path, "correct_password")
        vault1.add_entry("test", "secret")
        
        with pytest.raises(PermissionError):
            SecureVault(vault_path, "wrong_password")

    def test_empty_master_password(self, tmp_path: Path) -> None:
        """Test creating vault with empty password."""
        vault_path = tmp_path / "test.vault"
        
        with pytest.raises(ValueError):
            SecureVault(vault_path, "")

    def test_add_duplicate_entry(self, tmp_path: Path) -> None:
        """Test adding duplicate entry."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        vault.add_entry("test", "password1")
        
        with pytest.raises(ValueError):
            vault.add_entry("test", "password2")

    def test_add_empty_name(self, tmp_path: Path) -> None:
        """Test adding entry with empty name."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        with pytest.raises(ValueError):
            vault.add_entry("", "password")

    def test_add_empty_password(self, tmp_path: Path) -> None:
        """Test adding entry with empty password."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        with pytest.raises(ValueError):
            vault.add_entry("test", "")

    def test_persistence(self, tmp_path: Path) -> None:
        """Test that vault persists across instances."""
        vault_path = tmp_path / "test.vault"
        master_password = "master_pass"
        
        # Create vault and add entries
        vault1 = SecureVault(vault_path, master_password)
        vault1.add_entry("entry1", "pass1")
        vault1.add_entry("entry2", "pass2")
        
        # Open new instance
        vault2 = SecureVault(vault_path, master_password)
        entries = vault2.list_entries()
        
        assert len(entries) == 2
        assert vault2.get_entry("entry1")["password"] == "pass1"
        assert vault2.get_entry("entry2")["password"] == "pass2"

    def test_change_empty_master_password(self, tmp_path: Path) -> None:
        """Test changing to empty master password."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "old_pass")
        
        with pytest.raises(ValueError):
            vault.change_master_password("")

    def test_vault_encryption(self, tmp_path: Path) -> None:
        """Test that vault file is encrypted."""
        vault_path = tmp_path / "test.vault"
        password = "test_password"
        
        vault = SecureVault(vault_path, "master_pass")
        vault.add_entry("test", password)
        
        # Read raw file content
        with open(vault_path, "rb") as f:
            content = f.read()
        
        # Password should not appear in plaintext
        assert password.encode() not in content
        assert b"test" not in content

    def test_multiple_entries(self, tmp_path: Path) -> None:
        """Test handling multiple entries."""
        vault_path = tmp_path / "test.vault"
        vault = SecureVault(vault_path, "master_pass")
        
        # Add 100 entries
        for i in range(100):
            vault.add_entry(f"entry_{i}", f"password_{i}")
        
        entries = vault.list_entries()
        assert len(entries) == 100
        
        # Verify a few
        assert vault.get_entry("entry_0")["password"] == "password_0"
        assert vault.get_entry("entry_50")["password"] == "password_50"
        assert vault.get_entry("entry_99")["password"] == "password_99"
