"""Tests for CLI interface."""

import pytest
from click.testing import CliRunner
from pathlib import Path

from passwordgen.cli import main


class TestCLI:
    """Test CLI commands."""

    def test_main_help(self) -> None:
        """Test main help command."""
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Secure Password and Passphrase Generator" in result.output

    def test_version(self) -> None:
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_generate_password(self) -> None:
        """Test generating a password."""
        runner = CliRunner()
        result = runner.invoke(main, ["generate"])
        assert result.exit_code == 0
        assert len(result.output.strip()) > 0

    def test_generate_password_custom_length(self) -> None:
        """Test generating password with custom length."""
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "--length", "20"])
        assert result.exit_code == 0
        password = result.output.strip()
        assert len(password) == 20

    def test_generate_password_no_symbols(self) -> None:
        """Test generating password without symbols."""
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "--no-symbols"])
        assert result.exit_code == 0

    def test_generate_password_show_entropy(self) -> None:
        """Test showing entropy information."""
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "--show-entropy"])
        assert result.exit_code == 0
        assert "Entropy:" in result.output
        assert "Strength:" in result.output

    def test_generate_multiple_passwords(self) -> None:
        """Test generating multiple passwords."""
        runner = CliRunner()
        result = runner.invoke(main, ["generate", "--count", "3"])
        assert result.exit_code == 0
        lines = result.output.strip().split("\n")
        assert len(lines) == 3

    def test_passphrase_generate(self) -> None:
        """Test generating a passphrase."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase"])
        assert result.exit_code == 0
        assert "-" in result.output

    def test_passphrase_custom_words(self) -> None:
        """Test generating passphrase with custom word count."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase", "--words", "4"])
        assert result.exit_code == 0
        passphrase = result.output.strip()
        assert len(passphrase.split("-")) == 4

    def test_passphrase_custom_separator(self) -> None:
        """Test passphrase with custom separator."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase", "--separator", "_"])
        assert result.exit_code == 0
        assert "_" in result.output

    def test_passphrase_capitalize(self) -> None:
        """Test passphrase with capitalization."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase", "--capitalize"])
        assert result.exit_code == 0

    def test_passphrase_with_number(self) -> None:
        """Test passphrase with number."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase", "--include-number"])
        assert result.exit_code == 0

    def test_passphrase_show_entropy(self) -> None:
        """Test passphrase with entropy display."""
        runner = CliRunner()
        result = runner.invoke(main, ["passphrase", "--show-entropy"])
        assert result.exit_code == 0
        assert "Entropy:" in result.output

    def test_audit_command(self) -> None:
        """Test audit command."""
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "TestPass123!"])
        assert result.exit_code == 0
        assert "Strength:" in result.output
        assert "Entropy:" in result.output
        assert "Score:" in result.output

    def test_audit_weak_password(self) -> None:
        """Test auditing a weak password."""
        runner = CliRunner()
        result = runner.invoke(main, ["audit", "password"])
        assert result.exit_code == 0
        assert "Security Issues:" in result.output or "Issues:" in result.output

    def test_hash_command_argon2(self) -> None:
        """Test hashing with Argon2."""
        runner = CliRunner()
        result = runner.invoke(main, ["hash", "testpass"], input="testpass\n")
        assert result.exit_code == 0
        assert "Hash:" in result.output
        assert "$argon2" in result.output

    def test_hash_command_bcrypt(self) -> None:
        """Test hashing with bcrypt."""
        runner = CliRunner()
        result = runner.invoke(main, ["hash", "testpass", "--algorithm", "bcrypt"])
        assert result.exit_code == 0
        assert "Hash:" in result.output
        assert "$2" in result.output

    def test_hash_command_scrypt(self) -> None:
        """Test hashing with scrypt."""
        runner = CliRunner()
        result = runner.invoke(main, ["hash", "testpass", "--algorithm", "scrypt"])
        assert result.exit_code == 0
        assert "Hash:" in result.output

    def test_entropy_command(self) -> None:
        """Test entropy calculation command."""
        runner = CliRunner()
        result = runner.invoke(main, ["entropy", "TestPass123!"])
        assert result.exit_code == 0
        assert "Entropy:" in result.output
        assert "Strength:" in result.output

    def test_vault_init(self, tmp_path: Path) -> None:
        """Test vault initialization."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        result = runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        assert result.exit_code == 0
        assert vault_path.exists()

    def test_vault_add(self, tmp_path: Path) -> None:
        """Test adding entry to vault."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        
        # Add entry
        result = runner.invoke(
            main,
            ["vault", "add", str(vault_path), "testentry"],
            input="masterpass\ntestpassword\n"
        )
        assert result.exit_code == 0

    def test_vault_add_with_generate(self, tmp_path: Path) -> None:
        """Test adding entry with generated password."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        
        # Add entry with generated password
        result = runner.invoke(
            main,
            ["vault", "add", str(vault_path), "testentry", "--generate"],
            input="masterpass\n"
        )
        assert result.exit_code == 0
        assert "Generated password:" in result.output

    def test_vault_list(self, tmp_path: Path) -> None:
        """Test listing vault entries."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault and add entry
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        runner.invoke(
            main,
            ["vault", "add", str(vault_path), "entry1"],
            input="masterpass\npass1\n"
        )
        
        # List entries
        result = runner.invoke(
            main,
            ["vault", "list", str(vault_path)],
            input="masterpass\n"
        )
        assert result.exit_code == 0
        assert "entry1" in result.output

    def test_vault_get(self, tmp_path: Path) -> None:
        """Test getting entry from vault."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault and add entry
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        runner.invoke(
            main,
            ["vault", "add", str(vault_path), "entry1"],
            input="masterpass\npass123\n"
        )
        
        # Get entry
        result = runner.invoke(
            main,
            ["vault", "get", str(vault_path), "entry1"],
            input="masterpass\n"
        )
        assert result.exit_code == 0
        assert "entry1" in result.output
        assert "pass123" in result.output

    def test_vault_delete(self, tmp_path: Path) -> None:
        """Test deleting entry from vault."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault and add entry
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        runner.invoke(
            main,
            ["vault", "add", str(vault_path), "entry1"],
            input="masterpass\npass123\n"
        )
        
        # Delete entry
        result = runner.invoke(
            main,
            ["vault", "delete", str(vault_path), "entry1"],
            input="masterpass\ny\n"
        )
        assert result.exit_code == 0

    def test_vault_init_existing(self, tmp_path: Path) -> None:
        """Test initializing vault that already exists."""
        runner = CliRunner()
        vault_path = tmp_path / "test.vault"
        
        # Create vault
        runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        
        # Try to create again
        result = runner.invoke(
            main,
            ["vault", "init", str(vault_path)],
            input="masterpass\nmasterpass\n"
        )
        assert result.exit_code == 1

    def test_verify_command_argon2(self) -> None:
        """Test verify command with Argon2."""
        runner = CliRunner()
        
        # First hash a password
        hash_result = runner.invoke(main, ["hash", "testpass"], input="testpass\n")
        hash_line = [line for line in hash_result.output.split("\n") if line.startswith("Hash:")][0]
        hash_str = hash_line.replace("Hash:", "").strip()
        
        # Verify correct password
        result = runner.invoke(
            main,
            ["verify"],
            input=f"testpass\n{hash_str}\n"
        )
        assert result.exit_code == 0
        assert "verified successfully" in result.output.lower()

    def test_verify_command_wrong_password(self) -> None:
        """Test verify command with wrong password."""
        runner = CliRunner()
        
        # First hash a password
        hash_result = runner.invoke(main, ["hash", "testpass"], input="testpass\n")
        hash_line = [line for line in hash_result.output.split("\n") if line.startswith("Hash:")][0]
        hash_str = hash_line.replace("Hash:", "").strip()
        
        # Verify wrong password
        result = runner.invoke(
            main,
            ["verify"],
            input=f"wrongpass\n{hash_str}\n"
        )
        assert result.exit_code == 1
        assert "failed" in result.output.lower()
