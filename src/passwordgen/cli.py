"""
Command-line interface for the secure password generator.

Provides comprehensive CLI with subcommands for:
- Password generation
- Passphrase generation
- Password auditing
- Entropy calculation
- Password hashing and verification
- Encrypted vault management
"""

import sys
from getpass import getpass
from pathlib import Path

import click

from passwordgen import __version__
from passwordgen.audit import PasswordAuditor
from passwordgen.crypto import SecureHasher
from passwordgen.entropy import calculate_password_entropy, entropy_to_strength, estimate_crack_time
from passwordgen.logging_secure import SecureLogger
from passwordgen.passphrase import PassphraseGenerator
from passwordgen.password import PasswordGenerator
from passwordgen.vault import SecureVault

# Initialize secure logger
logger = SecureLogger.get_logger("passwordgen.cli")


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """
    Secure Password and Passphrase Generator
    
    A cybersecurity-focused tool for generating secure passwords,
    analyzing password strength, and managing encrypted vaults.
    """
    pass


@main.command()
@click.option("--length", "-l", default=16, help="Password length (default: 16)")
@click.option("--no-uppercase", is_flag=True, help="Exclude uppercase letters")
@click.option("--no-lowercase", is_flag=True, help="Exclude lowercase letters")
@click.option("--no-digits", is_flag=True, help="Exclude digits")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols")
@click.option("--exclude-ambiguous", is_flag=True, help="Exclude ambiguous characters (0, O, 1, l, I)")
@click.option("--count", "-c", default=1, help="Number of passwords to generate")
@click.option("--show-entropy", is_flag=True, help="Show entropy information")
def generate(
    length: int,
    no_uppercase: bool,
    no_lowercase: bool,
    no_digits: bool,
    no_symbols: bool,
    exclude_ambiguous: bool,
    count: int,
    show_entropy: bool,
) -> None:
    """Generate secure random passwords."""
    try:
        gen = PasswordGenerator(
            length=length,
            uppercase=not no_uppercase,
            lowercase=not no_lowercase,
            digits=not no_digits,
            symbols=not no_symbols,
            exclude_ambiguous=exclude_ambiguous,
        )

        if show_entropy:
            click.echo(f"Entropy: {gen.entropy_bits:.2f} bits")
            click.echo(f"Strength: {entropy_to_strength(gen.entropy_bits)}")
            click.echo(f"Charset size: {len(gen.charset)}")
            click.echo(f"Estimated crack time: {estimate_crack_time(gen.entropy_bits)}")
            click.echo()

        passwords = gen.generate_multiple(count)
        for password in passwords:
            click.echo(password)

        logger.info(f"Generated {count} password(s)")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option("--words", "-w", default=6, help="Number of words (default: 6)")
@click.option("--separator", "-s", default="-", help="Word separator (default: -)")
@click.option("--capitalize", is_flag=True, help="Capitalize first letter of each word")
@click.option("--include-number", is_flag=True, help="Include random number (0-999)")
@click.option("--count", "-c", default=1, help="Number of passphrases to generate")
@click.option("--show-entropy", is_flag=True, help="Show entropy information")
def passphrase(
    words: int,
    separator: str,
    capitalize: bool,
    include_number: bool,
    count: int,
    show_entropy: bool,
) -> None:
    """Generate secure Diceware-style passphrases."""
    try:
        gen = PassphraseGenerator(
            word_count=words,
            separator=separator,
            capitalize=capitalize,
            include_number=include_number,
        )

        if show_entropy:
            click.echo(f"Entropy: {gen.entropy_bits:.2f} bits")
            click.echo(f"Strength: {entropy_to_strength(gen.entropy_bits)}")
            click.echo(f"Wordlist size: {gen.wordlist_size}")
            click.echo(f"Estimated crack time: {estimate_crack_time(gen.entropy_bits)}")
            click.echo()

        passphrases = gen.generate_multiple(count)
        for pp in passphrases:
            click.echo(pp)

        logger.info(f"Generated {count} passphrase(s)")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("password", required=False)
def audit(password: str) -> None:
    """Audit password strength and security."""
    try:
        # Get password from argument or prompt
        if not password:
            password = getpass("Enter password to audit: ")

        auditor = PasswordAuditor()
        result = auditor.audit(password)

        # Display results
        click.echo("\n=== Password Security Audit ===\n")
        click.echo(f"Strength: {result.strength}")
        click.echo(f"Entropy: {result.entropy_bits:.2f} bits")
        click.echo(f"Score: {result.score}/100")
        click.echo(f"Estimated crack time: {estimate_crack_time(result.entropy_bits)}")

        click.echo("\nCharacter Classes:")
        for char_class, present in result.character_classes.items():
            status = "✓" if present else "✗"
            click.echo(f"  {status} {char_class}")

        if result.issues:
            click.echo("\nSecurity Issues:")
            for issue in result.issues:
                click.echo(f"  • {issue}")

        if result.recommendations:
            click.echo("\nRecommendations:")
            for rec in result.recommendations:
                click.echo(f"  • {rec}")

        logger.info("Password audit completed")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("password", required=False)
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(["argon2", "bcrypt", "scrypt"], case_sensitive=False),
    default="argon2",
    help="Hashing algorithm (default: argon2)",
)
def hash(password: str, algorithm: str) -> None:
    """Hash a password using secure algorithms."""
    try:
        # Get password from argument or prompt
        if not password:
            password = getpass("Enter password to hash: ")

        hasher = SecureHasher()

        click.echo(f"Hashing with {algorithm}...")

        if algorithm == "argon2":
            hash_str = hasher.hash_argon2(password)
        elif algorithm == "bcrypt":
            hash_str = hasher.hash_bcrypt(password)
        elif algorithm == "scrypt":
            hash_str = hasher.hash_scrypt(password)
        else:
            click.echo(f"Unknown algorithm: {algorithm}", err=True)
            sys.exit(1)

        click.echo(f"\nHash: {hash_str}")
        logger.info(f"Password hashed with {algorithm}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("password", required=False)
@click.argument("hash_str", required=False)
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(["argon2", "bcrypt", "scrypt"], case_sensitive=False),
    help="Hashing algorithm (auto-detect if not specified)",
)
def verify(password: str, hash_str: str, algorithm: str) -> None:
    """Verify a password against a hash."""
    try:
        # Get password from argument or prompt
        if not password:
            password = getpass("Enter password: ")

        # Get hash from argument or prompt
        if not hash_str:
            hash_str = input("Enter hash: ")

        hasher = SecureHasher()

        # Auto-detect algorithm if not specified
        if not algorithm:
            if hash_str.startswith("$argon2"):
                algorithm = "argon2"
            elif hash_str.startswith("$2"):
                algorithm = "bcrypt"
            elif "$" in hash_str and len(hash_str.split("$")) == 5:
                algorithm = "scrypt"
            else:
                click.echo("Could not auto-detect algorithm. Please specify with --algorithm", err=True)
                sys.exit(1)

        # Verify
        if algorithm == "argon2":
            valid = hasher.verify_argon2(password, hash_str)
        elif algorithm == "bcrypt":
            valid = hasher.verify_bcrypt(password, hash_str)
        elif algorithm == "scrypt":
            valid = hasher.verify_scrypt(password, hash_str)
        else:
            click.echo(f"Unknown algorithm: {algorithm}", err=True)
            sys.exit(1)

        if valid:
            click.echo("✓ Password verified successfully")
            logger.info("Password verification successful")
        else:
            click.echo("✗ Password verification failed", err=True)
            logger.warning("Password verification failed")
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument("password", required=False)
def entropy(password: str) -> None:
    """Calculate entropy of a password."""
    try:
        # Get password from argument or prompt
        if not password:
            password = getpass("Enter password: ")

        entropy_bits = calculate_password_entropy(password)
        strength = entropy_to_strength(entropy_bits)
        crack_time = estimate_crack_time(entropy_bits)

        click.echo(f"\nEntropy: {entropy_bits:.2f} bits")
        click.echo(f"Strength: {strength}")
        click.echo(f"Estimated crack time: {crack_time}")

        logger.info("Entropy calculation completed")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@main.group()
def vault() -> None:
    """Manage encrypted password vault."""
    pass


@vault.command("init")
@click.argument("path")
def vault_init(path: str) -> None:
    """Initialize a new encrypted vault."""
    try:
        vault_path = Path(path)

        if vault_path.exists():
            click.echo(f"Vault already exists at {path}", err=True)
            sys.exit(1)

        # Get master password
        master_password = getpass("Enter master password: ")
        confirm_password = getpass("Confirm master password: ")

        if master_password != confirm_password:
            click.echo("Passwords do not match", err=True)
            sys.exit(1)

        # Create vault
        SecureVault(vault_path, master_password)
        click.echo(f"Vault created at {path}")
        logger.info(f"Vault initialized at {path}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@vault.command("add")
@click.argument("vault_path")
@click.argument("name")
@click.option("--password", "-p", help="Password to store (prompted if not provided)")
@click.option("--generate", is_flag=True, help="Generate a secure password")
@click.option("--length", "-l", default=16, help="Generated password length (default: 16)")
def vault_add(vault_path: str, name: str, password: str, generate: bool, length: int) -> None:
    """Add an entry to the vault."""
    try:
        # Get master password
        master_password = getpass("Enter vault master password: ")

        # Open vault
        v = SecureVault(Path(vault_path), master_password)

        # Get or generate password
        if generate:
            gen = PasswordGenerator(length=length)
            password = gen.generate()
            click.echo(f"Generated password: {password}")
        elif not password:
            password = getpass("Enter password to store: ")

        # Add entry
        v.add_entry(name, password)
        click.echo(f"Entry '{name}' added to vault")
        logger.info(f"Entry added to vault: {name}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@vault.command("get")
@click.argument("vault_path")
@click.argument("name")
def vault_get(vault_path: str, name: str) -> None:
    """Retrieve an entry from the vault."""
    try:
        # Get master password
        master_password = getpass("Enter vault master password: ")

        # Open vault
        v = SecureVault(Path(vault_path), master_password)

        # Get entry
        entry = v.get_entry(name)

        click.echo(f"\nEntry: {name}")
        click.echo(f"Password: {entry['password']}")
        click.echo(f"Created: {entry['created']}")
        click.echo(f"Modified: {entry['modified']}")

        if entry.get("metadata"):
            click.echo("Metadata:")
            for key, value in entry["metadata"].items():
                click.echo(f"  {key}: {value}")

        logger.info(f"Entry retrieved from vault: {name}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@vault.command("list")
@click.argument("vault_path")
def vault_list(vault_path: str) -> None:
    """List all entries in the vault."""
    try:
        # Get master password
        master_password = getpass("Enter vault master password: ")

        # Open vault
        v = SecureVault(Path(vault_path), master_password)

        # List entries
        entries = v.list_entries()

        if entries:
            click.echo(f"\nVault entries ({len(entries)}):")
            for entry_name in entries:
                click.echo(f"  • {entry_name}")
        else:
            click.echo("Vault is empty")

        logger.info(f"Listed {len(entries)} vault entries")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@vault.command("delete")
@click.argument("vault_path")
@click.argument("name")
def vault_delete(vault_path: str, name: str) -> None:
    """Delete an entry from the vault."""
    try:
        # Get master password
        master_password = getpass("Enter vault master password: ")

        # Open vault
        v = SecureVault(Path(vault_path), master_password)

        # Confirm deletion
        if not click.confirm(f"Delete entry '{name}'?"):
            click.echo("Cancelled")
            return

        # Delete entry
        v.delete_entry(name)
        click.echo(f"Entry '{name}' deleted")
        logger.info(f"Entry deleted from vault: {name}")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
