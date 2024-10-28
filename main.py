#!/usr/bin/env python3
import typer
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from getpass import getpass
from pathlib import Path
import os
import base64
import hashlib
import csv
from rich.table import Table
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress
import fitz  # PyMuPDF
import tempfile
from cryptography.fernet import InvalidToken
from io import BytesIO
import string
import codecs
import pandas as pd
import base64
app = typer.Typer()

# Configuration constants
CONFIG_DIR = Path.home() / ".file_encryptor"
CONFIG_FILE = CONFIG_DIR / "config.hash"
SALT_FILE = CONFIG_DIR / "salt.key"
TRACKING_FILE = CONFIG_DIR / "encrypted_files.csv"
ITERATIONS = 100_000  # Number of iterations for hashing
console = Console()

def create_salt() -> bytes:
    """Generate a new salt and save it."""
    salt = os.urandom(16)
    CONFIG_DIR.mkdir(exist_ok=True)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt

def load_salt() -> bytes:
    """Load the salt or create a new one if it doesn't exist."""
    if SALT_FILE.exists():
        with open(SALT_FILE, "rb") as f:
            return f.read()
    return create_salt()

def hash_password(password: str) -> bytes:
    """Hash the password using PBKDF2 and a salt."""
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(password.encode())

def store_password_hash(password_hash: bytes):
    """Store the password hash."""
    with open(CONFIG_FILE, "wb") as f:
        f.write(password_hash)

def authenticate() -> bytes:
    """Prompt for the password and authenticate the user."""
    password = getpass("Enter your password: ")
    password_hash = hash_password(password)

    # Check the stored hash
    if not CONFIG_FILE.exists():
        store_password_hash(password_hash)  # Save hash for first-time setup
        typer.echo("New password set and securely stored.")
    else:
        with open(CONFIG_FILE, "rb") as f:
            stored_hash = f.read()
        if stored_hash != password_hash:
            typer.secho("Authentication failed. Incorrect password.", fg=typer.colors.RED)
            raise typer.Exit()

    # Use derived key for encryption and decryption
    return base64.urlsafe_b64encode(password_hash)

def record_encryption(file_path: Path, shortcut: str):
    """Record encrypted file details to the tracking CSV if not already recorded, with a shortcut."""
    CONFIG_DIR.mkdir(exist_ok=True)

    # Check if the file or shortcut is already recorded to avoid duplicates
    if TRACKING_FILE.exists():
        with open(TRACKING_FILE, "r") as csvfile:
            csv_reader = csv.reader(csvfile)
            for row in csv_reader:
                if row[1] == str(file_path.resolve()) or row[2] == shortcut:
                    typer.secho("File or shortcut already exists in the log.", fg=typer.colors.RED)
                    return

    # Record file details with shortcut
    with open(TRACKING_FILE, mode="a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow([file_path.name, str(file_path.resolve()), shortcut])

def remove_from_log(file_path: Path):
    """Remove a specific file entry from the tracking CSV."""
    if not TRACKING_FILE.exists():
        return
    
    # Read all entries except the one to delete
    rows_to_keep = []
    with open(TRACKING_FILE, "r") as csvfile:
        csv_reader = csv.reader(csvfile)
        rows_to_keep = [row for row in csv_reader if row[1] != str(file_path.resolve())]

    # Write the remaining entries back to the file
    with open(TRACKING_FILE, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerows(rows_to_keep)

def resolve_path(shortcut_or_path: str) -> Path:
    """Resolve a shortcut or file path to the actual file path."""
    if not TRACKING_FILE.exists():
        return Path(shortcut_or_path)
    
    with open(TRACKING_FILE, "r") as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            if row[2] == shortcut_or_path:  # Check if input is a shortcut
                return Path(row[1])
    
    return Path(shortcut_or_path)

@app.command()
def encrypt(file_path: Path):
    """Encrypt a file with a progress bar and record it with a shortcut name."""
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: Specified file does not exist.", fg=typer.colors.RED)
        raise typer.Exit()

    key = authenticate()
    fernet = Fernet(key)
    shortcut = typer.prompt("Enter a shortcut name for this file")
    
    file_size = file_path.stat().st_size

    with Progress(console=console) as progress:
        task = progress.add_task("Encrypting...", total=file_size)
        
        # Read the entire file as binary
        with open(file_path, "rb") as file:
            data = file.read()
            progress.update(task, advance=file_size)

        # Encrypt the entire binary data at once
        encrypted_data = fernet.encrypt(data)
        
        # Write the encrypted data
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

    record_encryption(file_path, shortcut)
    typer.secho(f"File encrypted and recorded with shortcut '{shortcut}'.", fg=typer.colors.GREEN)

@app.command()
def decrypt(shortcut_or_path: str):
    """Decrypt a file using its path or shortcut."""
    key = authenticate()
    file_path = resolve_path(shortcut_or_path)
    
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: File does not exist.", fg=typer.colors.RED)
        raise typer.Exit()
    
    fernet = Fernet(key)
    file_size = file_path.stat().st_size

    with Progress(console=console) as progress:
        task = progress.add_task("Decrypting...", total=file_size)
        
        # Read the encrypted data
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
            progress.update(task, advance=file_size)

        try:
            # Decrypt the entire binary data at once
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken:
            typer.secho("Decryption failed. File may not be encrypted or is corrupted.", fg=typer.colors.RED)
            raise typer.Exit()

        # Write the decrypted data
        with open(file_path, "wb") as file:
            file.write(decrypted_data)

    remove_from_log(file_path)
    typer.secho(f"File decrypted successfully.", fg=typer.colors.GREEN)

@app.command()
def view(shortcut_or_path: str):
    """Temporarily decrypt and view a file's content using its path or shortcut."""
    key = authenticate()
    file_path = resolve_path(shortcut_or_path)
    
    # Verify that file exists before viewing
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: Specified file does not exist. Please provide a valid file path or shortcut.", fg=typer.colors.RED)
        raise typer.Exit()

    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
        typer.echo(decrypted_data.decode())  # Display content
    except Exception:
        typer.secho("Decryption failed. File may not be encrypted or is corrupted.", fg=typer.colors.RED)
        raise typer.Exit()

@app.command()
def search(
    query: str = typer.Argument(..., help="Search term to filter files"),
    search_shortcuts: bool = typer.Option(True, "--shortcuts/--no-shortcuts", help="Include shortcuts in search"),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", help="Make search case-sensitive")
) -> None:
    """Search through encrypted files by filename or shortcut."""
    try:
        # Read CSV with proper column names
        files_df = pd.read_csv(TRACKING_FILE, names=['filename', 'filepath', 'shortcut'])
        
        # Prepare search query
        if not case_sensitive:
            query = query.lower()
            files_df['filename'] = files_df['filename'].str.lower()
            files_df['shortcut'] = files_df['shortcut'].str.lower()
        
        # Create mask for filename matches
        mask = files_df['filename'].str.contains(query, na=False)
        
        # Add shortcut matches if enabled
        if search_shortcuts:
            mask |= files_df['shortcut'].str.contains(query, na=False)
        
        # Filter results
        results = files_df[mask]
        
        if len(results) == 0:
            rprint(f"[yellow]No files found matching '{query}'[/yellow]")
            return
        
        # Display results in a table
        table = Table(title=f"Search Results for '{query}'")
        table.add_column("Filename", style="cyan")
        table.add_column("Shortcut", style="green")
        table.add_column("Encrypted Path", style="blue")
        
        for _, row in results.iterrows():
            table.add_row(
                row['filename'],
                row['shortcut'],
                row['filepath']
            )
        
        rprint(table)
        
    except FileNotFoundError:
        rprint("[red]No encrypted files found. Encrypt some files first.[/red]")
    except Exception as e:
        rprint(f"[red]Error searching files: {str(e)}[/red]")

@app.command()
def list_files():
    """List all files encrypted by this program with pretty formatting."""
    if not TRACKING_FILE.exists():
        typer.secho("No encrypted files recorded.", fg=typer.colors.YELLOW)
        return
    
    table = Table(title="Encrypted Files")
    table.add_column("File Name", style="cyan", no_wrap=True)
    table.add_column("Location", style="magenta")
    table.add_column("Shortcut", style="green")

    with open(TRACKING_FILE, mode="r") as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            table.add_row(row[0], row[1], row[2])
    
    console.print(table)

@app.command()
def clear_log():
    """Clear all entries in the encrypted files log."""
    if TRACKING_FILE.exists():
        os.remove(TRACKING_FILE)
        typer.secho("All entries in the encrypted files log have been cleared.", fg=typer.colors.GREEN)
    else:
        typer.secho("No encrypted files recorded.", fg=typer.colors.YELLOW)

@app.command()
def insert(shortcut_or_path: str, text: str, line: int = 1):
    """Insert text into a specific line of an encrypted file."""
    key = authenticate()
    file_path = resolve_path(shortcut_or_path)
    
    # Verify that file exists
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: Specified file does not exist. Please provide a valid file path or shortcut.", fg=typer.colors.RED)
        raise typer.Exit()

    fernet = Fernet(key)

    # Read and decrypt the file
    with open(file_path, "rb") as file:
        encrypted_data = file.read()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except InvalidToken:
        typer.secho("Decryption failed. File may not be encrypted or is corrupted.", fg=typer.colors.RED)
        raise typer.Exit()

    try:
        # Convert bytes to string and split into lines
        content = decrypted_data.decode('utf-8').splitlines()
        
        # Ensure line number is valid
        if line < 1:
            line = 1
        if line > len(content) + 1:
            line = len(content) + 1

        # Insert the text at the specified line (adjusting for 0-based index)
        content.insert(line - 1, text)
        
        # Join the lines back together
        modified_content = '\n'.join(content)
        
        # Encrypt the modified content
        encrypted_data = fernet.encrypt(modified_content.encode('utf-8'))
        
        # Save the modified file
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

        typer.secho(f"Text successfully inserted at line {line}.", fg=typer.colors.GREEN)

    except UnicodeDecodeError:
        typer.secho("The file appears to be binary or not a text file.", fg=typer.colors.RED)
        raise typer.Exit()
    except Exception as e:
        typer.secho(f"Failed to insert text: {e}", fg=typer.colors.RED)
        raise typer.Exit()

@app.command()
def help(command: Optional[str] = typer.Argument(None, help="Command to get help for")):
    """Show help information for a specific command or list all commands with their descriptions."""
    if command is None:
        # Create a table for all commands
        table = Table(title="File Encryptor Commands")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description", style="green")
        table.add_column("Usage", style="yellow")

        commands = {
            "encrypt": ("Encrypt a file with password protection", "encrypt FILE_PATH"),
            "decrypt": ("Decrypt a previously encrypted file", "decrypt FILE_PATH|SHORTCUT"),
            "view": ("Temporarily decrypt and view file contents", "view FILE_PATH|SHORTCUT"),
            "search": ("Search through encrypted files", "search QUERY [--shortcuts/--no-shortcuts] [--case-sensitive]"),
            "list-files": ("List all encrypted files", "list-files"),
            "clear-log": ("Clear the encrypted files log", "clear-log"),
            "insert": ("Insert text into an encrypted file", "insert FILE_PATH|SHORTCUT \"TEXT\" [LINE]"),
            "help": ("Show this help message", "help [COMMAND]")
        }

        for cmd_name, (desc, usage) in commands.items():
            table.add_row(cmd_name, desc, usage)

        console.print(table)
        
        # Print additional information
        console.print("\n[bold]Notes:[/bold]")
        console.print("• FILE_PATH can be the actual path to a file")
        console.print("• SHORTCUT is the name you gave to the file during encryption")
        console.print("• All commands will prompt for your password when needed")
        console.print("\nFor detailed help on a specific command, use: [cyan]python main.py help COMMAND[/cyan]")
        
    else:
        # Show detailed help for specific command
        command = command.lower()
        detailed_help = {
            "encrypt": {
                "description": "Encrypt a file with password protection",
                "usage": "encrypt FILE_PATH",
                "details": [
                    "• Encrypts the specified file using your password",
                    "• Prompts for a shortcut name to easily reference the file later",
                    "• Original file is replaced with encrypted version",
                    "• Records the encryption details in the tracking file"
                ]
            },
            "decrypt": {
                "description": "Decrypt a previously encrypted file",
                "usage": "decrypt FILE_PATH|SHORTCUT",
                "details": [
                    "• Decrypts the specified file using your password",
                    "• Can use either the file path or the shortcut name",
                    "• Original encrypted file is replaced with decrypted version",
                    "• Removes the file from the tracking log"
                ]
            },
            "view": {
                "description": "Temporarily decrypt and view file contents",
                "usage": "view FILE_PATH|SHORTCUT",
                "details": [
                    "• Shows the decrypted contents of the file",
                    "• Does not modify the original encrypted file",
                    "• Can use either the file path or the shortcut name"
                ]
            },
            "search": {
                "description": "Search through encrypted files",
                "usage": "search QUERY [--shortcuts/--no-shortcuts] [--case-sensitive]",
                "details": [
                    "• Searches through filenames and shortcuts",
                    "• --shortcuts: Include shortcuts in search (default: yes)",
                    "• --no-shortcuts: Exclude shortcuts from search",
                    "• --case-sensitive: Make search case-sensitive (default: no)"
                ]
            },
            "insert": {
                "description": "Insert text into an encrypted file",
                "usage": "insert FILE_PATH|SHORTCUT \"TEXT\" [LINE]",
                "details": [
                    "• Temporarily decrypts the file",
                    "• Inserts the specified text at the given line number",
                    "• Line number is optional (defaults to line 1)",
                    "• Re-encrypts the file after insertion"
                ]
            }
        }

        if command not in detailed_help:
            typer.secho(f"No detailed help available for '{command}'", fg=typer.colors.RED)
            typer.secho("\nAvailable commands:", fg=typer.colors.YELLOW)
            typer.secho("python main.py help", fg=typer.colors.GREEN)
            return

        help_info = detailed_help[command]
        console.print(f"\n[bold cyan]{command}[/bold cyan]")
        console.print(f"\n[bold]Description:[/bold] {help_info['description']}")
        console.print(f"\n[bold]Usage:[/bold] python main.py {help_info['usage']}")
        console.print("\n[bold]Details:[/bold]")
        for detail in help_info['details']:
            console.print(detail)

if __name__ == "__main__":
    app()
