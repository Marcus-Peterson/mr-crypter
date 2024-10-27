import typer
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
from rich.console import Console
from rich.progress import Progress
import fitz  # PyMuPDF
import tempfile
from cryptography.fernet import InvalidToken
from io import BytesIO
import string
import codecs
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
    # Check if file exists
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: Specified file does not exist. Please provide a valid file path.", fg=typer.colors.RED)
        raise typer.Exit()

    key = authenticate()
    fernet = Fernet(key)

    shortcut = typer.prompt("Enter a shortcut name for this file")
    
    # File size for progress tracking
    file_size = file_path.stat().st_size
    chunk_size = 4096  # Encrypt and write in 4KB chunks

    with open(file_path, "rb") as file, Progress(console=console) as progress:
        task = progress.add_task("Encrypting...", total=file_size)
        
        # Reading and encrypting in chunks
        encrypted_data = bytearray()
        while chunk := file.read(chunk_size):
            encrypted_data.extend(fernet.encrypt(chunk))
            progress.update(task, advance=chunk_size)

    # Write encrypted data to the file
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

    record_encryption(file_path, shortcut)
    typer.secho(f"File '{file_path}' encrypted and recorded with shortcut '{shortcut}' successfully.", fg=typer.colors.GREEN)

@app.command()
def decrypt(shortcut_or_path: str):
    """Decrypt a file using its path or shortcut and remove it from the encrypted log."""
    key = authenticate()
    file_path = resolve_path(shortcut_or_path)
    
    # Verify that file exists before decryption
    if not file_path.exists() or not file_path.is_file():
        typer.secho("Error: Specified file does not exist. Please provide a valid file path or shortcut.", fg=typer.colors.RED)
        raise typer.Exit()
    
    fernet = Fernet(key)

    # File size for progress tracking
    file_size = file_path.stat().st_size

    # Read the encrypted data with progress feedback
    with Progress(console=console) as progress:
        task = progress.add_task("Decrypting...", total=file_size)
        
        # Read the entire encrypted file
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
            progress.update(task, advance=file_size)  # Update progress to full since we read the whole file

    # Decrypt the data
    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        typer.secho("Decryption failed. File may not be encrypted or is corrupted.", fg=typer.colors.RED)
        raise typer.Exit()

    # Write the decrypted data back with progress feedback
    with Progress(console=console) as progress:
        task = progress.add_task("Writing decrypted file...", total=len(decrypted_data))
        
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
            progress.update(task, advance=len(decrypted_data))  # Update progress to full after writing

    # Remove from log
    remove_from_log(file_path)
    typer.secho(f"File '{file_path}' decrypted and removed from log successfully.", fg=typer.colors.GREEN)

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

if __name__ == "__main__":
    app()
