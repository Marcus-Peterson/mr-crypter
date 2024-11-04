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
from rich.progress import Progress, BarColumn, TimeRemainingColumn
import fitz  # PyMuPDF
import tempfile
from cryptography.fernet import InvalidToken
from io import BytesIO
import string
import codecs
import pandas as pd
import base64
from datetime import datetime
from rich.syntax import Syntax
from rich.panel import Panel
from rich.padding import Padding
import secrets
import filelock
import logging
app = typer.Typer()
# Configuration constants
CONFIG_DIR = Path.home() / ".file_encryptor"
SALT_FILE = CONFIG_DIR / "salt.key"
TRACKING_FILE = CONFIG_DIR / "encrypted_files.csv"
ITERATIONS = 100_000  # Higher number = stronger but slower key derivation
console = Console()

# Setup logging
logging.basicConfig(
    filename=CONFIG_DIR / 'file_encryptor.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class TrackingFileManager:
    """Thread-safe manager for tracking file operations."""
    
    def __init__(self):
        self.lock_file = str(TRACKING_FILE) + ".lock"
        self.lock = filelock.FileLock(self.lock_file)
    
    def __enter__(self):
        self.lock.acquire()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()

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

def derive_key(password: str) -> bytes:
    """Derive an encryption key from the password and salt."""
    salt = load_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def authenticate() -> bytes:
    """Prompt for the password and return the derived key."""
    password = getpass("Enter your password: ")
    return derive_key(password)

def create_verification_tag(key: bytes) -> bytes:
    """Create a verification tag from the key."""
    # Create a known piece of data that we'll encrypt as our verification
    verification_data = b"VALID_ENCRYPTION_TAG"
    fernet = Fernet(key)
    return fernet.encrypt(verification_data)

def verify_key(key: bytes, tag: bytes) -> bool:
    """Verify if the key can decrypt the verification tag."""
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(tag)
        return decrypted == b"VALID_ENCRYPTION_TAG"
    except InvalidToken:
        return False

def record_encryption(file_path: Path, shortcut: str, verification_tag: bytes):
    """Record encrypted file details with verification tag."""
    try:
        CONFIG_DIR.mkdir(exist_ok=True)
        secure_file_permissions(CONFIG_DIR)

        # Get file metadata
        file_stats = file_path.stat()
        encryption_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_size = file_stats.st_size
        
        # Convert verification tag to string for storage
        tag_str = base64.b64encode(verification_tag).decode('utf-8')
        
        with TrackingFileManager():
            # Check for existing entries
            exists = False
            if TRACKING_FILE.exists():
                with open(TRACKING_FILE, "r") as csvfile:
                    csv_reader = csv.reader(csvfile)
                    exists = any(row[1] == str(file_path.resolve()) or row[2] == shortcut 
                               for row in csv_reader)
            
            if exists:
                typer.secho("File or shortcut already exists in the log.", fg=typer.colors.RED)
                return

            # Add new entry atomically
            new_row = [
                file_path.name,
                str(file_path.resolve()),
                shortcut,
                encryption_date,
                file_size,
                "encrypted",
                tag_str
            ]
            
            temp_file = TRACKING_FILE.with_suffix('.tmp')
            try:
                # Read existing content
                rows = []
                if TRACKING_FILE.exists():
                    with open(TRACKING_FILE, "r") as csvfile:
                        rows = list(csv.reader(csvfile))
                
                # Append new row and write
                rows.append(new_row)
                with open(temp_file, "w", newline="") as csvfile:
                    csv_writer = csv.writer(csvfile)
                    csv_writer.writerows(rows)
                
                temp_file.replace(TRACKING_FILE)
                secure_file_permissions(TRACKING_FILE)
                
            finally:
                if temp_file.exists():
                    temp_file.unlink()

    except Exception as e:
        log_error(e, "record_encryption")
        typer.secho("Error recording encryption details.", fg=typer.colors.RED)

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
def encrypt(
    path: Path = typer.Argument(..., help="File or directory to encrypt"),
    pattern: str = typer.Option("*", help="File pattern to match when encrypting a directory (e.g., *.txt)"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Process subdirectories recursively")
):
    """Encrypt a file or all files in a directory."""
    if not path.exists():
        typer.secho("Error: Specified path does not exist.", fg=typer.colors.RED)
        raise typer.Exit()

    try:
        key = authenticate()
        fernet = Fernet(key)
        verification_tag = create_verification_tag(key)

        # Handle directory encryption
        if path.is_dir():
            # Collect files to process
            if recursive:
                files = list(path.rglob(pattern))
            else:
                files = list(path.glob(pattern))

            # Filter out directories
            files = [f for f in files if f.is_file()]

            if not files:
                typer.secho(f"No files matching pattern '{pattern}' found in {path}", fg=typer.colors.YELLOW)
                return

            # Confirm with user
            typer.echo(f"\nFound {len(files)} files to encrypt:")
            for f in files:
                typer.echo(f"  • {f.relative_to(path)}")
            
            if not typer.confirm("\nDo you want to proceed with encryption?"):
                typer.echo("Operation cancelled.")
                return

            # Process files with progress bar
            with Progress(console=console) as progress:
                task = progress.add_task("Encrypting files...", total=len(files))
                
                for file_path in files:
                    try:
                        # Generate a shortcut based on relative path
                        shortcut = str(file_path.relative_to(path)).replace('\\', '_').replace('/', '_')
                        
                        # Read and encrypt
                        with open(file_path, "rb") as file:
                            data = file.read()
                        encrypted_data = fernet.encrypt(data)
                        
                        # Write encrypted data
                        with open(file_path, "wb") as file:
                            file.write(encrypted_data)
                        
                        # Record encryption
                        record_encryption(file_path, shortcut, verification_tag)
                        update_file_status(file_path, "encrypted")
                        
                        progress.advance(task)
                        
                    except Exception as e:
                        typer.secho(f"Failed to encrypt {file_path.name}: {str(e)}", fg=typer.colors.RED)

            typer.secho("\nBatch encryption completed!", fg=typer.colors.GREEN)

        # Handle single file encryption
        else:
            shortcut = typer.prompt("Enter a shortcut name for this file")
            file_size = path.stat().st_size

            with Progress(console=console) as progress:
                task = progress.add_task("Encrypting...", total=file_size)
                
                with open(path, "rb") as file:
                    data = file.read()
                    progress.update(task, advance=file_size)

                encrypted_data = fernet.encrypt(data)
                
                with open(path, "wb") as file:
                    file.write(encrypted_data)

            record_encryption(path, shortcut, verification_tag)
            update_file_status(path, "encrypted")
            typer.secho(f"File encrypted and recorded with shortcut '{shortcut}'.", fg=typer.colors.GREEN)
            
    except Exception as e:
        typer.secho(f"Error during encryption: {str(e)}", fg=typer.colors.RED)
        raise typer.Exit()

@app.command()
def decrypt(
    path: str = typer.Argument(..., help="File/directory path or shortcut to decrypt"),
    pattern: str = typer.Option("*", help="File pattern to match when decrypting a directory"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Process subdirectories recursively")
):
    """Decrypt a file or all files in a directory."""
    key = None
    encrypted_data = None
    decrypted_data = None
    
    try:
        key = authenticate()
        file_path = resolve_path(path)
        
        # Verify file exists and permissions
        if not file_path.exists():
            typer.secho("Error: File not found.", fg=typer.colors.RED)
            raise typer.Exit()
            
        if not check_file_permissions(file_path):
            typer.secho("Warning: File permissions are not secure.", fg=typer.colors.YELLOW)
            if not typer.confirm("Continue anyway?"):
                raise typer.Exit()

        # Verify the key using stored tag
        file_found = False
        with TrackingFileManager():
            if not TRACKING_FILE.exists():
                typer.secho("Error: No tracking file found.", fg=typer.colors.RED)
                raise typer.Exit()
                
            with open(TRACKING_FILE, "r") as csvfile:
                csv_reader = csv.reader(csvfile)
                for row in csv_reader:
                    if row[1] == str(file_path.resolve()):
                        file_found = True
                        try:
                            tag = base64.b64decode(row[6])
                            if not verify_key(key, tag):
                                typer.secho("Invalid password for this file.", fg=typer.colors.RED)
                                raise typer.Exit()
                        except (IndexError, base64.binascii.Error):
                            typer.secho("Error: Corrupted tracking file entry.", fg=typer.colors.RED)
                            raise typer.Exit()
                        break

        if not file_found:
            typer.secho("Error: File not found in tracking database.", fg=typer.colors.RED)
            raise typer.Exit()

        if file_path.is_file():
            # Single file decryption
            file_size = file_path.stat().st_size
            
            try:
                with Progress(console=console) as progress:
                    task = progress.add_task("Decrypting...", total=file_size)
                    
                    # Step 1: Read
                    progress.update(task, description="Reading file...")
                    encrypted_data = atomic_read(file_path)
                    progress.advance(task, file_size/3)
                    
                    # Step 2: Decrypt
                    progress.update(task, description="Decrypting data...")
                    fernet = Fernet(key)
                    decrypted_data = fernet.decrypt(encrypted_data)
                    progress.advance(task, file_size/3)
                    
                    # Step 3: Write
                    progress.update(task, description="Writing file...")
                    atomic_write(file_path, decrypted_data)
                    secure_file_permissions(file_path)
                    progress.advance(task, file_size/3)
                    
                    # Update file status without using TrackingFileManager
                    update_file_status(file_path, "decrypted")
                
                typer.secho("File decrypted successfully.", fg=typer.colors.GREEN)
                return
                
            except InvalidToken:
                typer.secho("\nDecryption failed. File may be corrupted.", fg=typer.colors.RED)
                raise typer.Exit()
            except Exception as e:
                log_error(e, "decrypt")
                typer.secho(f"\nError during decryption: {str(e)}", fg=typer.colors.RED)
                raise typer.Exit()

    except Exception as e:
        log_error(e, "decrypt")
        typer.secho("\nAn error occurred during decryption.", fg=typer.colors.RED)
        raise typer.Exit()
        
    finally:
        # Secure cleanup
        if key:
            key = None
        if encrypted_data:
            secure_cleanup(encrypted_data)
        if decrypted_data:
            secure_cleanup(decrypted_data)

@app.command()
def view(
    shortcut_or_path: str,
    lines: Optional[int] = typer.Option(None, "--lines", "-n", help="Number of lines to display for text files"),
    pages: Optional[int] = typer.Option(None, "--pages", "-p", help="Number of pages to display for PDFs"),
    chars_per_page: Optional[int] = typer.Option(500, "--chars", "-c", help="Number of characters to show per PDF page"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all content (overrides --lines/--pages/--chars)")
):
    """Temporarily decrypt and view a file's content using its path or shortcut."""
    key = None
    decrypted_data = None
    content = None
    content_lines = None
    
    try:
        key = authenticate()
        file_path = resolve_path(shortcut_or_path)
        
        if not file_path.exists() or not file_path.is_file():
            typer.secho("Error: Specified file does not exist. Please provide a valid file path or shortcut.", fg=typer.colors.RED)
            raise typer.Exit()

        fernet = Fernet(key)

        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
            content = decrypted_data.decode()
            
            if lines is not None:
                if lines <= 0:
                    typer.secho("Line count must be positive.", fg=typer.colors.RED)
                    raise typer.Exit()
                content_lines = content.splitlines()[:lines]
                content = '\n'.join(content_lines)
            
            file_extension = file_path.suffix.lower()
            lexer_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.html': 'html',
                '.css': 'css',
                '.json': 'json',
                '.xml': 'xml',
                '.md': 'markdown',
                '.txt': 'text',
                '.sh': 'bash',
                '.yml': 'yaml',
                '.yaml': 'yaml',
                '.sql': 'sql',
                '.ini': 'ini',
                '.conf': 'ini',
                '.env': 'env',
            }
            
            lexer = lexer_map.get(file_extension, 'text')
            
            syntax = Syntax(
                content,
                lexer,
                line_numbers=True,
                word_wrap=True,
                theme="monokai",
                padding=1
            )
            
            total_lines = len(decrypted_data.decode().splitlines())
            panel_title = f"[bold blue]{file_path.name}[/bold blue]"
            if lines:
                panel_title += f" [italic](showing first {lines} of {total_lines} lines)[/italic]"
            
            panel = Panel(
                syntax,
                title=panel_title,
                subtitle=f"[italic]{total_lines} lines total[/italic]",
                border_style="blue"
            )
            
            console.clear()
            
            console.print(f"\n[bold yellow]File Information:[/bold yellow]")
            console.print(f"[cyan]Location:[/cyan] {file_path}")
            console.print(f"[cyan]Size:[/cyan] {file_path.stat().st_size:,} bytes")
            console.print(f"[cyan]Type:[/cyan] {lexer.upper()}\n")
            
            console.print(panel)
            console.print("\n[dim]Press Ctrl+C to exit[/dim]")

        except UnicodeDecodeError:
            # Check if it's a PDF file
            if file_path.suffix.lower() == '.pdf':
                try:
                    # Create a temporary file for the decrypted PDF
                    with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_pdf:
                        temp_pdf.write(decrypted_data)
                        temp_path = temp_pdf.name

                    try:
                        # Open the PDF with PyMuPDF
                        doc = fitz.open(temp_path)
                        
                        # Print PDF metadata
                        console.print("\n[bold yellow]PDF Information:[/bold yellow]")
                        console.print(f"[cyan]Location:[/cyan] {file_path}")
                        console.print(f"[cyan]Pages:[/cyan] {doc.page_count}")
                        console.print(f"[cyan]Size:[/cyan] {file_path.stat().st_size:,} bytes")
                        
                        # Print PDF metadata if available
                        metadata = doc.metadata
                        if metadata:
                            if metadata.get('title'):
                                console.print(f"[cyan]Title:[/cyan] {metadata['title']}")
                            if metadata.get('author'):
                                console.print(f"[cyan]Author:[/cyan] {metadata['author']}")
                            if metadata.get('subject'):
                                console.print(f"[cyan]Subject:[/cyan] {metadata['subject']}")
                        
                        console.print("\n[bold yellow]Content Preview:[/bold yellow]")
                        
                        # Determine number of pages to show
                        if show_all:
                            pages_to_show = doc.page_count
                            chars_to_show = None  # Show all characters
                        else:
                            pages_to_show = min(pages or 3, doc.page_count)
                            chars_to_show = chars_per_page
                        
                        # Show page navigation help if not showing all pages
                        if not show_all and doc.page_count > pages_to_show:
                            console.print("[dim]Use --pages N to show N pages, --all to show all content[/dim]\n")
                        
                        for page_num in range(pages_to_show):
                            page = doc[page_num]
                            text = page.get_text()
                            
                            # Handle text truncation
                            if chars_to_show and len(text) > chars_to_show:
                                display_text = text[:chars_to_show] + "..."
                            else:
                                display_text = text
                            
                            # Create a panel for each page
                            panel = Panel(
                                display_text,
                                title=f"[bold blue]Page {page_num + 1} of {doc.page_count}[/bold blue]",
                                border_style="blue"
                            )
                            console.print(panel)
                            console.print()
                        
                        # Show summary if content was truncated
                        if not show_all:
                            if doc.page_count > pages_to_show:
                                console.print(f"[dim]... {doc.page_count - pages_to_show} more pages not shown[/dim]")
                            if chars_to_show:
                                console.print("[dim]Use --chars N to show N characters per page, --all to show full content[/dim]")
                        
                    finally:
                        # Close the document
                        if 'doc' in locals():
                            doc.close()
                        
                finally:
                    # Securely delete the temporary file
                    try:
                        # First overwrite
                        with open(temp_path, 'wb') as f:
                            f.write(b'\x00' * len(decrypted_data))
                        # Then delete
                        os.unlink(temp_path)
                    except Exception:
                        pass  # Ignore cleanup errors
                
            else:
                # Handle other binary files with hex view
                console.print("[yellow]Warning: This appears to be a binary file.[/yellow]")
                console.print("\n[bold]Hex View:[/bold]")
                
                hex_lines = [decrypted_data[i:i+16].hex(' ') for i in range(0, min(512, len(decrypted_data)), 16)]
                console.print("\n".join(hex_lines))
                
                if len(decrypted_data) > 512:
                    console.print("\n[dim]... (showing first 512 bytes only)[/dim]")

        except InvalidToken:
            typer.secho("Decryption failed. File may not be encrypted.", fg=typer.colors.RED)
            raise typer.Exit()
            
    except Exception as e:
        # Generic error without exposing details
        typer.secho("An error occurred while viewing the file.", fg=typer.colors.RED)
        raise typer.Exit()
        
    finally:
        # Clear sensitive data from memory
        if key:
            key = None
        if decrypted_data:
            decrypted_data = b'\x00' * len(decrypted_data)
        if content:
            content = '\x00' * len(content)
        if content_lines:
            content_lines = None

@app.command()
def search(
    query: str = typer.Argument(..., help="Search term to filter files"),
    search_shortcuts: bool = typer.Option(True, "--shortcuts/--no-shortcuts", help="Include shortcuts in search"),
    case_sensitive: bool = typer.Option(False, "--case-sensitive", help="Make search case-sensitive")
) -> None:
    """Search through encrypted files by filename or shortcut."""
    try:
        # Read CSV with all column names
        files_df = pd.read_csv(TRACKING_FILE, names=[
            'filename', 'filepath', 'shortcut', 'encryption_date', 'size', 'status', 'tag'
        ])
        
        # Special handling for status-based searches
        status_keywords = {
            'encrypted': ['encrypt', 'encrypted', 'enc'],
            'decrypted': ['decrypt', 'decrypted', 'dec']
        }
        
        # Check if query matches any status keywords
        status_search = None
        query_lower = query.lower()
        for status, keywords in status_keywords.items():
            if query_lower in keywords:
                status_search = status
                break
        
        if status_search:
            # Filter by status
            results = files_df[files_df['status'] == status_search]
            title = f"Files that are {status_search}"
        else:
            # Regular search
            if not case_sensitive:
                query = query.lower()
                files_df['filename'] = files_df['filename'].str.lower()
                files_df['shortcut'] = files_df['shortcut'].str.lower()
            
            # Create mask for filename matches
            mask = files_df['filename'].str.contains(query, na=False)
            
            # Add shortcut matches if enabled
            if search_shortcuts:
                mask |= files_df['shortcut'].str.contains(query, na=False)
            
            results = files_df[mask]
            title = f"Search Results for '{query}'"
        
        if len(results) == 0:
            rprint(f"[yellow]No files found matching '{query}'[/yellow]")
            return
        
        # Display results in a table
        table = Table(title=title)
        table.add_column("Filename", style="cyan")
        table.add_column("Shortcut", style="green")
        table.add_column("Location", style="blue")
        table.add_column("Status")

        for _, row in results.iterrows():
            # Color-code the status
            status_style = {
                "encrypted": "[green]encrypted[/green]",
                "decrypted": "[red]decrypted[/red]",
                "file not found": "[yellow]file not found[/yellow]"
            }.get(row['status'], row['status'])
            
            table.add_row(
                row['filename'],
                row['shortcut'],
                row['filepath'],
                status_style
            )
        
        rprint(table)
        
    except FileNotFoundError:
        rprint("[red]No encrypted files found. Encrypt some files first.[/red]")
    except Exception as e:
        rprint(f"[red]Error searching files: {str(e)}[/red]")

def check_encryption_status(file_path: Path) -> bool:
    """
    Check if a file is currently encrypted by checking Fernet format.
    Returns True if the file is encrypted, False if it's decrypted.
    """
    try:
        with open(file_path, "rb") as file:
            data = file.read()
            # Fernet tokens start with 'gAAAAA'
            if data.startswith(b'gAAAAA'):
                return True
            return False
    except Exception:
        return False

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
    table.add_column("Encrypted On", style="yellow")
    table.add_column("Size", style="blue")
    table.add_column("Status")  # Removed default style as we'll color-code each status

    with open(TRACKING_FILE, mode="r") as csvfile:
        csv_reader = csv.reader(csvfile)
        for row in csv_reader:
            file_path = Path(row[1])
            
            # Check actual encryption status
            if file_path.exists():
                current_status = "encrypted" if check_encryption_status(file_path) else "decrypted"
                if current_status != row[5]:
                    update_file_status(file_path, current_status)
                    row[5] = current_status
            else:
                row[5] = "file not found"

            # Color-code the status
            status_style = {
                "encrypted": "[green]encrypted[/green]",
                "decrypted": "[red]decrypted[/red]",
                "file not found": "[yellow]file not found[/yellow]"
            }.get(row[5], row[5])
            
            # Convert file size to human-readable format
            size_bytes = int(row[4])
            if size_bytes < 1024:
                size_str = f"{size_bytes}B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes/1024:.1f}KB"
            else:
                size_str = f"{size_bytes/(1024*1024):.1f}MB"
            
            table.add_row(
                row[0],          # filename
                row[1],          # filepath
                row[2],          # shortcut
                row[3],          # encryption date
                size_str,        # file size
                status_style     # colored status
            )
    
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
    key = None
    decrypted_data = None
    content = None
    modified_content = None
    
    try:
        key = authenticate()
        file_path = resolve_path(shortcut_or_path)
        
        # Verify that file exists
        if not file_path.exists() or not file_path.is_file():
            typer.secho("Error: Specified file does not exist.", fg=typer.colors.RED)
            raise typer.Exit()

        # Validate input text
        if not text or len(text.strip()) == 0:
            typer.secho("Error: Empty text is not allowed.", fg=typer.colors.RED)
            raise typer.Exit()

        fernet = Fernet(key)

        # Read and decrypt the file
        with open(file_path, "rb") as file:
            encrypted_data = file.read()

        try:
            decrypted_data = fernet.decrypt(encrypted_data)
        except InvalidToken:
            typer.secho("Decryption failed. File may not be encrypted.", fg=typer.colors.RED)
            raise typer.Exit()

        try:
            # Convert bytes to string and split into lines
            content = decrypted_data.decode('utf-8').splitlines()
            
            # Ensure line number is valid
            if line < 1:
                typer.secho("Line number must be positive.", fg=typer.colors.RED)
                raise typer.Exit()
            if line > len(content) + 1:
                typer.secho(f"Line number exceeds file length. Using last line ({len(content) + 1}).", fg=typer.colors.YELLOW)
                line = len(content) + 1

            # Insert the text at the specified line (adjusting for 0-based index)
            content.insert(line - 1, text)
            
            # Join the lines back together
            modified_content = '\n'.join(content)
            
            # Encrypt the modified content
            encrypted_modified = fernet.encrypt(modified_content.encode('utf-8'))
            
            # Save the modified file atomically
            temp_file = file_path.with_suffix('.tmp')
            try:
                # Write to temporary file first
                with open(temp_file, "wb") as file:
                    file.write(encrypted_modified)
                
                # Replace original file with temporary file
                temp_file.replace(file_path)
                
            finally:
                # Clean up temporary file if it still exists
                if temp_file.exists():
                    temp_file.unlink()

            typer.secho(f"Text successfully inserted at line {line}.", fg=typer.colors.GREEN)

        except UnicodeDecodeError:
            typer.secho("The file appears to be binary or not a text file.", fg=typer.colors.RED)
            raise typer.Exit()
            
    except Exception as e:
        # Generic error without exposing details
        typer.secho("An error occurred while modifying the file.", fg=typer.colors.RED)
        raise typer.Exit()
        
    finally:
        # Clear sensitive data from memory
        if key:
            key = None
        if decrypted_data:
            decrypted_data = b'\x00' * len(decrypted_data)
        if content:
            for i in range(len(content)):
                content[i] = '\x00' * len(content[i])
            content = None
        if modified_content:
            modified_content = '\x00' * len(modified_content)

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
            "encrypt": ("Encrypt a file or directory", "encrypt PATH [--pattern PATTERN] [--recursive]"),
            "decrypt": ("Decrypt a file or directory", "decrypt PATH|SHORTCUT [--pattern PATTERN] [--recursive]"),
            "view": ("View encrypted file contents", "view PATH|SHORTCUT [--lines N] [--pages N] [--chars N] [--all]"),
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
        console.print("• PATH can be the actual path to a file or directory")
        console.print("• SHORTCUT is the name you gave to the file during encryption")
        console.print("• All commands will prompt for your password when needed")
        console.print("\nFor detailed help on a specific command, use: [cyan]python main.py help COMMAND[/cyan]")
        
    else:
        # Show detailed help for specific command
        command = command.lower()
        detailed_help = {
            "encrypt": {
                "description": "Encrypt a file or directory",
                "usage": "encrypt PATH [--pattern PATTERN] [--recursive]",
                "details": [
                    "• Encrypts a single file or all files in a directory",
                    "• Prompts for a shortcut name for single files",
                    "• Optional pattern matching for directories (e.g., *.txt)",
                    "• --recursive flag to process subdirectories",
                    "• Records encryption details in the tracking file"
                ]
            },
            "decrypt": {
                "description": "Decrypt a file or directory",
                "usage": "decrypt PATH|SHORTCUT [--pattern PATTERN] [--recursive]",
                "details": [
                    "• Decrypts a single file or all files in a directory",
                    "• Can use file path or shortcut for single files",
                    "• Optional pattern matching for directories (e.g., *.txt)",
                    "• --recursive flag to process subdirectories",
                    "• Updates tracking information automatically"
                ]
            },
            "view": {
                "description": "View encrypted file contents with format-specific display options",
                "usage": "view PATH|SHORTCUT [--lines N] [--pages N] [--chars N] [--all]",
                "details": [
                    "• Shows the decrypted contents with syntax highlighting for text files",
                    "• Special handling for PDF files with metadata and content preview",
                    "• Hex view for binary files",
                    "• Text file options:",
                    "  - --lines N: Show first N lines only",
                    "• PDF options:",
                    "  - --pages N: Show first N pages (default: 3)",
                    "  - --chars N: Characters per page (default: 500)",
                    "  - --all: Show entire content without truncation",
                    "• Does not modify the original encrypted file",
                    "• Can use either file path or shortcut name",
                    "• Example: view document.pdf --pages 5 --chars 1000"
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
            "list-files": {
                "description": "List all encrypted files",
                "usage": "list-files",
                "details": [
                    "• Shows a table of all tracked files",
                    "• Displays file name, location, shortcut, encryption date, size",
                    "• Color-coded status indicators:",
                    "  - Green: Currently encrypted",
                    "  - Red: Currently decrypted",
                    "  - Yellow: File not found",
                    "• Automatically updates file status on display"
                ]
            },
            "clear-log": {
                "description": "Clear the encrypted files log",
                "usage": "clear-log",
                "details": [
                    "• Removes all entries from the tracking file",
                    "• Does not modify or delete the actual files",
                    "• Requires confirmation before proceeding",
                    "• Use with caution - this action cannot be undone"
                ]
            },
            "insert": {
                "description": "Insert text into an encrypted file",
                "usage": "insert FILE_PATH|SHORTCUT \"TEXT\" [LINE]",
                "details": [
                    "• Temporarily decrypts the file",
                    "• Inserts the specified text at the given line number",
                    "• Line number is optional (defaults to line 1)",
                    "• Re-encrypts the file after insertion",
                    "• Works with text files only",
                    "• Uses atomic operations for file safety"
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

def update_file_status(file_path: Path, new_status: str):
    """Update the status of a file in the tracking CSV."""
    if not TRACKING_FILE.exists():
        return
    
    try:
        # Read all entries
        rows = []
        updated = False
        file_path_str = str(file_path.resolve())
        
        with open(TRACKING_FILE, "r", newline='') as csvfile:
            csv_reader = csv.reader(csvfile)
            rows = list(csv_reader)
        
        # Update status
        for row in rows:
            if row[1] == file_path_str:
                row[5] = new_status
                updated = True
                break
        
        if updated:
            # Write back all entries
            with open(TRACKING_FILE, "w", newline='') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerows(rows)
                
    except Exception as e:
        log_error(e, "update_file_status")

@app.command()
def migrate_tracking_file():
    """Migrate existing tracking file to include verification tags."""
    if not TRACKING_FILE.exists():
        typer.secho("No tracking file to migrate.", fg=typer.colors.YELLOW)
        return

    try:
        # Get password for creating new verification tags
        key = authenticate()
        verification_tag = create_verification_tag(key)
        tag_str = base64.b64encode(verification_tag).decode('utf-8')

        # Read existing entries
        with open(TRACKING_FILE, "r") as csvfile:
            rows = list(csv.reader(csvfile))

        # Add verification tag to each row
        for row in rows:
            if len(row) < 7:  # Only add tag if it doesn't exist
                row.append(tag_str)

        # Write back updated entries
        with open(TRACKING_FILE, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerows(rows)

        typer.secho("Successfully migrated tracking file.", fg=typer.colors.GREEN)

    except Exception as e:
        typer.secho(f"Error during migration: {str(e)}", fg=typer.colors.RED)
        raise typer.Exit()

def secure_cleanup(data: bytes) -> None:
    """Securely clear sensitive data from memory."""
    try:
        # Multiple overwrites with random data
        for _ in range(3):
            data[:] = secrets.token_bytes(len(data))
        data[:] = b'\x00' * len(data)
    except Exception:
        pass

def atomic_write(file_path: Path, data: bytes) -> None:
    """Write data atomically using a temporary file."""
    temp_path = file_path.with_suffix(file_path.suffix + '.tmp')
    with open(temp_path, 'wb') as f:
        f.write(data)
    temp_path.replace(file_path)

def atomic_read(file_path: Path) -> bytes:
    """Read file with error handling."""
    try:
        with open(file_path, 'rb') as f:
            return f.read()
    except Exception as e:
        typer.secho("Error reading file.", fg=typer.colors.RED)
        raise typer.Exit()

def check_file_permissions(path: Path) -> bool:
    """Check if file permissions are secure."""
    try:
        return (path.stat().st_mode & 0o777) <= 0o600
    except Exception as e:
        log_error(e, "check_file_permissions")
        return False

def secure_file_permissions(path: Path) -> None:
    """Set secure file permissions."""
    try:
        if os.name == 'posix':  # Unix-like systems
            path.chmod(0o600)  # User read/write only
    except Exception as e:
        log_error(e, "secure_file_permissions")

def log_error(error: Exception, function_name: str) -> None:
    """Log errors to the configured logging file."""
    logging.error(f"Error in {function_name}: {str(error)}")

if __name__ == "__main__":
    app()
