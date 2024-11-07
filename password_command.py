from safestring import PasswordManager, Entry
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from pathlib import Path
import typer
from getpass import getpass
import tempfile
import os

password_app = typer.Typer(name="password", help="Secure password management commands")
console = Console()

def display_password_structure():
    """Display the structure of a .password file with syntax highlighting"""
    sample_structure = """# Password Storage File Structure
# This is a secure password storage format

group company_credentials {
    [john.doe@email.com = ********]:account,password;
    [jane.doe@email.com = ********]:account,password;
    [api_key = ********]:generic;
}"""

    syntax = Syntax(
        sample_structure,
        lexer="python",
        theme="monokai",
        background_color="default",
        line_numbers=False,
        highlight_lines=set()
    )
    
    console.print("\n[cyan]Password File Structure:[/cyan]")
    console.print("-" * 50)
    console.print(syntax)
    console.print("-" * 50)

def secure_print_file_content(filepath: str):
    """Securely display file content with masked sensitive data"""
    console.print(f"\n[cyan]Reading {filepath}:[/cyan]")
    console.print("-" * 50)
    with open(filepath, 'rb') as f:
        content = f.read()
        console.print("[dim]<encrypted content>[/dim]")
    console.print("-" * 50)

@password_app.command()
def init(
    file: Path = typer.Option(Path("passwords.password"), "--file", "-f", help="Password file path")
):
    """Initialize a new password storage file"""
    try:
        master_password = getpass("Enter master password: ")
        manager = PasswordManager(master_password)
        manager.create_password_file(str(file))
        display_password_structure()
        typer.secho(f"Password file created: {file}", fg=typer.colors.GREEN)
    except Exception as e:
        typer.secho(f"Error: {str(e)}", fg=typer.colors.RED)
        raise typer.Exit(1)

@password_app.command()
def add(
    group: str = typer.Option(..., "--group", "-g", help="Group name"),
    identifier: str = typer.Option(..., "--id", "-i", help="Entry identifier"),
    value: str = typer.Option(..., "--value", "-v", help="Entry value"),
    entry_type: str = typer.Option("account,password", "--type", "-t", help="Entry type(s)"),
    file: Path = typer.Option(Path("passwords.password"), "--file", "-f", help="Password file")
):
    """Add a new password entry"""
    try:
        # Create manager with secure password handling
        master_password = getpass("Enter master password: ")
        manager = PasswordManager(master_password)

        # Create new entry
        entry_types = [t.strip() for t in entry_type.split(",")]
        entry = Entry(identifier, value, entry_types)

        # Add entry to group and save
        manager.add_entry(group, entry)
        manager.save_file(str(file))

        # Show results
        results_table = Table(title="Operation Results")
        results_table.add_column("Operation", style="cyan")
        results_table.add_column("Result", style="green")
        results_table.add_row("Add Entry", f"Added '{identifier}' to '{group}'")
        console.print(results_table)

    except Exception as e:
        typer.secho(f"Error: {str(e)}", fg=typer.colors.RED)
        raise typer.Exit(1)
