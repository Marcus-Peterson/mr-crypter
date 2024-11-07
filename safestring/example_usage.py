from safestring import PasswordManager, Entry
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich import print as rprint
import os
import tempfile

console = Console()

def display_password_file_structure():
    """Display the structure of a .password file with syntax highlighting"""
    sample_structure = """# Password Storage File Structure
# This is a secure password storage format

group company_credentials {
    [john.doe@email.com = ********]:account,password;
    [jane.doe@email.com = ********]:account,password;

    [api_key = ********]:generic;
    [key_pad = ****]:generic;
}

group development {
    [github_token = ********]:generic;
    [aws_key = ********]:account,password;
}"""

    # Create custom syntax highlighting
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

def demonstrate_secure_password_manager():
    temp_dir = tempfile.mkdtemp()
    password_file = os.path.join(temp_dir, "test_encrypted.password")
    
    try:
        # Display password file structure first
        display_password_file_structure()

        # Create new password manager with secure password handling
        manager = PasswordManager("StrongM@sterP@ss123!")

        # Add sample entries with strong passwords
        entries = [
            Entry("john.doe@email.com", "J0hn$SecureP@ss123!", ["account", "password"]),
            Entry("jane.doe@email.com", "J@ne$StrongP@ss456!", ["account", "password"]),
            Entry("api_key", "ak_prod_9X$mK2pL5vN8qR3", ["generic"]),
            Entry("key_pad", "9876#5432@1098", ["generic"])
        ]

        # Add entries to group
        for entry in entries:
            manager.add_entry("company_credentials", entry)

        # Save with secure permissions
        manager.save_file(password_file)

        # Demonstrate secure operations
        console.print("\n[cyan]Demonstrating secure operations:[/cyan]")
        console.print("-" * 50)
        
        # Create tables for results
        results_table = Table(title="Password Operations Results")
        results_table.add_column("Operation", style="cyan")
        results_table.add_column("Result", style="green")

        # Test operations
        password = manager.get_password("john.doe@email.com")
        results_table.add_row(
            "Password Retrieval",
            f"{'*' * len(password)}"
        )

        account = manager.get_account("jane.doe@email.com")
        results_table.add_row(
            "Account Retrieval",
            f"{account.identifier}"
        )

        group = manager.get_group("company_credentials")
        results_table.add_row(
            "Group Retrieval",
            f"Found group with {len(group.entries)} entries"
        )

        search_results = manager.search_entries("api")
        results_table.add_row(
            "Search Operation",
            f"Found {len(search_results)} matches"
        )

        deleted = manager.delete_entry("company_credentials", "key_pad")
        results_table.add_row(
            "Delete Operation",
            "Success" if deleted else "Failed"
        )

        console.print(results_table)

        # Show encrypted content securely
        secure_print_file_content(password_file)

    except Exception as e:
        console.print(f"[red]Error:[/red] {str(e)}")
        raise
    finally:
        # Cleanup
        if os.path.exists(password_file):
            os.unlink(password_file)
        os.rmdir(temp_dir)
        if 'manager' in locals():
            del manager

if __name__ == "__main__":
    demonstrate_secure_password_manager()
