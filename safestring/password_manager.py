from typing import List, Optional, Dict
from safestring.secure_string import SecureString
from safestring.security import PasswordSecurity
from safestring.parser import Parser, Group, Entry
from safestring.lexer import Lexer
from safestring.formatter import PasswordFormatter
import os
import platform

class PasswordMetadata:
    def __init__(self, created_at: str, last_modified: str):
        self.created_at = created_at
        self.last_modified = last_modified

class PasswordManager:
    def __init__(self, master_password: str):
        # Keep master password secure but available for file operations
        self._secure_password = SecureString(master_password)
        self.security = PasswordSecurity(master_password)
        self.groups: List[Group] = []
        self.metadata: Dict[str, PasswordMetadata] = {}
        self._loaded_file: Optional[str] = None
        self.formatter = PasswordFormatter()
        
    def _secure_file_permissions(self, filepath: str):
        if platform.system() != "Windows":
            os.chmod(filepath, 0o600)
        
    def load_file(self, filepath: str):
        if not filepath.endswith('.password'):
            raise ValueError("Invalid file format. Only .password files are supported")
        
        with open(filepath, 'rb') as f:
            salt = f.read(16)  # Read first 16 bytes as salt
            encrypted_content = f.read()
            
        try:
            self.security.set_salt(salt)  # Set the salt before decrypting
            decrypted_content = self.security.decrypt(encrypted_content)
            lexer = Lexer(decrypted_content)
            parser = Parser(lexer)
            
            while True:
                try:
                    group = parser.parse_group()
                    self.groups.append(group)
                except EOFError:
                    break
        except Exception as e:
            raise ValueError(f"Failed to decrypt file: {str(e)}")

    def save_file(self, filepath: str):
        if not filepath.endswith('.password'):
            raise ValueError("Invalid file format. Only .password files are supported")
            
        temp_path = f"{filepath}.tmp"
        try:
            content = self._groups_to_string()
            encrypted_content = self.security.encrypt(content)
            
            with open(temp_path, 'wb') as f:
                f.write(self.security.salt)
                f.write(encrypted_content)
            
            self._secure_file_permissions(temp_path)
            os.replace(temp_path, filepath)
            self._secure_file_permissions(filepath)
            
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def get_password(self, identifier: str) -> Optional[str]:
        """Retrieve a password by its identifier"""
        for group in self.groups:
            for entry in group.entries:
                if entry.identifier == identifier and "password" in entry.entry_type:
                    return entry.value
        return None

    def get_account(self, identifier: str) -> Optional[Entry]:
        """Retrieve an account entry by its identifier"""
        for group in self.groups:
            for entry in group.entries:
                if entry.identifier == identifier and "account" in entry.entry_type:
                    return entry
        return None

    def get_group(self, group_name: str) -> Optional[Group]:
        """Retrieve a group by its name"""
        for group in self.groups:
            if group.name == group_name:
                return group
        return None

    def search_entries(self, query: str) -> List[Entry]:
        """Search for entries containing the query string"""
        results = []
        for group in self.groups:
            for entry in group.entries:
                if query.lower() in entry.identifier.lower() or query.lower() in entry.value.lower():
                    results.append(entry)
        return results

    def validate_entry_type(self, entry_type: List[str]) -> bool:
        """Validate entry types against allowed values"""
        allowed_types = {self.formatter.account, self.formatter.password, self.formatter.generic}
        return all(t in allowed_types for t in entry_type)

    def add_password(self, group_name: str, identifier: str, password: str, entry_type: List[str]):
        # Implement password addition
        pass

    def _groups_to_string(self) -> str:
        lines = []
        for group in self.groups:
            group_entries = []
            for entry in group.entries:
                if "account" in entry.entry_type and "password" in entry.entry_type:
                    entry_str = self.formatter.format_account_password(
                        entry.identifier, 
                        entry.value
                    )
                else:
                    entry_str = self.formatter.format_generic(
                        entry.identifier, 
                        entry.value
                    )
                group_entries.append(entry_str)
            
            formatted_group = self.formatter.format_group(group.name, group_entries)
            lines.append(formatted_group)
        
        return "\n".join(lines)

    def create_password_file(self, filepath: str):
        if not filepath.endswith('.password'):
            filepath += '.password'
        
        if os.path.exists(filepath):
            raise FileExistsError("Password file already exists")
        
        # Create empty file with basic structure
        with open(filepath, 'w') as f:
            f.write("# Password Storage File\n\n")
        
        self._loaded_file = filepath
    
    def add_entry(self, group_name: str, entry: Entry):
        """Add an entry with validation"""
        if not self.validate_entry_type(entry.entry_type):
            raise ValueError("Invalid entry type. Allowed types: account, password, generic")
            
        # Check for duplicate identifiers
        for group in self.groups:
            for existing_entry in group.entries:
                if existing_entry.identifier == entry.identifier:
                    raise ValueError(f"Entry with identifier '{entry.identifier}' already exists")
        
        # Original add_entry logic
        for group in self.groups:
            if group.name == group_name:
                group.entries.append(entry)
                return
                
        new_group = Group(name=group_name, entries=[entry])
        self.groups.append(new_group)

    def delete_entry(self, group_name: str, identifier: str) -> bool:
        """Delete an entry from a specific group"""
        for group in self.groups:
            if group.name == group_name:
                for i, entry in enumerate(group.entries):
                    if entry.identifier == identifier:
                        group.entries.pop(i)
                        return True
        return False