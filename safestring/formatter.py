from typing import List

class PasswordFormatter:
    """
    Handles the formatting of password entries and groups according to the .password file format
    """
    def __init__(self):
        self.group = "group"
        self.account = "account"
        self.password = "password"
        self.generic = "generic"
    
    def format_account_password(self, account: str, password: str) -> str:
        """Formats an account-password entry"""
        return f"[{account} = {password}]:{self.account},{self.password};"
    
    def format_generic(self, identifier: str, value: str) -> str:
        """Formats a generic entry"""
        return f"[{identifier} = {value}]:{self.generic};"
    
    def format_group(self, group_name: str, entries: List[str]) -> str:
        """Formats a complete group with its entries"""
        lines = [f"{self.group} {group_name} {{"]
        indented_entries = ["    " + entry for entry in entries]
        lines.extend(indented_entries)
        lines.append("}")
        return "\n".join(lines) 