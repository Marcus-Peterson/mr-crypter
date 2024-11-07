import re
from typing import Optional
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordValidator:
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
    
    def validate_password(self, password: str) -> Optional[str]:
        if len(password) < self.min_length:
            return f"Password must be at least {self.min_length} characters"
        if len(password) > self.max_length:
            return f"Password must be less than {self.max_length} characters"
        if not re.search(r"[A-Z]", password):
            return "Password must contain uppercase letters"
        if not re.search(r"[a-z]", password):
            return "Password must contain lowercase letters"
        if not re.search(r"\d", password):
            return "Password must contain numbers"
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return "Password must contain special characters"
        return None

    def sanitize_input(self, value: str) -> str:
        return re.sub(r'[^\w\s@.-]', '', value)[:256] 