from safestring.secure_string import SecureString
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import secrets
import json
import ctypes
import hmac

class PasswordSecurity:
    def __init__(self, master_password: str):
        self._temp_password = SecureString(master_password)
        self.salt = None
        self._hmac_key = None
        self._initialize_key()
        
    def __del__(self):
        if hasattr(self, '_temp_password'):
            self._temp_password.clear()
        if hasattr(self, 'key'):
            ctypes.memset(self.key, 0, len(self.key))
    
    def _initialize_key(self):
        if self.salt is None:
            self.salt = secrets.token_bytes(32)  # Increased salt size
            self._hmac_key = secrets.token_bytes(32)
        
        password = self._temp_password.get()
        self.key = self._generate_key(password)
        self.fernet = Fernet(self.key)
        # Only clear after we're done using it
        self._temp_password.clear()
    
    def _generate_key(self, password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600000,  # Increased iterations for security
        )
        key = kdf.derive(password.encode())
        return base64.urlsafe_b64encode(key)
    
    def encrypt(self, data: str) -> bytes:
        encrypted = self.fernet.encrypt(data.encode())
        h = hmac.new(key=self._hmac_key, digestmod='sha256')
        h.update(encrypted)
        mac = h.digest()
        return mac + encrypted
    
    def decrypt(self, encrypted_data: bytes) -> str:
        mac, data = encrypted_data[:32], encrypted_data[32:]
        h = hmac.new(key=self._hmac_key, digestmod='sha256')
        h.update(data)
        if not hmac.compare_digest(h.digest(), mac):
            raise ValueError("Invalid MAC")
        return self.fernet.decrypt(data).decode()
    
    def get_salt(self) -> bytes:
        return self.salt
    
    def set_salt(self, salt: bytes):
        self.salt = salt
        # Reinitialize with new salt
        password = self._temp_password.get()
        self.key = self._generate_key(password)
        self.fernet = Fernet(self.key)