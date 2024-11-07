import ctypes

class SecureString:
    def __init__(self, value: str):
        self._value = value.encode()
        self._cleared = False
        
    def __del__(self):
        self.clear()
        
    def clear(self):
        if hasattr(self, '_value') and not self._cleared:
            ctypes.memset(self._value, 0, len(self._value))
            del self._value
            self._cleared = True
    
    def get(self) -> str:
        if self._cleared:
            raise ValueError("SecureString has been cleared")
        return self._value.decode()
    
    def __str__(self):
        return "[PROTECTED]" 