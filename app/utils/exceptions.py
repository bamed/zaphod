# utils/exceptions.py
from typing import Optional

class ZaphodError(Exception):
    """Base exception for all application errors"""
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class ConfigurationError(ZaphodError):
    """Configuration related errors"""
    def __init__(self, message: str):
        super().__init__(message, status_code=500)

class ModelProviderError(ZaphodError):
    """Model provider related errors"""
    def __init__(self, message: str, provider: Optional[str] = None):
        self.provider = provider
        super().__init__(message, status_code=503)

class ValidationError(ZaphodError):
    """Input validation errors"""
    def __init__(self, message: str):
        super().__init__(message, status_code=400)

class RateLimitError(ZaphodError):
    """Rate limiting errors"""
    def __init__(self, message: str):
        super().__init__(message, status_code=429)