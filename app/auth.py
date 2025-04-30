from typing import Optional
from fastapi import HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
import logging

logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

class ApiKey(str):
    pass

class ApiKeyValidator:
    def __init__(self):
        # In production, this should be loaded from secure storage
        self._valid_keys = {"your-test-api-key"}

    def is_valid(self, key: str) -> bool:
        return key in self._valid_keys

async def verify_api_key(
    api_key: Optional[str] = Security(api_key_header)
) -> ApiKey:
    if api_key is None:
        raise HTTPException(
            status_code=401,
            detail="API key is missing"
        )
    
    validator = ApiKeyValidator()
    if not validator.is_valid(api_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid API key"
        )
    
    return ApiKey(api_key)