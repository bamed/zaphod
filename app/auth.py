from typing import Optional, Set
from fastapi import HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

class ApiKey(str):
    pass

class ApiKeyValidator:
    def __init__(self):
        self._valid_keys = self._load_api_keys()

    def _load_api_keys(self) -> Set[str]:
        try:
            # Get the path to config relative to this file
            config_path = Path(__file__).parent / "config" / "config.json"
            
            with open(config_path, 'r') as f:
                config = json.load(f)
                
            # Get API keys from system config
            api_keys = config.get('system', {}).get('api_keys', [])
            
            if not api_keys:
                logger.warning("No API keys found in config.json")
                return set()
                
            return set(api_keys)
            
        except Exception as e:
            logger.error(f"Error loading API keys from config: {e}")
            return set()

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