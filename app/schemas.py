from typing import List, Optional
from pydantic import BaseModel, conint, confloat, validator

class GenerateRequest(BaseModel):
    prompt: str
    max_length: conint(gt=0, le=4096) = 1024
    temperature: Optional[confloat(gt=0, le=1)] = 0.7
    provider: Optional[str] = None
    stop_sequences: Optional[List[str]] = None

    @validator('provider')
    def validate_provider(cls, v):
        if v is not None:
            try:
            # Updated import path
                from .server import registry  # This imports the instance from server.py
                if not registry._initialized:
                    raise RuntimeError("Registry not initialized")
                valid_providers = registry.providers.keys()
                if v not in valid_providers:
                    raise ValueError(f"Invalid provider. Must be one of: {', '.join(valid_providers)}")
            except Exception as e:
                raise ValueError("Unable to validate provider at this time")
        return v