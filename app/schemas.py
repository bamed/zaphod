# Standard library
from typing import List, Optional

# Third-party imports
from pydantic import BaseModel, conint, confloat, validator

# No local imports needed for basic schema definition
# Note: The dynamic provider validation might need a different approach to avoid circular imports

class GenerateRequest(BaseModel):
    prompt: str
    max_length: conint(gt=0, le=4096) = 1024
    temperature: Optional[confloat(gt=0, le=1)] = 0.7
    provider: Optional[str] = None
    stop_sequences: Optional[List[str]] = None

    @validator('provider')
    def validate_provider(cls, v):
        if v is not None:
            # Get valid providers from registry
            from .server import registry
            valid_providers = registry.providers.keys()
            if v not in valid_providers:
                raise ValueError(f"Invalid provider. Must be one of: {', '.join(valid_providers)}")
        return v