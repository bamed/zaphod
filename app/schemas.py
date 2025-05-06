from typing import List, Optional
from pydantic import BaseModel, conint, confloat, validator
from utils.constants import ProviderType

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
                # Instead of checking registry, verify it's a valid provider type
                if v not in [p.value for p in ProviderType]:
                    valid_providers = [p.value for p in ProviderType]
                    raise ValueError(f"Invalid provider. Must be one of: {', '.join(valid_providers)}")
            except Exception as e:
                raise ValueError(f"Invalid provider: {str(e)}")
        return v


class RenameFunctionRequest(BaseModel):
    model_name: str = "default"
    function_code: str
    max_length: conint(gt=0, le=4096) = 20

class AnalyzeFunctionRequest(BaseModel):
    model_name: str
    function_code: str
    max_length: int = 100

class ChatRequest(BaseModel):
    prompt: str
    model_name: str
    function_code: str
    max_length: int = 1000

class AlgorithmDetectionRequest(BaseModel):
    model_name: str
    function_code: str
    max_length: int = 500

class ChatResponse(BaseModel):
    summary: str

class AnalysisResponse(BaseModel):
    summary: str

class AlgorithmDetectionResponse(BaseModel):
    algorithm_detected: str
    confidence: str
    notes: str

class RenameFunctionResponse(BaseModel):
    new_name: str

class GenerateResponse(BaseModel):
    generated_text: str