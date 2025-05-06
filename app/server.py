# Standard library
import logging
import json
import sys
import os
from pathlib import Path

# Third-party
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Local
from .auth import ApiKey, ApiKeyValidator, verify_api_key
from .health import router as health_router
from .middleware import RequestIDMiddleware, request_id_context
from .model_registry import ModelRegistry
from .settings import Settings
from .rate_limiter import RateLimiter
from .schemas import (
    GenerateRequest,
    RenameFunctionRequest,
    AnalyzeFunctionRequest,
    ChatRequest
)

# Add the project root to sys.path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

from dotenv import load_dotenv
load_dotenv()

# Add debug logging for environment variables
logger.info(f"AWS Region: {os.getenv('AWS_REGION')}")
logger.info(f"AWS Access Key ID exists: {bool(os.getenv('AWS_ACCESS_KEY_ID'))}")
logger.info(f"AWS Secret Access Key exists: {bool(os.getenv('AWS_SECRET_ACCESS_KEY'))}")

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load settings
settings = Settings()

# Initialize components
app = FastAPI(title="AI Text Generation API")
rate_limiter = RateLimiter()
registry = ModelRegistry(config_path="config/config.json")  # Relative to app directory
api_key_validator = ApiKeyValidator()


# Add middleware (order matters)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
    expose_headers=["X-Request-ID"]
)

# Include routers
app.include_router(health_router)

@app.post("/generate")
async def generate_text(
    request: GenerateRequest,
    api_key: ApiKey = Depends(verify_api_key)
):
    request_id = request_id_context.get()
    logger.info(f"Processing generation request {request_id}")
    
    try:
        # Rate limit check
        if not await rate_limiter.check_rate_limit(api_key):
            logger.warning(f"Rate limit exceeded for request {request_id}")
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        # Generate text
        result = await registry.generate(
            prompt=request.prompt,
            max_length=request.max_length,
            temperature=request.temperature,
            provider=request.provider,
            stop_sequences=request.stop_sequences
        )

        logger.info(f"Successfully processed request {request_id}")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
# ... existing imports and setup ...

@app.post("/rename_function")
async def rename_function(
    request: RenameFunctionRequest,
    api_key: ApiKey = Depends(verify_api_key)
):
    request_id = request_id_context.get()
    logger.info(f"Processing rename request {request_id}")
    
    try:
        # Generate text
        result = await registry.generate(
            prompt=f"Based on this decompiled function code, suggest a clear and descriptive function name:\n\n{request.function_code}",
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        new_name = parse_function_name(result)
        return {"new_name": new_name}

    except Exception as e:
        logger.error(f"Error processing rename request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/analyze")
async def analyze_function(
    request: AnalyzeFunctionRequest,
    api_key: ApiKey = Depends(verify_api_key)
):
    request_id = request_id_context.get()
    logger.info(f"Processing analysis request {request_id}")
    
    try:
        # Generate text
        result = await registry.generate(
            prompt=f"Analyze this decompiled function and provide a concise summary:\n\n{request.function_code}",
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        summary = parse_function_summary(result)
        return {"summary": summary}

    except Exception as e:
        logger.error(f"Error processing analysis request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/chat")
async def chat(
    request: ChatRequest,
    api_key: ApiKey = Depends(verify_api_key)
):
    request_id = request_id_context.get()
    logger.info(f"Processing chat request {request_id}")
    
    try:
        # Generate text
        result = await registry.generate(
            prompt=request.prompt,
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        return {"summary": result}

    except Exception as e:
        logger.error(f"Error processing chat request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

def parse_function_summary(model_output):
    try:
        text = model_output[0]['generated_text'].strip()
        
        # Find last { to extract a possibly incomplete JSON block
        last_brace = text.rfind('{')
        if last_brace == -1:
            logger.warning("No JSON start found.")
            return "No summary available."

        possible_json = text[last_brace:].strip()

        # Try to brute-force fix missing closing quotes/brackets
        if not possible_json.endswith('}'):
            possible_json += '"}' if possible_json.count('"') % 2 == 1 else '}'

        parsed = json.loads(possible_json)
        if "summary" in parsed:
            return parsed["summary"].strip()

        logger.warning("Parsed block missing 'summary'")
        return "No summary available."

    except Exception as e:
        logger.error(f"Parser Error: {e}")
        return "No summary available."

def parse_function_name(model_output):
    try:
        if isinstance(model_output, dict):
            return model_output.get('new_name', '').strip()
        elif isinstance(model_output, str):
            return model_output.strip().split('\n')[0].strip()
        return "unnamed_function"
    except Exception as e:
        logger.error(f"Error parsing function name: {e}")
        return "unnamed_function"