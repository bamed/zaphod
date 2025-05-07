import logging
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any

# Initialize logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup separate loggers
api_logger = logging.getLogger('api')
bedrock_logger = logging.getLogger('bedrock')

# Configure loggers
for logger_name, log_file in [
    ('api', 'logs/api.log'),
    ('bedrock', 'logs/bedrock.log')
]:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    
    # File handler
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    logger.addHandler(fh)

# Third-party
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request, Response

# Local
from auth import ApiKeyValidator, verify_api_key, ApiKey, api_key_header
from health import router as health_router
from middleware import RequestIDMiddleware, request_id_context
from model_registry import ModelRegistry
from settings import Settings
from rate_limiter import RateLimiter
from schemas import (
    ChatRequest,
    AnalyzeFunctionRequest,
    AlgorithmDetectionRequest,
    RenameFunctionRequest,
    GenerateRequest,
    ChatResponse,
    AnalysisResponse,
    AlgorithmDetectionResponse,
    RenameFunctionResponse,
    GenerateResponse
)

from dotenv import load_dotenv
load_dotenv()

# Now we can use logger for environment variables
logger.info(f"AWS Region: {os.getenv('AWS_REGION')}")
logger.info(f"AWS Access Key ID exists: {bool(os.getenv('AWS_ACCESS_KEY_ID'))}")
logger.info(f"AWS Secret Access Key exists: {bool(os.getenv('AWS_SECRET_ACCESS_KEY'))}")

# Rest of your code...
# Add the project root to sys.path
project_root = Path(__file__).parent
sys.path.append(str(project_root))

# Add debug logging for environment variables


# Initialize logging


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

# Add middleware for API logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log request
    body = await request.body()
    api_logger.debug(f"Request {request_id_context.get()}:")
    api_logger.debug(f"Method: {request.method}")
    api_logger.debug(f"URL: {request.url}")
    api_logger.debug(f"Headers: {dict(request.headers)}")
    api_logger.debug(f"Body: {body.decode()}")

    # Get response
    response = await call_next(request)

    # Log response
    api_logger.debug(f"Response {request_id_context.get()}:")
    api_logger.debug(f"Status: {response.status_code}")
    api_logger.debug(f"Headers: {dict(response.headers)}")
    
    # Get response body - need to handle streaming responses
    response_body = b""
    async for chunk in response.body_iterator:
        response_body += chunk
    api_logger.debug(f"Body: {response_body.decode()}")

    return Response(
        content=response_body,
        status_code=response.status_code,
        headers=dict(response.headers),
        media_type=response.media_type
    )

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
import re
import json

def extract_last_json(text: str) -> Dict[str, Any]:
    """Extract the last valid JSON object from text, allowing for incomplete ones."""
    json_pattern = r'({[^}]*})'
    matches = list(re.finditer(json_pattern, text))
    
    if not matches:
        return None
        
    for match in reversed(matches):
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
    return None

def parse_bedrock_response(result: Dict[str, Any]) -> str:
    """Parse response from Bedrock into a consistent format."""
    try:
        if isinstance(result, dict):
            if 'outputs' in result and result['outputs']:
                return result['outputs'][0].get('text', '').strip()
            return result.get('generated_text', '').strip()
        return ''
    except Exception as e:
        logger.error(f"Error parsing model output: {str(e)}")
        return ''

def parse_rename_response(result: Dict[str, Any]) -> Dict[str, str]:
    try:
        if not isinstance(result, dict) or 'outputs' not in result or not result['outputs']:
            return {"new_name": "unnamed_function"}
        
        text = result['outputs'][0].get('text', '').strip()
        if not text:
            return {"new_name": "unnamed_function"}
            
        # Clean the name
        name = text.split('(')[0].strip()  # Remove parameters
        clean_name = ''.join(c for c in name if c.isalnum() or c == '_')
        
        if not clean_name:
            return {"new_name": "unnamed_function"}
        if clean_name[0].isdigit():
            clean_name = 'func_' + clean_name
            
        return {"new_name": clean_name}

    except Exception as e:
        logger.error(f"Error parsing rename response: {str(e)}")
        return {"new_name": "unnamed_function"}

@app.post("/rename_function", response_model=RenameFunctionResponse)
async def rename_function(request: RenameFunctionRequest, api_key: ApiKey = Depends(verify_api_key)):
    request_id = request_id_context.get()
    logger.info(f"Processing rename request {request_id}")
    
    try:
        prompt = "Based on this decompiled function code, suggest a clear and descriptive function name that reflects its purpose. Return only the suggested name without explanation.\n\n" + request.function_code
        
        result = await registry.generate(
            prompt=prompt,
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        return parse_rename_response(result)
    except Exception as e:
        logger.error(f"Error processing rename request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_function(request: AnalyzeFunctionRequest, api_key: ApiKey = Depends(verify_api_key)):
    request_id = request_id_context.get()
    logger.info(f"Processing analysis request {request_id}")
    
    try:
        prompt = (
            "Analyze this decompiled function and provide a concise summary of its functionality:\n\n"
            f"Function code:\n{request.function_code}"
        )
        
        result = await registry.generate(
            prompt=prompt,
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        summary = parse_bedrock_response(result)
        return {"summary": summary if summary else "No summary available"}
    except Exception as e:
        logger.error(f"Error processing analysis request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest, api_key: ApiKey = Depends(verify_api_key)):
    request_id = request_id_context.get()
    logger.info(f"Processing chat request {request_id}")
    
    try:
        prompt = (
            f"Question about this decompiled function: {request.user_question}\n\n"
            f"Function code:\n{request.function_code}"
        )
        
        result = await registry.generate(
            prompt=prompt,
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        response = parse_bedrock_response(result)
        return {"response": response if response else "No response available"}
    except Exception as e:
        logger.error(f"Error processing chat request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/detect_algorithm", response_model=AlgorithmDetectionResponse)
async def detect_algorithm(request: AlgorithmDetectionRequest, api_key: ApiKey = Depends(verify_api_key)):
    request_id = request_id_context.get()
    logger.info(f"Processing algorithm detection request {request_id}")
    
    try:
        prompt = (
            "Identify the algorithm implemented in this decompiled function.\n"
            "Format your response as follows:\n"
            "Algorithm: [name]\n"
            "Confidence: [high/medium/low]\n"
            "Notes: [brief explanation]\n\n"
            f"Function code:\n{request.function_code}"
        )
        
        result = await registry.generate(
            prompt=prompt,
            max_length=request.max_length,
            temperature=0.7,
            provider=request.model_name if request.model_name != "default" else None
        )
        
        text = parse_bedrock_response(result)
        if not text:
            return {
                "algorithm_detected": "unknown",
                "confidence": "low",
                "notes": "Failed to analyze algorithm"
            }
            
        # Parse the response format
        algorithm = "unknown"
        confidence = "low"
        notes = text
        
        lines = text.split('\n')
        for line in lines:
            if line.startswith("Algorithm:"):
                algorithm = line.replace("Algorithm:", "").strip()
            elif line.startswith("Confidence:"):
                confidence = line.replace("Confidence:", "").strip().lower()
            elif line.startswith("Notes:"):
                notes = line.replace("Notes:", "").strip()
                
        return {
            "algorithm_detected": algorithm,
            "confidence": confidence,
            "notes": notes
        }
    except Exception as e:
        logger.error(f"Error processing algorithm detection request {request_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")