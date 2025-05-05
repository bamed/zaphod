# Standard library
import logging

# Third-party
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

# Local
from .auth import ApiKey, ApiKeyValidator, verify_api_key
from .health import router as health_router
from .middleware import RequestIDMiddleware, request_id_context
from .model_registry import ModelRegistry
from .models import Settings
from .rate_limiter import RateLimiter
from .schemas import GenerateRequest

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load settings
settings = Settings()

# Initialize components
app = FastAPI(title="AI Text Generation API")
rate_limiter = RateLimiter()
registry = ModelRegistry()
api_key_validator = ApiKeyValidator()

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing application components")
    await registry.initialize()
    await rate_limiter.initialize()

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down application components")
    await registry.cleanup()
    await rate_limiter.cleanup()

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