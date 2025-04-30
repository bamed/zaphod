# Standard library
import logging
from datetime import datetime

# Third-party imports
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseSettings

# Local imports - alphabetically ordered
from .auth import ApiKey, ApiKeyValidator, verify_api_key
from .health import router as health_router
from .middleware import RequestIDMiddleware
from .models import Settings
from .rate_limiter import RateLimiter
from .registry import ModelRegistry
from .schemas import GenerateRequest

class ProviderConfig(TypedDict):
    api_key: str
    endpoint: HttpUrl
    timeout: conint(gt=0)
    max_retries: conint(ge=0)
    backoff_factor: confloat(gt=0)

class AppConfig(BaseSettings):
    debug: bool = False
    environment: str = "production"
    log_level: str = "INFO"
    
    # Provider configurations
    providers: Dict[str, ProviderConfig]
    
    # Rate limiting
    rate_limit_per_minute: int = 60
    rate_limit_burst: int = 10
    
    # Security
    api_key_prefix: str = "sk-"
    min_api_key_length: int = 32
    
    # Metrics
    enable_metrics: bool = True
    metrics_port: int = 9090
    
    class Config:
        env_prefix = "APP_"
        env_nested_delimiter = "__"

config = AppConfig()

class Settings(BaseSettings):
    ALLOWED_ORIGINS: List[str] = [
        "https://api.yourdomain.com",
        "https://admin.yourdomain.com"
    ]
    ALLOWED_METHODS: List[str] = ["GET", "POST"]
    ALLOWED_HEADERS: List[str] = [
        "Authorization",
        "Content-Type",
        "X-Request-ID"
    ]

    class Config:
        env_prefix = "APP_"

settings = Settings()

# Initialize FastAPI app
app = FastAPI(
    title="Zaphod LLM API",
    description="API for accessing large language models",
    version=VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Initialize metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Initialize logger
logger = logging.getLogger(__name__)

# Initialize model registry
registry = ModelRegistry()
metrics = MetricsCollector()

# API key security scheme
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Request Models
class GenerateRequest(BaseModel):
    model_name: constr(min_length=1, max_length=100) = Field(
        ..., 
        description="Name of the model to use"
    )
    provider: Optional[str] = Field(
        None, 
        max_length=50,
        description="Provider to use (optional)"
    )
    prompt: constr(min_length=1, max_length=8192) = Field(
        ..., 
        description="Input prompt for generation"
    )
    max_length: int = Field(
        default=512,
        gt=0,
        le=2048,
        description="Maximum length of generated text"
    )
    temperature: Optional[float] = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Sampling temperature"
    )

    @validator('model_name', 'provider')
    def validate_identifiers(cls, v):
        if v and not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError("Invalid characters in identifier")
        return v

    class Config:
        schema_extra = {
            "example": {
                "model_name": "mistralai/Mistral-7B-Instruct-v0.3",
                "provider": "vast",
                "prompt": "Tell me about the universe",
                "max_length": 512,
                "temperature": 0.7
            }
        }

# Response Models
class GenerateResponse(BaseModel):
    request_id: str
    result: str
    model: str
    provider: str
    timing: Dict[str, float]

class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: str
    providers: Dict[str, str]

class ErrorResponse(BaseModel):
    error: str
    detail: str
    request_id: str

# Middleware
@app.middleware("http")
async def add_request_id_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    request.state.start_time = time.time()
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    process_time = time.time() - request.state.start_time
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# Issue: Potential memory leak in RateLimiter
class RateLimiter:
    def __init__(self, requests_per_minute: int = 60):
        self._requests = defaultdict(list)  # No cleanup of old api_keys
        # Need periodic cleanup of inactive api_keys

# Fix:
    async def _cleanup_old_keys(self):
        async with self._lock:
            now = time()
            stale_keys = [
                key for key, times in self._requests.items()
                if not times or (now - max(times)) > 3600  # Remove keys inactive for 1 hour
            ]
            for key in stale_keys:
                del self._requests[key]

        self._lock = Lock()
        
    async def check_rate_limit(self, api_key: str) -> bool:
        async with self._lock:
            now = time()
            # Clean old requests
            self._requests[api_key] = [
                req_time for req_time in self._requests[api_key]
                if now - req_time < 60
            ]
            
            if len(self._requests[api_key]) >= self.limit:
                return False
                
            self._requests[api_key].append(now)
            return True

rate_limiter = RateLimiter()

# Security
class ApiKey(BaseModel):
    key: str
    owner: str
    expires: Optional[datetime]
    permissions: list[str]

# Issue: No cache expiration mechanism
class ApiKeyValidator:
    def __init__(self):
        self._cache = {}  # Can grow indefinitely

# Fix:
from cachetools import TTLCache

class ApiKeyValidator:
    def __init__(self):
        self._cache = TTLCache(maxsize=1000, ttl=3600)  # 1 hour TTL
        self._cache_lock = Lock()
    
    async def validate_key(self, api_key: str) -> ApiKey:
        if not api_key or not api_key.startswith('sk-'):
            raise HTTPException(
                status_code=401,
                detail="Invalid API key format"
            )
        
        # Check cache first
        async with self._cache_lock:
            if api_key in self._cache:
                key_data = self._cache[api_key]
                if key_data.expires and key_data.expires < datetime.utcnow():
                    del self._cache[api_key]
                else:
                    return key_data
        
        # Verify against database
        key_data = await self._verify_key_in_db(api_key)
        if not key_data:
            raise HTTPException(
                status_code=401,
                detail="Invalid API key"
            )
        
        # Cache the result
        async with self._cache_lock:
            self._cache[api_key] = key_data
            
        return key_data
    
    async def _verify_key_in_db(self, api_key: str) -> Optional[ApiKey]:
        # Implement actual database verification here
        pass

api_key_validator = ApiKeyValidator()

async def verify_api_key(
    api_key: str = Depends(api_key_header),
    request: Request = None
) -> ApiKey:
    key_data = await api_key_validator.validate_key(api_key)
    if request:
        request.state.api_key_data = key_data
    return key_data

# Scattered error handling
class ErrorCode(Enum):
    INVALID_INPUT = "INVALID_INPUT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    RATE_LIMIT = "RATE_LIMIT"
    INTERNAL_ERROR = "INTERNAL_ERROR"

class APIError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        status_code: int = 500,
        details: Optional[Any] = None
    ):
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(message)

@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.code.value,
            "message": exc.message,
            "request_id": request.state.request_id,
            "details": exc.details,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# Error Handlers
@app.exception_handler(ZaphodError)
async def zaphod_exception_handler(request: Request, exc: ZaphodError):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.__class__.__name__,
            detail=str(exc),
            request_id=request.state.request_id
        ).dict()
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unexpected error: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="InternalServerError",
            detail="An unexpected error occurred",
            request_id=request.state.request_id
        ).dict()
    )

# Routes
@app.post("/api/v1/generate", response_model=GenerateResponse)
async def generate_text(
    request: GenerateRequest,
    api_key: str = Depends(verify_api_key),
    request_id: str = None
):
    start_time = time.time()
    provider = None
    
    try:
        provider, endpoint_config = get_provider_and_config('generate', request.provider)
        
        # Merge request parameters with endpoint configuration
        max_tokens = min(
            request.max_length,
            endpoint_config.get('max_tokens', 2048)
        )
        
        temperature = request.temperature or endpoint_config.get('temperature', 0.7)
        
        # Generate text
        output = provider.generate(
            prompt=request.prompt,
            max_tokens=max_tokens,
            temperature=temperature,
            model_id=request.model_name
        )
        
        process_time = time.time() - start_time
        
        response = GenerateResponse(
            request_id=request_id or str(uuid.uuid4()),
            result=output.get('generated_text', ''),
            model=request.model_name,
            provider=provider.__class__.__name__,
            timing={
                'total_time': process_time,
                'generation_time': process_time
            }
        )
        
        # Record metrics
        metrics.record_request(
            endpoint='/api/v1/generate',
            provider=provider.__class__.__name__,
            status='success',
            duration=process_time
        )
        
        return response
        
    except Exception as e:
        if provider:
            metrics.record_request(
                endpoint='/api/v1/generate',
                provider=provider.__class__.__name__,
                status='error',
                duration=time.time() - start_time
            )
        raise

@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check():
    """Check system health status"""
    status = {
        "status": "healthy",
        "version": VERSION,
        "timestamp": datetime.utcnow().isoformat(),
        "providers": {}
    }
    
    all_healthy = True
    for name, provider in registry.providers.items():
        try:
            provider_healthy = provider.is_healthy()
            status["providers"][name] = "healthy" if provider_healthy else "unhealthy"
            all_healthy &= provider_healthy
        except Exception as e:
            status["providers"][name] = f"error: {str(e)}"
            all_healthy = False
    
    if not all_healthy:
        status["status"] = "degraded"
    
    return status

@app.get("/api/v1/models")
async def list_models(
    api_key: str = Depends(verify_api_key)
):
    """List available models"""
    return {
        "models": registry.list_models(),
        "default_provider": registry.config['system']['default_provider']
    }

# Utility functions
def get_provider_and_config(endpoint_name: str, provider_name: Optional[str] = None) -> tuple:
    """Get provider and endpoint configuration"""
    try:
        endpoint_config = registry.get_endpoint_config(endpoint_name) or {}
        
        # Get provider
        if provider_name:
            provider = registry.get_provider(provider_name)
            if not provider:
                logger.warning(f"Requested provider {provider_name} not found, falling back to default")
                provider = registry.get_default_provider()
        else:
            preferred_provider = endpoint_config.get('preferred_provider')
            provider = (registry.get_provider(preferred_provider) 
                      if preferred_provider 
                      else registry.get_default_provider())
        
        if not provider:
            raise HTTPException(
                status_code=503,
                detail="No available providers"
            )
            
        return provider, endpoint_config
        
    except Exception as e:
        logger.error(f"Error getting provider and config: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize provider"
        )

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
    expose_headers=["X-Request-ID"]
)

# Startup and shutdown events
@app.on_event("startup")
async def startup_event():
    logger.info("Starting up server...")
    # Additional startup tasks can be added here

# Issue: Cleanup chain might break if one provider fails
    async def cleanup(self):
        cleanup_results = await asyncio.gather(*cleanup_tasks, return_exceptions=True)
        for provider, result in zip(self.providers.values(), cleanup_results):
            if isinstance(result, Exception):
                logger.error(f"Failed to cleanup provider {provider.__class__.__name__}: {result}")
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down server...")
    # Cleanup tasks can be added here
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
# Add these new imports
from .health import router as health_router
from .middleware import RequestIDMiddleware
from .schemas import GenerateRequest

# Your existing app initialization
app = FastAPI()

# Add RequestIDMiddleware before other middleware
app.add_middleware(RequestIDMiddleware)

# Your existing CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=settings.ALLOWED_METHODS,
    allow_headers=settings.ALLOWED_HEADERS,
    expose_headers=["X-Request-ID"]  # Add this to expose request ID header
)

# Include the health router
app.include_router(health_router)

# Update your existing generate endpoint to use the new schema
@app.post("/generate")
async def generate_text(
    request: GenerateRequest,  # Updated to use the new schema
    api_key: ApiKey = Depends(verify_api_key)
):
    try:
        # Your existing rate limit check
        if not await rate_limiter.check_rate_limit(api_key):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        result = await registry.generate(
            prompt=request.prompt,
            max_length=request.max_length,
            temperature=request.temperature,
            provider=request.provider,
            stop_sequences=request.stop_sequences
        )

        # Record metrics
        metrics.record_request(
            endpoint="/generate",
            provider=request.provider or "default",
            status="success",
            duration=result.get("duration", 0)
        )

        return result

    except Exception as e:
        metrics.record_request(
            endpoint="/generate",
            provider=request.provider or "default",
            status="error",
            duration=0
        )
        raise
# server.py - Updated with correct error handling and dependencies
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime

# Local imports
from .health import router as health_router
from .middleware import RequestIDMiddleware
from .schemas import GenerateRequest
from .auth import ApiKeyValidator, ApiKey, verify_api_key
from .rate_limiter import RateLimiter
from .registry import ModelRegistry

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize components
app = FastAPI()
rate_limiter = RateLimiter()
registry = ModelRegistry()
api_key_validator = ApiKeyValidator()

# Add middleware in correct order
app.add_middleware(RequestIDMiddleware)  # Must be first
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
    try:
        if not await rate_limiter.check_rate_limit(api_key):
            raise HTTPException(status_code=429, detail="Rate limit exceeded")

        start_time = datetime.utcnow()
        result = await registry.generate(
            prompt=request.prompt,
            max_length=request.max_length,
            temperature=request.temperature,
            provider=request.provider,
            stop_sequences=request.stop_sequences
        )
        duration = (datetime.utcnow() - start_time).total_seconds()

        # Record metrics
        metrics.record_request(
            endpoint="/generate",
            provider=request.provider or "default",
            status="success",
            duration=duration
        )

        return result

    except Exception as e:
        logger.exception("Generation failed")
        metrics.record_request(
            endpoint="/generate",
            provider=request.provider or "default",
            status="error",
            duration=0
        )
        raise