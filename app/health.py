# Standard library
from datetime import datetime
from typing import Dict, Any
import logging

# Third-party
from fastapi import APIRouter, Depends
from pydantic import BaseModel

# Local
from rate_limiter import RateLimiter
from model_registry import ModelRegistry
from auth import ApiKeyValidator

# Initialize logger
logger = logging.getLogger(__name__)

class ComponentHealth(BaseModel):
    status: str
    details: Dict[str, Any] = {}
    last_check: datetime

class HealthStatus(BaseModel):
    status: str
    components: Dict[str, ComponentHealth]
    timestamp: datetime

router = APIRouter()

# Get component instances
def get_rate_limiter() -> RateLimiter:
    from server import rate_limiter
    return rate_limiter

def get_model_registry() -> ModelRegistry:
    from server import registry
    return registry

def get_api_validator() -> ApiKeyValidator:
    from server import api_key_validator
    return api_key_validator

@router.get("/health", response_model=HealthStatus)
async def health_check(
    rate_limiter: RateLimiter = Depends(get_rate_limiter),
    registry: ModelRegistry = Depends(get_model_registry),
    api_validator: ApiKeyValidator = Depends(get_api_validator)
) -> HealthStatus:
    components = {}
    overall_status = "healthy"

    # Check rate limiter
    try:
        rate_limiter_healthy = await rate_limiter.is_healthy()
        components["rate_limiter"] = ComponentHealth(
            status="healthy" if rate_limiter_healthy else "unhealthy",
            last_check=datetime.utcnow()
        )
        if not rate_limiter_healthy:
            overall_status = "degraded"
    except Exception as e:
        logger.error(f"Rate limiter health check failed: {e}")
        components["rate_limiter"] = ComponentHealth(
            status="unhealthy",
            details={"error": str(e)},
            last_check=datetime.utcnow()
        )
        overall_status = "degraded"

    # Check registry
    try:
        if not registry._initialized:
            raise RuntimeError("Registry not initialized")
        registry_status = await registry.get_health_status()
        components["model_registry"] = ComponentHealth(
            status="healthy" if all(registry_status.values()) else "degraded",
            details=registry_status,
            last_check=datetime.utcnow()
        )
        if not all(registry_status.values()):
            overall_status = "degraded"
    except Exception as e:
        logger.error(f"Registry health check failed: {e}")
        components["model_registry"] = ComponentHealth(
            status="unhealthy",
            details={"error": str(e)},
            last_check=datetime.utcnow()
        )
        overall_status = "unhealthy"

    return HealthStatus(
        status=overall_status,
        components=components,
        timestamp=datetime.utcnow()
    )