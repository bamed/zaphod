# Standard library
import logging
import uuid
from contextvars import ContextVar

# Third-party imports
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# No local imports needed

logger = logging.getLogger(__name__)
request_id_context = ContextVar("request_id", default=None)

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        token = request_id_context.set(request_id)
        
        try:
            response = await call_next(request)
            if isinstance(response, Response):
                response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_context.reset(token)