import uuid
import logging
from contextvars import ContextVar
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

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
        except Exception as e:
            logger.error(f"Error processing request {request_id}: {str(e)}")
            raise
        finally:
            request_id_context.reset(token)