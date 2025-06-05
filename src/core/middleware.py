"""
Custom middleware for the FastAPI application.
"""
import time
import logging
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import uuid
import json

# Set up logging
logger = logging.getLogger(__name__)

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for logging request and response information.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)
    
    async def dispatch(self, request: Request, call_next):
        """
        Process the request and log information.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler
            
        Returns:
            Response: The response from the next handler
        """
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        
        # Log request details
        client_host = request.client.host if request.client else "unknown"
        logger.info(f"Request {request_id} started: {request.method} {request.url.path} from {client_host}")
        
        # Record request start time
        start_time = time.time()
        
        # Process the request
        try:
            response = await call_next(request)
            
            # Calculate processing time
            process_time = time.time() - start_time
            
            # Add custom headers
            response.headers["X-Process-Time"] = str(process_time)
            response.headers["X-Request-ID"] = request_id
            
            # Log response details
            logger.info(
                f"Request {request_id} completed: {request.method} {request.url.path} "
                f"- Status: {response.status_code} - Duration: {process_time:.4f}s"
            )
            
            return response
        except Exception as e:
            # Log exception details
            process_time = time.time() - start_time
            logger.error(
                f"Request {request_id} failed: {request.method} {request.url.path} "
                f"- Error: {str(e)} - Duration: {process_time:.4f}s"
            )
            raise


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware for basic rate limiting.
    
    This is a simple in-memory rate limiter. For production,
    consider using Redis or another distributed cache.
    """
    def __init__(self, app: ASGIApp, rate_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.requests = {}  # IP -> [timestamp1, timestamp2, ...]
    
    async def dispatch(self, request: Request, call_next):
        """
        Process the request with rate limiting.
        
        Args:
            request: The incoming request
            call_next: The next middleware or endpoint handler
            
        Returns:
            Response: The response from the next handler or a 429 response
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Current time
        now = time.time()
        
        # Clean up old requests
        if client_ip in self.requests:
            self.requests[client_ip] = [
                timestamp for timestamp in self.requests[client_ip]
                if now - timestamp < self.window_seconds
            ]
        else:
            self.requests[client_ip] = []
        
        # Check rate limit
        if len(self.requests[client_ip]) >= self.rate_limit:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            return Response(
                content=json.dumps({"detail": "Rate limit exceeded"}),
                status_code=429,
                media_type="application/json"
            )
        
        # Add current request
        self.requests[client_ip].append(now)
        
        # Process the request
        return await call_next(request)


def setup_middlewares(app):
    """
    Set up all custom middlewares for the application.
    
    Args:
        app: FastAPI application instance
    """
    app.add_middleware(RequestLoggingMiddleware)
    # Uncomment to enable rate limiting
    # app.add_middleware(RateLimitMiddleware, rate_limit=100, window_seconds=60)
