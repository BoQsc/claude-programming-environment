import json
import asyncio
import traceback
from typing import Dict, Any, Callable, Optional, Union, List
from aiohttp import web, hdrs
from aiohttp.web_request import Request
from aiohttp.web_response import Response
import logging

logger = logging.getLogger(__name__)


class APIError(Exception):
    """Custom API exception with status code and message"""
    def __init__(self, message: str, status_code: int = 400, details: Optional[Dict] = None):
        self.message = message
        self.status_code = status_code
        self.details = details or {}
        super().__init__(self.message)


class WebApp:
    """Simplified abstraction layer over aiohttp"""
    
    def __init__(self, cors_origins: Optional[List[str]] = None):
        self.app = web.Application()
        self.routes = []
        self.middlewares = []
        self.cors_origins = cors_origins or ["*"]
        self._setup_middlewares()
    
    def _setup_middlewares(self):
        """Setup default middlewares"""
        self.app.middlewares.append(self._cors_middleware)
        self.app.middlewares.append(self._error_middleware)
        self.app.middlewares.append(self._json_middleware)
    
    @web.middleware
    async def _cors_middleware(self, request: Request, handler):
        """Handle CORS headers"""
        response = await handler(request)
        
        origin = request.headers.get('Origin', '')
        if self.cors_origins == ["*"] or origin in self.cors_origins:
            response.headers['Access-Control-Allow-Origin'] = origin or "*"
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            response.headers['Access-Control-Max-Age'] = '86400'
        
        return response
    
    @web.middleware
    async def _error_middleware(self, request: Request, handler):
        """Global error handling middleware"""
        try:
            return await handler(request)
        except APIError as e:
            logger.warning(f"API Error: {e.message} (Status: {e.status_code})")
            return self.json_response({
                'error': e.message,
                'details': e.details
            }, status=e.status_code)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
            return self.json_response({
                'error': 'Internal server error'
            }, status=500)
    
    @web.middleware
    async def _json_middleware(self, request: Request, handler):
        """Automatically parse JSON request bodies"""
        # Skip JSON parsing for GET requests and requests without content-type
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            request.json_data = None
        elif request.method in ['POST', 'PUT', 'PATCH']:
            # Check if request has content-type and body
            content_type = request.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                try:
                    # Get content length to check if there's a body
                    content_length = request.headers.get('Content-Length', '0')
                    
                    if int(content_length) > 0:
                        request.json_data = await request.json()
                    else:
                        request.json_data = None
                        
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid JSON in request: {e}")
                    raise APIError("Invalid JSON in request body", 400)
                except ValueError as e:
                    logger.warning(f"JSON parsing error: {e}")
                    request.json_data = None
                except Exception as e:
                    logger.warning(f"Unexpected JSON parsing error: {e}")
                    request.json_data = None
            else:
                request.json_data = None
        else:
            request.json_data = None
        
        return await handler(request)
    
    def route(self, method: str, path: str):
        """Decorator for registering routes"""
        def decorator(func: Callable):
            async def wrapper(request: Request):
                return await func(request)
            
            self.routes.append((method.upper(), path, wrapper))
            return wrapper
        return decorator
    
    def get(self, path: str):
        """Decorator for GET routes"""
        return self.route('GET', path)
    
    def post(self, path: str):
        """Decorator for POST routes"""
        return self.route('POST', path)
    
    def put(self, path: str):
        """Decorator for PUT routes"""
        return self.route('PUT', path)
    
    def delete(self, path: str):
        """Decorator for DELETE routes"""
        return self.route('DELETE', path)
    
    def options(self, path: str):
        """Decorator for OPTIONS routes (useful for CORS preflight)"""
        return self.route('OPTIONS', path)
    
    def middleware(self, func: Callable):
        """Decorator for custom middleware"""
        @web.middleware
        async def middleware_wrapper(request: Request, handler):
            return await func(request, handler)
        
        self.middlewares.append(middleware_wrapper)
        self.app.middlewares.append(middleware_wrapper)
        return func
    
    def json_response(self, data: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
        """Create a JSON response"""
        response_headers = {'Content-Type': 'application/json'}
        if headers:
            response_headers.update(headers)
        
        return web.Response(
            text=json.dumps(data, indent=2, default=str),
            status=status,
            headers=response_headers
        )
    
    def text_response(self, text: str, status: int = 200, headers: Optional[Dict[str, str]] = None) -> Response:
        """Create a text response"""
        response_headers = {'Content-Type': 'text/plain'}
        if headers:
            response_headers.update(headers)
        
        return web.Response(
            text=text,
            status=status,
            headers=response_headers
        )
    
    def register_routes(self):
        """Register all defined routes with the aiohttp app"""
        for method, path, handler in self.routes:
            self.app.router.add_route(method, path, handler)
    
    def add_static(self, prefix: str, path: str):
        """Add static file serving"""
        self.app.router.add_static(prefix, path)
    
    async def startup(self):
        """Application startup hook"""
        logger.info("Application starting up...")
    
    async def cleanup(self):
        """Application cleanup hook"""
        logger.info("Application shutting down...")
    
    def run(self, host: str = '0.0.0.0', port: int = 8080, debug: bool = False):
        """Run the web application"""
        self.register_routes()
        
        # Setup startup and cleanup
        self.app.on_startup.append(lambda app: self.startup())
        self.app.on_cleanup.append(lambda app: self.cleanup())
        
        logger.info(f"Starting server on {host}:{port}")
        web.run_app(self.app, host=host, port=port, access_log=logger if debug else None)


# Utility functions for common request operations
def get_json_data(request: Request) -> Dict[str, Any]:
    """Get JSON data from request (parsed by middleware)"""
    if not hasattr(request, 'json_data') or request.json_data is None:
        raise APIError("Request must contain valid JSON", 400)
    return request.json_data


def get_query_params(request: Request) -> Dict[str, str]:
    """Get query parameters from request"""
    return dict(request.query)


def get_path_params(request: Request) -> Dict[str, str]:
    """Get path parameters from request"""
    return dict(request.match_info)


def require_fields(data: Dict[str, Any], fields: List[str]) -> None:
    """Validate that required fields are present in data"""
    missing = [field for field in fields if field not in data or data[field] is None]
    if missing:
        raise APIError(f"Missing required fields: {', '.join(missing)}", 400)


def validate_field_types(data: Dict[str, Any], field_types: Dict[str, type]) -> None:
    """Validate field types in data"""
    for field, expected_type in field_types.items():
        if field in data and data[field] is not None and not isinstance(data[field], expected_type):
            raise APIError(f"Field '{field}' must be of type {expected_type.__name__}", 400)


# Example usage functions
async def handle_options(request: Request) -> Response:
    """Standard OPTIONS handler for CORS preflight"""
    return web.Response(status=200)


def create_app(**kwargs) -> WebApp:
    """Factory function to create a WebApp instance"""
    return WebApp(**kwargs)