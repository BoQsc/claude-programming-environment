from aiohttp import web
import hashlib
import secrets
import time
import json
from db import create_database, create_unique_id

# Database initialization
db = create_database('./api_data')

def hash_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(32)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return salt.hex(), hash_bytes.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return secrets.compare_digest(hash_bytes.hex(), hash_hex)

def generate_token() -> str:
    return secrets.token_urlsafe(32)

async def get_user_from_token(token: str):
    sessions = await db.get_collection('sessions')
    session = await sessions.get(token)
    if not session:
        return None
    if time.time() > session['expires_at']:
        await sessions.delete(token)
        return None
    
    users = await db.get_collection('users')
    return await users.get(session['username'])

# Clean up expired sessions periodically
async def cleanup_expired_sessions():
    while True:
        try:
            await asyncio.sleep(300)  # Every 5 minutes
            sessions = await db.get_collection('sessions')
            
            expired_tokens = []
            current_time = time.time()
            
            for token, session in await sessions.items():
                if current_time > session['expires_at']:
                    expired_tokens.append(token)
            
            for token in expired_tokens:
                await sessions.delete(token)
                
            if expired_tokens:
                print(f"Cleaned up {len(expired_tokens)} expired sessions")
                
        except Exception as e:
            print(f"Error during session cleanup: {e}")

# Rate limiting
from collections import defaultdict
import functools

rate_limits = defaultdict(list)  # {key: [timestamp1, timestamp2, ...]}

def rate_limit(max_requests=10, window_seconds=60, key_func=None):
    def decorator(handler):
        @functools.wraps(handler)  # This preserves the original function metadata
        async def wrapper(request):
            # Determine rate limit key
            if key_func:
                key = key_func(request)
            else:
                # Default: use IP for public endpoints, user for auth endpoints
                if hasattr(handler, '__wrapped__'):  # Has @require_auth
                    auth_header = request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer '):
                        token = auth_header[7:]
                        sessions = await db.get_collection('sessions')
                        session = await sessions.get(token)
                        key = f"user:{session['username']}" if session else f"ip:{request.remote}"
                    else:
                        key = f"ip:{request.remote}"
                else:
                    key = f"ip:{request.remote}"
            
            now = time.time()
            
            # Clean up old requests outside the window
            rate_limits[key] = [req_time for req_time in rate_limits[key] 
                               if now - req_time < window_seconds]
            
            # Check if rate limit exceeded
            if len(rate_limits[key]) >= max_requests:
                return web.json_response({
                    'error': 'Rate limit exceeded',
                    'retry_after': window_seconds
                }, status=429)
            
            # Record this request
            rate_limits[key].append(now)
            
            return await handler(request)
        return wrapper
    return decorator

# Auth decorator for protected endpoints
def require_auth(handler):
    @functools.wraps(handler)  # This preserves the original function metadata
    async def wrapper(request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return web.Response(text='Unauthorized', status=401)
        
        token = auth_header[7:]  # Remove 'Bearer '
        user = await get_user_from_token(token)
        if not user:
            return web.Response(text='Invalid token', status=401)
        
        request['user'] = user
        return await handler(request)
    return wrapper

# Public endpoints
@rate_limit(max_requests=5, window_seconds=300)  # 5 registrations per 5 minutes per IP
async def post_register(request):
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        users = await db.get_collection('users')
        
        if await users.exists(username):
            return web.json_response({'error': 'User already exists'}, status=400)
        
        salt, password_hash = hash_password(password)
        await users.set(username, {
            'username': username,
            'salt': salt,
            'password_hash': password_hash,
            'created_at': time.time()
        })
        
        return web.json_response({'message': 'User created successfully'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

@rate_limit(max_requests=10, window_seconds=300)  # 10 login attempts per 5 minutes per IP
async def post_login(request):
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        users = await db.get_collection('users')
        user = await users.get(username)
        
        if not user or not verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        token = generate_token()
        sessions = await db.get_collection('sessions')
        await sessions.set(token, {
            'username': username,
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour
        })
        
        return web.json_response({'token': token, 'expires_in': 3600})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

@rate_limit(max_requests=100, window_seconds=60)  # 100 per minute
async def post_logout(request):
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        sessions = await db.get_collection('sessions')
        await sessions.delete(token)
    return web.json_response({'message': 'Logged out'})

# Protected endpoints
@rate_limit(max_requests=200, window_seconds=60)  # 200 per minute per user
@require_auth
async def get_profile(request):
    user = request['user']
    return web.json_response({
        'username': user['username'],
        'created_at': user['created_at']
    })

@rate_limit(max_requests=50, window_seconds=60)   # 50 per minute per user
@require_auth
async def get_users(request):
    users = await db.get_collection('users')
    all_users = await users.values()
    return web.json_response({
        'users': [{'username': u['username'], 'created_at': u['created_at']} for u in all_users]
    })

@rate_limit(max_requests=100, window_seconds=60)  # 100 per minute per user
@require_auth
async def get_users_id(request):
    username = request.match_info['id']
    users = await db.get_collection('users')
    user = await users.get(username)
    if not user:
        return web.json_response({'error': 'User not found'}, status=404)
    return web.json_response({
        'username': user['username'], 
        'created_at': user['created_at']
    })

@rate_limit(max_requests=5, window_seconds=300)   # 5 deletions per 5 minutes per user
@require_auth
async def delete_users_id(request):
    current_user = request['user']
    username = request.match_info['id']
    
    # Only allow users to delete themselves (add admin logic as needed)
    if current_user['username'] != username:
        return web.json_response({'error': 'Forbidden'}, status=403)
    
    users = await db.get_collection('users')
    if not await users.exists(username):
        return web.json_response({'error': 'User not found'}, status=404)
    
    await users.delete(username)
    
    # Clean up user sessions
    sessions = await db.get_collection('sessions')
    user_sessions = []
    
    for token, session in await sessions.items():
        if session['username'] == username:
            user_sessions.append(token)
    
    for token in user_sessions:
        await sessions.delete(token)
    
    return web.json_response({'message': 'User deleted'})

# Admin endpoints
@rate_limit(max_requests=10, window_seconds=60)
@require_auth  
async def get_admin_stats(request):
    # Simple admin endpoint
    users = await db.get_collection('users')
    sessions = await db.get_collection('sessions')
    
    user_count = await users.count()
    session_count = await sessions.count()
    
    return web.json_response({
        'total_users': user_count,
        'active_sessions': session_count,
        'database_collections': await db.list_collections()
    })

# File watching for auto-reload
import os, sys, threading
def watch_file():
    original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    while True: 
        time.sleep(2)
        current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        if current_hash != original_hash:
            os.execv(sys.executable, ['python'] + sys.argv)
threading.Thread(target=watch_file, daemon=True).start()

# Auto-routing
import re, inspect, asyncio
app = web.Application()

def debug_auto_routing():
    """Debug function to trace auto-routing logic"""
    print("\n🔍 Auto-routing Debug:")
    for name, handler in list(globals().items()):
        for method in ['get', 'post', 'put', 'delete', 'patch']:
            if name.startswith(f"{method}_"):
                print(f"  Processing: {name}")
                route_parts = name[len(method)+1:].split('_')
                print(f"    Initial route_parts: {route_parts}")
                
                # Get the original function source (handle decorators)
                original_func = handler
                while hasattr(original_func, '__wrapped__'):
                    original_func = original_func.__wrapped__
                
                try:
                    source = inspect.getsource(original_func)
                except:
                    # Fallback to handler source if original fails
                    source = inspect.getsource(handler)
                
                params = re.findall(r"request\.match_info\['(\w+)'\]", source)
                print(f"    Found parameters: {params}")
                print(f"    Source snippet: {repr(source[:200])}")
                
                # Fixed parameter replacement logic
                for param in params:
                    param_parts = param.split('_')
                    print(f"    Looking for param '{param}' as parts {param_parts}")
                    
                    # Find exact match in route_parts
                    for i in range(len(route_parts) - len(param_parts) + 1):
                        if route_parts[i:i+len(param_parts)] == param_parts:
                            print(f"    Found match at position {i}: {route_parts[i:i+len(param_parts)]} -> {{{param}}}")
                            route_parts[i:i+len(param_parts)] = [f'{{{param}}}']
                            break
                
                route = '/' + '/'.join(route_parts)
                print(f"    Final route: {route}\n")
                break

# Run debug first
debug_auto_routing()

for name, handler in list(globals().items()):
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route_parts = name[len(method)+1:].split('_')
            
            # Get the original function source (handle decorators)
            original_func = handler
            while hasattr(original_func, '__wrapped__'):
                original_func = original_func.__wrapped__
            
            try:
                source = inspect.getsource(original_func)
            except:
                # Fallback to handler source if original fails
                source = inspect.getsource(handler)
            
            params = re.findall(r"request\.match_info\['(\w+)'\]", source)
            
            # Fixed parameter replacement logic
            for param in params:
                param_parts = param.split('_')
                # Find exact match in route_parts
                for i in range(len(route_parts) - len(param_parts) + 1):
                    if route_parts[i:i+len(param_parts)] == param_parts:
                        route_parts[i:i+len(param_parts)] = [f'{{{param}}}']
                        break
            
            route = '/' + '/'.join(route_parts)
            app.router.add_route(method.upper(), route, handler)
            print(f"Registered: {method.upper()} {route}")
            break

async def init_app():
    """Initialize the application with background tasks"""
    # Start session cleanup task
    asyncio.create_task(cleanup_expired_sessions())
    return app

if __name__ == '__main__':
    print("\n🗄️  API with Persistent Database")
    print("Database: AsyncJSONDB at ./api_data/")
    print("\nEndpoints:")
    print("- POST /register - Create account")
    print("- POST /login - Get auth token") 
    print("- POST /logout - Logout")
    print("- GET /profile - User profile (auth required)")
    print("- GET /users - List users (auth required)")
    print("- GET /users/{id} - Get user (auth required)")
    print("- DELETE /users/{id} - Delete user (auth required)")
    print("- GET /admin/stats - Admin stats (auth required)")
    print("\nTry these commands:")
    print("curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/profile")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/admin/stats")
    
    web.run_app(init_app(), host='localhost', port=8080)