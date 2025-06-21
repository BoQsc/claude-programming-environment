from aiohttp import web
import aiosqlite
import hashlib
import secrets
import time
import json
import asyncio

DB_PATH = "auth.db"

class DB:
    @staticmethod
    async def _execute(query, params=None, fetch=None):
        async with aiosqlite.connect(DB_PATH) as db:
            if fetch:
                db.row_factory = aiosqlite.Row
            cursor = await db.execute(query, params or ())
            if fetch == 'one':
                result = await cursor.fetchone()
            elif fetch == 'all':
                result = await cursor.fetchall()
            else:
                result = None
            await db.commit()
            return result
    
    @staticmethod
    async def init():
        await DB._execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT, password_hash TEXT, created_at REAL, is_active BOOLEAN DEFAULT 1, last_login REAL)")
        await DB._execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, created_at REAL, expires_at REAL, ip_address TEXT, user_agent TEXT)")
    
    @staticmethod
    async def create_user(username, salt, password_hash):
        await DB._execute("INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)", (username, salt, password_hash, time.time()))
    
    @staticmethod
    async def get_user(username):
        return await DB._execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,), 'one')
    
    @staticmethod
    async def user_exists(username):
        result = await DB._execute("SELECT 1 FROM users WHERE username = ?", (username,), 'one')
        return result is not None
    
    @staticmethod
    async def create_session(token, username, expires_at, ip=None, agent=None):
        await DB._execute("INSERT INTO sessions (token, username, created_at, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)", 
                         (token, username, time.time(), expires_at, ip, agent))
    
    @staticmethod
    async def get_user_by_token(token):
        return await DB._execute("SELECT u.* FROM users u JOIN sessions s ON u.username = s.username WHERE s.token = ? AND s.expires_at > ? AND u.is_active = 1", 
                                (token, time.time()), 'one')
    
    @staticmethod
    async def delete_session(token):
        await DB._execute("DELETE FROM sessions WHERE token = ?", (token,))
    
    @staticmethod
    async def update_last_login(username):
        await DB._execute("UPDATE users SET last_login = ? WHERE username = ?", (time.time(), username))
    
    @staticmethod
    async def get_all_users():
        return await DB._execute("SELECT username, created_at, last_login FROM users WHERE is_active = 1", fetch='all')
    
    @staticmethod
    async def delete_user(username):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
            await db.execute("DELETE FROM sessions WHERE username = ?", (username,))
            await db.commit()
    
    @staticmethod
    async def cleanup_sessions():
        await DB._execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))

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

@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        response = web.Response()
    else:
        response = await handler(request)
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

def require_auth(handler):
    async def wrapper(request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return web.Response(text='Unauthorized', status=401)
        
        token = auth_header[7:]
        user = await DB.get_user_by_token(token)
        if not user:
            return web.Response(text='Invalid token', status=401)
        
        request['user'] = user
        request['token'] = token
        return await handler(request)
    return wrapper

async def post_register(request):
    try:
        data = await request.json()
        username, password = data['username'], data['password']
        
        if len(username) < 3 or len(password) < 6:
            return web.json_response({'error': 'Username min 3 chars, password min 6'}, status=400)
        
        if await DB.user_exists(username):
            return web.json_response({'error': 'User exists'}, status=400)
        
        salt, hash_val = hash_password(password)
        await DB.create_user(username, salt, hash_val)
        return web.json_response({'message': 'User created'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def get_checkusername(request):
    username = request.query.get('username')
    if not username:
        return web.json_response({'error': 'Username required'}, status=400)
    exists = await DB.user_exists(username)
    return web.json_response({'available': not exists})

@require_auth
async def put_changepassword(request):
    try:
        data = await request.json()
        current_password, new_password = data['current_password'], data['new_password']
        
        user = request['user']
        if not verify_password(current_password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Current password incorrect'}, status=400)
        
        if len(new_password) < 6:
            return web.json_response({'error': 'New password min 6 chars'}, status=400)
        
        salt, hash_val = hash_password(new_password)
        await DB._execute("UPDATE users SET salt = ?, password_hash = ? WHERE username = ?", (salt, hash_val, user['username']))
        return web.json_response({'message': 'Password changed'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def post_login(request):
    try:
        data = await request.json()
        username, password = data['username'], data['password']
        
        user = await DB.get_user(username)
        if not user or not verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        token = generate_token()
        await DB.create_session(token, username, time.time() + 3600, request.remote, request.headers.get('User-Agent'))
        await DB.update_last_login(username)
        
        return web.json_response({'token': token, 'expires_in': 3600})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def post_logout(request):
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        await DB.delete_session(auth_header[7:])
    return web.json_response({'message': 'Logged out'})

@require_auth
async def get_profile(request):
    user = request['user']
    return web.json_response({'username': user['username'], 'created_at': user['created_at'], 'last_login': user['last_login']})

@require_auth
async def get_users(request):
    users = await DB.get_all_users()
    return web.json_response({'users': [dict(u) for u in users]})

@require_auth
async def get_users_id(request):
    user = await DB.get_user(request.match_info['id'])
    if not user:
        return web.json_response({'error': 'User not found'}, status=404)
    return web.json_response(dict(user))

@require_auth
async def delete_users_id(request):
    current_user = request['user']
    username = request.match_info['id']
    
    # First check if the user to be deleted exists
    user_to_delete = await DB.get_user(username)
    if not user_to_delete:
        return web.json_response({'error': 'User not found'}, status=404)
    
    # Then check if the current user is trying to delete themselves
    if current_user['username'] != username:
        return web.json_response({'error': 'Forbidden'}, status=403)
    
    await DB.delete_user(username)
    return web.json_response({'message': 'User deleted'})

async def cleanup_task():
    while True:
        await asyncio.sleep(300)
        await DB.cleanup_sessions()

# File watching
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
import re, inspect
app = web.Application(middlewares=[cors_middleware])

async def init_app():
    await DB.init()
    asyncio.create_task(cleanup_task())

app.on_startup.append(lambda app: init_app())

# First, explicitly register the problematic routes
app.router.add_route('GET', '/users/{id}', get_users_id)
app.router.add_route('DELETE', '/users/{id}', delete_users_id)
print(f"Registered: GET /users/{{id}}")
print(f"Registered: DELETE /users/{{id}}")

# Then auto-register the rest
for name, handler in list(globals().items()):
    # Skip the ones we manually registered
    if name in ['get_users_id', 'delete_users_id']:
        continue
        
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route_parts = name[len(method)+1:].split('_')
            source = inspect.getsource(handler)
            params = re.findall(r"request\.match_info\['(\w+)'\]", source)
            
            # Create route with parameters
            route_with_params = route_parts[:]
            for param in params:
                # Look for the parameter in route parts and replace with {param}
                if param in route_parts:
                    param_index = route_parts.index(param)
                    route_with_params[param_index] = f'{{{param}}}'
                elif param == 'id' and len(route_parts) > 1:
                    # Special handling for 'id' parameter - replace last part
                    route_with_params[-1] = f'{{{param}}}'
            
            route = '/' + '/'.join(route_with_params)
            app.router.add_route(method.upper(), route, handler)
            print(f"Registered: {method.upper()} {route}")
            break

if __name__ == '__main__':
    print("🔐 Auth API with SQLite")
    print("\nRegistered routes:")
    for resource in app.router.resources():
        print(f"  {resource}")
    print("\nAPI Commands:")
    print("curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/profile")
    web.run_app(app, host='localhost', port=8080)