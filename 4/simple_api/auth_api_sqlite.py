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
        await DB._execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT, password_hash TEXT, created_at REAL, last_login REAL)")
        await DB._execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at REAL, expires_at REAL, ip_address TEXT, user_agent TEXT, FOREIGN KEY (user_id) REFERENCES users (id))")
    
    @staticmethod
    async def create_user(username, salt, password_hash):
        cursor = await DB._execute("INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)", (username, salt, password_hash, time.time()))
        return cursor.lastrowid if hasattr(cursor, 'lastrowid') else None
    
    @staticmethod
    async def get_user_by_id(user_id):
        return await DB._execute("SELECT * FROM users WHERE id = ?", (user_id,), 'one')
    
    @staticmethod
    async def get_user_by_username(username):
        return await DB._execute("SELECT * FROM users WHERE username = ?", (username,), 'one')
    
    @staticmethod
    async def user_exists(username):
        result = await DB._execute("SELECT 1 FROM users WHERE username = ?", (username,), 'one')
        return result is not None
    
    @staticmethod
    async def create_session(token, user_id, expires_at, ip=None, agent=None):
        await DB._execute("INSERT INTO sessions (token, user_id, created_at, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)", 
                         (token, user_id, time.time(), expires_at, ip, agent))
    
    @staticmethod
    async def get_user_by_token(token):
        return await DB._execute("SELECT u.* FROM users u JOIN sessions s ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ?", 
                                (token, time.time()), 'one')
    
    @staticmethod
    async def delete_session(token):
        await DB._execute("DELETE FROM sessions WHERE token = ?", (token,))
    
    @staticmethod
    async def update_last_login(user_id):
        await DB._execute("UPDATE users SET last_login = ? WHERE id = ?", (time.time(), user_id))
    
    @staticmethod
    async def get_all_users():
        return await DB._execute("SELECT id, username, created_at, last_login FROM users ORDER BY id", fetch='all')
    
    @staticmethod
    async def delete_user(user_id):
        """Hard delete user and all their sessions"""
        async with aiosqlite.connect(DB_PATH) as db:
            # Delete all user sessions first
            await db.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            # Delete the user record
            result = await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
            await db.commit()
            return result.rowcount > 0
    
    @staticmethod
    async def update_user_password(user_id, salt, password_hash):
        await DB._execute("UPDATE users SET salt = ?, password_hash = ? WHERE id = ?", (salt, password_hash, user_id))
    
    @staticmethod
    async def cleanup_sessions():
        await DB._execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))

# Async password functions - single line implementations
async def hash_password(password: str) -> tuple[str, str]:
    return await asyncio.get_event_loop().run_in_executor(None, lambda: (lambda s: (s.hex(), hashlib.pbkdf2_hmac('sha256', password.encode(), s, 600_000).hex()))(secrets.token_bytes(32)))

async def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    return await asyncio.get_event_loop().run_in_executor(None, lambda: secrets.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 600_000).hex(), hash_hex))

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
        
        salt, hash_val = await hash_password(password)
        user_id = await DB.create_user(username, salt, hash_val)
        
        return web.json_response({
            'message': 'User created',
            'user_id': user_id,
            'username': username
        })
    
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
        if not await verify_password(current_password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Current password incorrect'}, status=400)
        
        if len(new_password) < 6:
            return web.json_response({'error': 'New password min 6 chars'}, status=400)
        
        salt, hash_val = await hash_password(new_password)
        await DB.update_user_password(user['id'], salt, hash_val)
        return web.json_response({'message': 'Password changed'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def post_login(request):
    try:
        data = await request.json()
        username, password = data['username'], data['password']
        
        user = await DB.get_user_by_username(username)
        if not user or not await verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        token = generate_token()
        await DB.create_session(token, user['id'], time.time() + 3600, request.remote, request.headers.get('User-Agent'))
        await DB.update_last_login(user['id'])
        
        return web.json_response({
            'token': token, 
            'expires_in': 3600,
            'user_id': user['id'],
            'username': user['username']
        })
    
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
    return web.json_response({
        'id': user['id'],
        'username': user['username'], 
        'created_at': user['created_at'], 
        'last_login': user['last_login']
    })

@require_auth
async def get_users(request):
    users = await DB.get_all_users()
    return web.json_response({'users': [dict(u) for u in users]})

@require_auth
async def get_users_id(request):
    try:
        user_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid user ID'}, status=400)
    
    user = await DB.get_user_by_id(user_id)
    if not user:
        return web.json_response({'error': 'User not found'}, status=404)
    
    return web.json_response({
        'id': user['id'],
        'username': user['username'],
        'created_at': user['created_at'],
        'last_login': user['last_login']
    })

@require_auth
async def delete_users_id(request):
    current_user = request['user']
    
    try:
        user_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid user ID'}, status=400)
    
    print(f"🗑️  Delete request: current_user_id={current_user['id']}, target_id={user_id}")
    
    # Check if the current user is trying to delete themselves
    if current_user['id'] != user_id:
        print(f"❌ User {current_user['id']} cannot delete user {user_id}")
        return web.json_response({'error': 'Forbidden: Can only delete your own account'}, status=403)
    
    print(f"✅ Deleting user {user_id}")
    deleted = await DB.delete_user(user_id)
    
    if not deleted:
        print(f"❌ User {user_id} not found")
        return web.json_response({'error': 'User not found'}, status=404)
    
    print(f"✅ User {user_id} deleted successfully")
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
    print("🔐 Auth API with SQLite - ASYNC PASSWORD HASHING VERSION WITH UNIQUE IDS")
    print("\nRegistered routes:")
    for resource in app.router.resources():
        print(f"  {resource}")
    print("\nAPI Commands:")
    print("curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/profile")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/users")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/users/1")
    print("curl -X DELETE -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/users/1")
    web.run_app(app, host='localhost', port=8080)