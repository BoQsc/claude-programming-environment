from aiohttp import web
import hashlib
import secrets
import time
import json

# In-memory stores (use a database in production)
users = {}
sessions = {}

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

def get_user_from_token(token: str):
    session = sessions.get(token)
    if not session:
        return None
    if time.time() > session['expires_at']:
        del sessions[token]
        return None
    return users.get(session['username'])

# Auth decorator for protected endpoints
def require_auth(handler):
    async def wrapper(request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return web.Response(text='Unauthorized', status=401)
        
        token = auth_header[7:]  # Remove 'Bearer '
        user = get_user_from_token(token)
        if not user:
            return web.Response(text='Invalid token', status=401)
        
        request['user'] = user
        return await handler(request)
    return wrapper

# Public endpoints
async def post_register(request):
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        if username in users:
            return web.json_response({'error': 'User already exists'}, status=400)
        
        salt, password_hash = hash_password(password)
        users[username] = {
            'username': username,
            'salt': salt,
            'password_hash': password_hash,
            'created_at': time.time()
        }
        
        return web.json_response({'message': 'User created successfully'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def post_login(request):
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        user = users.get(username)
        if not user or not verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        token = generate_token()
        sessions[token] = {
            'username': username,
            'created_at': time.time(),
            'expires_at': time.time() + 3600  # 1 hour
        }
        
        return web.json_response({'token': token, 'expires_in': 3600})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

async def post_logout(request):
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        sessions.pop(token, None)
    return web.json_response({'message': 'Logged out'})

# Protected endpoints
@require_auth
async def get_profile(request):
    user = request['user']
    return web.json_response({
        'username': user['username'],
        'created_at': user['created_at']
    })

@require_auth
async def get_users(request):
    return web.json_response({
        'users': [{'username': u['username']} for u in users.values()]
    })

@require_auth
async def get_users_id(request):
    username = request.match_info['id']
    user = users.get(username)
    if not user:
        return web.json_response({'error': 'User not found'}, status=404)
    return web.json_response({'username': user['username']})

@require_auth
async def delete_users_id(request):
    current_user = request['user']
    username = request.match_info['id']
    
    # Only allow users to delete themselves (add admin logic as needed)
    if current_user['username'] != username:
        return web.json_response({'error': 'Forbidden'}, status=403)
    
    if username not in users:
        return web.json_response({'error': 'User not found'}, status=404)
    
    del users[username]
    # Clean up user sessions
    to_remove = [token for token, session in sessions.items() 
                 if session['username'] == username]
    for token in to_remove:
        del sessions[token]
    
    return web.json_response({'message': 'User deleted'})

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
import re, inspect
app = web.Application()
for name, handler in list(globals().items()):
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route_parts = name[len(method)+1:].split('_')
            source = inspect.getsource(handler)
            params = re.findall(r"request\.match_info\['(\w+)'\]", source)
            
            for param in params:
                param_parts = param.split('_')
                for i in range(len(route_parts) - len(param_parts) + 1):
                    if route_parts[i:i+len(param_parts)] == param_parts:
                        route_parts[i:i+len(param_parts)] = [f'{{{param}}}']
                        break
            
            route = '/' + '/'.join(route_parts)
            app.router.add_route(method.upper(), route, handler)
            print(f"Registered: {method.upper()} {route}")
            break

if __name__ == '__main__':
    print("\n🔐 API Authentication Demo")
    print("Try these commands:")
    print("curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/profile")
    web.run_app(app, host='localhost', port=8080)