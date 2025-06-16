from aiohttp import web
import hashlib
import secrets
import time
import json
import asyncio
from enhanced_safe_db import create_database

# Database instance (initialized on startup)
db = None
users_collection = None
sessions_collection = None

async def init_database():
    """Initialize database and collections"""
    global db, users_collection, sessions_collection
    
    db = create_database()
    users_collection = await db.get_collection("users")
    sessions_collection = await db.get_collection("sessions")
    
    print("✅ Database initialized")

def hash_password(password: str) -> tuple[str, str]:
    """Generate salt and hash for password"""
    salt = secrets.token_bytes(32)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return salt.hex(), hash_bytes.hex()

def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Verify password against stored salt and hash"""
    salt = bytes.fromhex(salt_hex)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600_000)
    return secrets.compare_digest(hash_bytes.hex(), hash_hex)

def generate_token() -> str:
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

async def get_user_from_token(token: str):
    """Get user from session token, handling expiry"""
    try:
        session = await sessions_collection.get(token)
        if not session:
            return None
            
        # Check if session expired
        if time.time() > session['expires_at']:
            await sessions_collection.delete(token)
            return None
            
        # Get user data
        user = await users_collection.get(session['username'])
        return user
        
    except Exception:
        return None

# Auth decorator for protected endpoints
def require_auth(handler):
    """Decorator to require authentication for endpoints"""
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
async def post_register(request):
    """Register a new user"""
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        # Validate input
        if not username or not password:
            return web.json_response({'error': 'Username and password required'}, status=400)
        
        if len(password) < 6:
            return web.json_response({'error': 'Password must be at least 6 characters'}, status=400)
        
        # Check if user already exists
        existing_user = await users_collection.get(username)
        if existing_user:
            return web.json_response({'error': 'User already exists'}, status=400)
        
        # Create user with transaction (ensures atomicity)
        async with db.transaction() as tx:
            salt, password_hash = hash_password(password)
            
            user_data = {
                'username': username,
                'salt': salt,
                'password_hash': password_hash,
                'created_at': time.time(),
                'last_login': None
            }
            
            await tx.set("users", username, user_data)
            
        print(f"👤 User '{username}' registered successfully")
        return web.json_response({'message': 'User created successfully'})
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return web.json_response({'error': 'Registration failed'}, status=500)

async def post_login(request):
    """Login user and create session"""
    try:
        data = await request.json()
        username = data['username']
        password = data['password']
        
        # Get user from database
        user = await users_collection.get(username)
        if not user:
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        # Verify password
        if not verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid credentials'}, status=401)
        
        # Create session with transaction (update user + create session atomically)
        async with db.transaction() as tx:
            # Update user's last login
            updated_user = {**user, 'last_login': time.time()}
            await tx.set("users", username, updated_user)
            
            # Create session
            token = generate_token()
            session_data = {
                'username': username,
                'created_at': time.time(),
                'expires_at': time.time() + 3600,  # 1 hour
                'user_agent': request.headers.get('User-Agent', 'Unknown')
            }
            await tx.set("sessions", token, session_data)
        
        print(f"🔑 User '{username}' logged in successfully")
        return web.json_response({
            'token': token, 
            'expires_in': 3600,
            'username': username
        })
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        print(f"❌ Login error: {e}")
        return web.json_response({'error': 'Login failed'}, status=500)

async def post_logout(request):
    """Logout user by invalidating session"""
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header[7:]
        try:
            # Get session info before deleting
            session = await sessions_collection.get(token)
            username = session.get('username', 'Unknown') if session else 'Unknown'
            
            await sessions_collection.delete(token)
            print(f"👋 User '{username}' logged out")
            return web.json_response({'message': 'Logged out successfully'})
        except Exception as e:
            print(f"⚠️ Logout warning: {e}")
    
    return web.json_response({'message': 'Logged out'})

# Protected endpoints
@require_auth
async def get_profile(request):
    """Get current user's profile"""
    user = request['user']
    
    # Count user's active sessions
    try:
        session_count = 0
        async for session_id, session_data in sessions_collection.items():
            if (session_data.get('username') == user['username'] and 
                time.time() <= session_data.get('expires_at', 0)):
                session_count += 1
    except:
        session_count = 0
    
    return web.json_response({
        'username': user['username'],
        'created_at': user['created_at'],
        'last_login': user.get('last_login'),
        'active_sessions': session_count
    })

@require_auth
async def get_users(request):
    """Get list of all users (limited info)"""
    try:
        user_list = []
        async for username, user_data in users_collection.items():
            user_list.append({
                'username': user_data['username'],
                'created_at': user_data['created_at'],
                'last_login': user_data.get('last_login')
            })
        
        # Sort by creation date (newest first)
        user_list.sort(key=lambda x: x['created_at'], reverse=True)
        
        return web.json_response({
            'users': user_list,
            'total': len(user_list)
        })
    except Exception as e:
        print(f"❌ Get users error: {e}")
        return web.json_response({'error': 'Failed to fetch users'}, status=500)

@require_auth
async def get_users_id(request):
    """Get specific user by username"""
    username = request.match_info['id']
    
    try:
        user = await users_collection.get(username)
        if not user:
            return web.json_response({'error': 'User not found'}, status=404)
        
        return web.json_response({
            'username': user['username'],
            'created_at': user['created_at'],
            'last_login': user.get('last_login')
        })
    except Exception as e:
        print(f"❌ Get user error: {e}")
        return web.json_response({'error': 'Failed to fetch user'}, status=500)

@require_auth
async def delete_users_id(request):
    """Delete user account (self-deletion only unless admin)"""
    current_user = request['user']
    username = request.match_info['id']
    
    # Only allow users to delete themselves (add admin logic as needed)
    if current_user['username'] != username:
        return web.json_response({'error': 'Forbidden: Can only delete your own account'}, status=403)
    
    try:
        # Check if user exists
        user = await users_collection.get(username)
        if not user:
            return web.json_response({'error': 'User not found'}, status=404)
        
        # Delete user and all their sessions atomically
        async with db.transaction() as tx:
            # Delete user record
            await tx.delete("users", username)
            
            # Find and delete all user sessions
            sessions_to_delete = []
            async for session_id, session_data in sessions_collection.items():
                if session_data.get('username') == username:
                    sessions_to_delete.append(session_id)
            
            for session_id in sessions_to_delete:
                await tx.delete("sessions", session_id)
        
        print(f"🗑️ User '{username}' deleted with {len(sessions_to_delete)} sessions")
        return web.json_response({
            'message': 'User account deleted successfully',
            'sessions_removed': len(sessions_to_delete)
        })
        
    except Exception as e:
        print(f"❌ Delete user error: {e}")
        return web.json_response({'error': 'Failed to delete user'}, status=500)

@require_auth
async def get_sessions(request):
    """Get current user's active sessions"""
    current_user = request['user']
    
    try:
        user_sessions = []
        current_time = time.time()
        
        async for session_id, session_data in sessions_collection.items():
            if (session_data.get('username') == current_user['username'] and 
                current_time <= session_data.get('expires_at', 0)):
                
                user_sessions.append({
                    'session_id': session_id[:8] + '...',  # Partial ID for security
                    'created_at': session_data['created_at'],
                    'expires_at': session_data['expires_at'],
                    'user_agent': session_data.get('user_agent', 'Unknown'),
                    'expires_in': max(0, int(session_data['expires_at'] - current_time))
                })
        
        # Sort by creation date (newest first)
        user_sessions.sort(key=lambda x: x['created_at'], reverse=True)
        
        return web.json_response({
            'sessions': user_sessions,
            'total': len(user_sessions)
        })
        
    except Exception as e:
        print(f"❌ Get sessions error: {e}")
        return web.json_response({'error': 'Failed to fetch sessions'}, status=500)

# Cleanup expired sessions periodically
async def cleanup_expired_sessions():
    """Background task to clean up expired sessions"""
    while True:
        try:
            current_time = time.time()
            expired_sessions = []
            
            async for session_id, session_data in sessions_collection.items():
                if current_time > session_data.get('expires_at', 0):
                    expired_sessions.append(session_id)
            
            # Delete expired sessions
            if expired_sessions:
                async with db.transaction() as tx:
                    for session_id in expired_sessions:
                        await tx.delete("sessions", session_id)
                
                print(f"🧹 Cleaned up {len(expired_sessions)} expired sessions")
            
        except Exception as e:
            print(f"⚠️ Session cleanup error: {e}")
        
        # Run cleanup every 10 minutes
        await asyncio.sleep(600)

# File watching for auto-reload
import os, sys, threading
def watch_file():
    original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    while True: 
        time.sleep(2)
        current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        if current_hash != original_hash:
            print("📁 File changed, restarting...")
            os.execv(sys.executable, ['python'] + sys.argv)
threading.Thread(target=watch_file, daemon=True).start()

# Auto-routing
import re, inspect

async def create_app():
    """Create and configure the web application"""
    await init_database()
    
    app = web.Application()
    
    # Register routes automatically based on function names
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
                print(f"🛣️  Registered: {method.upper()} {route}")
                break
    
    # Start background session cleanup
    asyncio.create_task(cleanup_expired_sessions())
    
    return app

if __name__ == '__main__':
    print("\n🔐 Database-Backed Authentication API")
    print("=" * 50)
    print("Features:")
    print("✅ Persistent user storage")
    print("✅ Secure password hashing (PBKDF2)")
    print("✅ Session management with expiry")
    print("✅ Transaction-safe operations")
    print("✅ Automatic session cleanup")
    print("✅ Auto-reload development mode")
    
    print(f"\n🧪 Try these commands:")
    print("# Register a user")
    print("curl -X POST http://localhost:8080/register -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    
    print("\n# Login")
    print("curl -X POST http://localhost:8080/login -H 'Content-Type: application/json' -d '{\"username\":\"alice\",\"password\":\"secret123\"}'")
    
    print("\n# Get profile (use token from login)")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/profile")
    
    print("\n# List all users")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/users")
    
    print("\n# Get your sessions")
    print("curl -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/sessions")
    
    print("\n# Logout")
    print("curl -X POST -H 'Authorization: Bearer YOUR_TOKEN' http://localhost:8080/logout")
    
    # Run the app
    app = asyncio.get_event_loop().run_until_complete(create_app())
    web.run_app(app, host='localhost', port=8080)