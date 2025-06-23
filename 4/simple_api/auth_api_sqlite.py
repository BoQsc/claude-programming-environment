#!/usr/bin/env python3
"""
Auth API - Production Ready Implementation
==========================================
• aiohttp async web server with SQLite database
• PBKDF2 password hashing (600k iterations) with secure salts
• Auto SSL detection: HTTP dev (localhost:8080) → HTTPS prod (0.0.0.0:8447)
• Bearer token authentication with 1-hour session expiration
• Unique user IDs (auto-increment integers) with username lookup
• CORS enabled for cross-origin requests from frontend
• Auto session cleanup (5min intervals) + file watching dev mode
• Users can only delete their own accounts (self-service only)
• Auto-routing system with manual parameterized route registration
• Production: Frontend on :443, API on :8447, separate services

ISOLATION SECTIONS:
==================
This codebase uses "isolated sections" - clearly marked code blocks that add
specific features and can be easily removed without affecting core functionality.
Look for "ISOLATED SECTION: [FEATURE NAME]" comments to identify these blocks.
To remove a feature, simply delete everything between the start/end markers.
"""

from aiohttp import web
import aiosqlite
import hashlib
import secrets
import time
import json
import asyncio
import os
import ssl

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
        
        # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
        await DB._execute("""CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            user_id INTEGER NOT NULL, 
            title TEXT NOT NULL, 
            content TEXT NOT NULL, 
            created_at REAL NOT NULL, 
            updated_at REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )""")
        # ===== END ISOLATED SECTION: POSTS =====
    
    @staticmethod
    async def create_user(username, salt, password_hash):
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute("INSERT INTO users (username, salt, password_hash, created_at) VALUES (?, ?, ?, ?)", 
                                    (username, salt, password_hash, time.time()))
            await db.commit()
            return cursor.lastrowid
    
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

    # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
    @staticmethod
    async def create_post(user_id, title, content):
        """Create a new post for the specified user"""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "INSERT INTO posts (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)", 
                (user_id, title, content, time.time(), time.time())
            )
            await db.commit()
            return cursor.lastrowid
    
    @staticmethod
    async def get_post_by_id(post_id):
        """Get a specific post by ID with user information"""
        return await DB._execute("""
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.id = ?
        """, (post_id,), 'one')
    
    @staticmethod
    async def get_posts_by_user(user_id, limit=50, offset=0):
        """Get all posts by a specific user with pagination"""
        return await DB._execute("""
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            WHERE p.user_id = ? 
            ORDER BY p.created_at DESC 
            LIMIT ? OFFSET ?
        """, (user_id, limit, offset), 'all')
    
    @staticmethod
    async def get_all_posts(limit=50, offset=0):
        """Get all posts with user information and pagination"""
        return await DB._execute("""
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC 
            LIMIT ? OFFSET ?
        """, (limit, offset), 'all')
    
    @staticmethod
    async def update_post(post_id, user_id, title=None, content=None):
        """Update a post - only the owner can update"""
        if title is None and content is None:
            return False
        
        # First verify the post belongs to the user
        post = await DB._execute("SELECT user_id FROM posts WHERE id = ?", (post_id,), 'one')
        if not post or post['user_id'] != user_id:
            return False
        
        # Build dynamic update query
        updates = []
        params = []
        if title is not None:
            updates.append("title = ?")
            params.append(title)
        if content is not None:
            updates.append("content = ?")
            params.append(content)
        
        updates.append("updated_at = ?")
        params.append(time.time())
        params.append(post_id)
        
        query = f"UPDATE posts SET {', '.join(updates)} WHERE id = ?"
        result = await DB._execute(query, params)
        return True
    
    @staticmethod
    async def delete_post(post_id, user_id):
        """Delete a post - only the owner can delete"""
        async with aiosqlite.connect(DB_PATH) as db:
            # Verify ownership and delete in one query
            result = await db.execute("DELETE FROM posts WHERE id = ? AND user_id = ?", (post_id, user_id))
            await db.commit()
            return result.rowcount > 0
    
    @staticmethod
    async def get_posts_count():
        """Get total number of posts"""
        result = await DB._execute("SELECT COUNT(*) as count FROM posts", fetch='one')
        return result['count'] if result else 0
    
    @staticmethod
    async def get_user_posts_count(user_id):
        """Get total number of posts by a specific user"""
        result = await DB._execute("SELECT COUNT(*) as count FROM posts WHERE user_id = ?", (user_id,), 'one')
        return result['count'] if result else 0
    # ===== END ISOLATED SECTION: POSTS =====

# Async password functions - single line implementations
async def hash_password(password: str) -> tuple[str, str]:
    return await asyncio.get_event_loop().run_in_executor(None, lambda: (lambda s: (s.hex(), hashlib.pbkdf2_hmac('sha256', password.encode(), s, 600_000).hex()))(secrets.token_bytes(32)))

async def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    return await asyncio.get_event_loop().run_in_executor(None, lambda: secrets.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt_hex), 600_000).hex(), hash_hex))

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def check_ssl_certificates():
    """Check if SSL certificates exist in current directory"""
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    
    # Also check for common certificate names
    common_names = [
        ('server.crt', 'server.key'),
        ('localhost.pem', 'localhost-key.pem'),
        ('ssl_cert.pem', 'ssl_key.pem'),
        ('certificate.pem', 'private_key.pem')
    ]
    
    for cert_name, key_name in common_names:
        if os.path.exists(cert_name) and os.path.exists(key_name):
            return cert_name, key_name
    
    return None, None

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

# ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
@require_auth
async def post_posts(request):
    """Create a new post"""
    try:
        data = await request.json()
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        
        if not title or not content:
            return web.json_response({'error': 'Title and content are required'}, status=400)
        
        if len(title) > 200:
            return web.json_response({'error': 'Title too long (max 200 chars)'}, status=400)
        
        if len(content) > 10000:
            return web.json_response({'error': 'Content too long (max 10000 chars)'}, status=400)
        
        user = request['user']
        post_id = await DB.create_post(user['id'], title, content)
        
        return web.json_response({
            'message': 'Post created',
            'post_id': post_id,
            'title': title
        }, status=201)
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

@require_auth
async def get_posts(request):
    """Get all posts with pagination"""
    try:
        limit = min(int(request.query.get('limit', 50)), 100)  # Max 100 posts per request
        offset = int(request.query.get('offset', 0))
        user_id = request.query.get('user_id')  # Optional filter by user
        
        if user_id:
            posts = await DB.get_posts_by_user(int(user_id), limit, offset)
            total_count = await DB.get_user_posts_count(int(user_id))
        else:
            posts = await DB.get_all_posts(limit, offset)
            total_count = await DB.get_posts_count()
        
        return web.json_response({
            'posts': [dict(post) for post in posts],
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total_count,
                'has_more': offset + limit < total_count
            }
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)

@require_auth
async def get_posts_id(request):
    """Get a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID'}, status=400)
    
    post = await DB.get_post_by_id(post_id)
    if not post:
        return web.json_response({'error': 'Post not found'}, status=404)
    
    return web.json_response({'post': dict(post)})

@require_auth
async def put_posts_id(request):
    """Update a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        
        title = data.get('title', '').strip() if 'title' in data else None
        content = data.get('content', '').strip() if 'content' in data else None
        
        if title is not None and (not title or len(title) > 200):
            return web.json_response({'error': 'Invalid title (1-200 chars)'}, status=400)
        
        if content is not None and (not content or len(content) > 10000):
            return web.json_response({'error': 'Invalid content (1-10000 chars)'}, status=400)
        
        user = request['user']
        updated = await DB.update_post(post_id, user['id'], title, content)
        
        if not updated:
            return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
        
        return web.json_response({'message': 'Post updated'})
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request'}, status=400)

@require_auth
async def delete_posts_id(request):
    """Delete a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID'}, status=400)
    
    user = request['user']
    deleted = await DB.delete_post(post_id, user['id'])
    
    if not deleted:
        return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
    
    return web.json_response({'message': 'Post deleted'})

@require_auth
async def get_posts_my(request):
    """Get current user's posts"""
    try:
        limit = min(int(request.query.get('limit', 50)), 100)
        offset = int(request.query.get('offset', 0))
        
        user = request['user']
        posts = await DB.get_posts_by_user(user['id'], limit, offset)
        total_count = await DB.get_user_posts_count(user['id'])
        
        return web.json_response({
            'posts': [dict(post) for post in posts],
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total_count,
                'has_more': offset + limit < total_count
            }
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
# ===== END ISOLATED SECTION: POSTS =====

async def cleanup_task():
    while True:
        await asyncio.sleep(300)
        await DB.cleanup_sessions()

# File watching for development
import sys
import threading

def watch_file():
    original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    while True: 
        time.sleep(2)
        current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        if current_hash != original_hash:
            os.execv(sys.executable, ['python'] + sys.argv)

# Auto-routing system
import re
import inspect

app = web.Application(middlewares=[cors_middleware])

async def init_app():
    await DB.init()
    asyncio.create_task(cleanup_task())

app.on_startup.append(lambda app: init_app())

# Manually register parameterized routes first
app.router.add_route('GET', '/users/{id}', get_users_id)
app.router.add_route('DELETE', '/users/{id}', delete_users_id)

# ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
# Manually register posts parameterized routes
app.router.add_route('GET', '/posts/{id}', get_posts_id)
app.router.add_route('PUT', '/posts/{id}', put_posts_id)
app.router.add_route('DELETE', '/posts/{id}', delete_posts_id)
# ===== END ISOLATED SECTION: POSTS =====

# Auto-register other routes
for name, handler in list(globals().items()):
    # Skip manually registered routes
    # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
    if name in ['get_users_id', 'delete_users_id', 'get_posts_id', 'put_posts_id', 'delete_posts_id']:
    # ===== END ISOLATED SECTION: POSTS =====
        continue
        
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route_parts = name[len(method)+1:].split('_')
            route = '/' + '/'.join(route_parts)
            app.router.add_route(method.upper(), route, handler)
            break

if __name__ == '__main__':
    print("🔐 Auth API with SQLite - Production Ready with SSL Auto-Detection")
    print("=" * 70)
    
    # Start file watcher for development
    threading.Thread(target=watch_file, daemon=True).start()
    
    # Check for SSL certificates
    cert_file, key_file = check_ssl_certificates()
    
    if cert_file and key_file:
        # HTTPS Production Mode
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_file, key_file)
        
        host = '0.0.0.0'  # Accept connections from any IP
        port = 8447
        protocol = 'https'
        
        print(f"🔒 SSL certificates found ({cert_file}, {key_file})")
        print(f"🚀 Starting HTTPS API server on {protocol}://{host}:{port}")
        print(f"🌍 Production ready! Accessible from external hosts")
        
    else:
        # HTTP Development Mode
        host = 'localhost'
        port = 8080
        protocol = 'http'
        
        print("⚠️  No SSL certificates found - running in HTTP development mode")
        print("💡 To enable HTTPS production mode:")
        print("   • Place cert.pem and key.pem in current directory")
        print("   • Or generate self-signed: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes")
        print(f"🚀 Starting HTTP server on {protocol}://{host}:{port}")
    
    print(f"\n📋 Available API endpoints:")
    print(f"  POST   /register       - Create new user account")
    print(f"  GET    /checkusername  - Check username availability")
    print(f"  POST   /login          - Authenticate and get token")
    print(f"  POST   /logout         - Invalidate session token")
    print(f"  GET    /profile        - Get current user profile")
    print(f"  PUT    /changepassword - Change user password")
    print(f"  GET    /users          - List all users (authenticated)")
    print(f"  GET    /users/{{id}}     - Get specific user by ID")
    print(f"  DELETE /users/{{id}}     - Delete user account (own only)")
    
    # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
    print(f"\n📝 Posts API endpoints:")
    print(f"  POST   /posts          - Create new post")
    print(f"  GET    /posts          - List all posts (with pagination)")
    print(f"  GET    /posts/my       - Get current user's posts")
    print(f"  GET    /posts/{{id}}     - Get specific post by ID")
    print(f"  PUT    /posts/{{id}}     - Update specific post (owner only)")
    print(f"  DELETE /posts/{{id}}     - Delete specific post (owner only)")
    # ===== END ISOLATED SECTION: POSTS =====
    
    print(f"\n🔧 Example API usage:")
    base_url = f"{protocol}://{host}:{port}"
    print(f"# Register new user:")
    print(f"curl -X POST {base_url}/register -H 'Content-Type: application/json' \\")
    print(f"  -d '{{\"username\":\"alice\",\"password\":\"secret123\"}}'")
    print(f"\n# Login:")
    print(f"curl -X POST {base_url}/login -H 'Content-Type: application/json' \\")
    print(f"  -d '{{\"username\":\"alice\",\"password\":\"secret123\"}}'")
    print(f"\n# Get profile (replace YOUR_TOKEN):")
    print(f"curl -H 'Authorization: Bearer YOUR_TOKEN' {base_url}/profile")
    print(f"\n# List users:")
    print(f"curl -H 'Authorization: Bearer YOUR_TOKEN' {base_url}/users")
    
    # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
    print(f"\n📝 Posts API examples:")
    print(f"# Create post:")
    print(f"curl -X POST {base_url}/posts -H 'Content-Type: application/json' \\")
    print(f"  -H 'Authorization: Bearer YOUR_TOKEN' \\")
    print(f"  -d '{{\"title\":\"My First Post\",\"content\":\"Hello world!\"}}'")
    print(f"\n# Get all posts:")
    print(f"curl -H 'Authorization: Bearer YOUR_TOKEN' {base_url}/posts")
    print(f"\n# Get my posts:")
    print(f"curl -H 'Authorization: Bearer YOUR_TOKEN' {base_url}/posts/my")
    print(f"\n# Update post:")
    print(f"curl -X PUT {base_url}/posts/1 -H 'Content-Type: application/json' \\")
    print(f"  -H 'Authorization: Bearer YOUR_TOKEN' \\")
    print(f"  -d '{{\"title\":\"Updated Title\",\"content\":\"Updated content\"}}'")
    # ===== END ISOLATED SECTION: POSTS =====
    
    if protocol == 'https':
        print(f"\n🌐 Production Architecture:")
        print(f"  • Auth API (this): {base_url}")
        print(f"  • Frontend Web Server: https://yourdomain.com:443")
        print(f"  • Frontend makes API calls to: {base_url}")
        print(f"\n🔒 Security: HTTPS enabled, ready for production!")
    else:
        print(f"\n🔧 Development mode - add SSL certificates for production deployment")
    
    print("=" * 70)
    
    # Start the server
    try:
        if cert_file and key_file:
            web.run_app(app, host=host, port=port, ssl_context=ssl_context)
        else:
            web.run_app(app, host=host, port=port)
    except KeyboardInterrupt:
        print("\n👋 Server stopped")
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        sys.exit(1)