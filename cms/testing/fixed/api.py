#!/usr/bin/env python3
"""
Main API implementation using aioweb and db modules
A flat structured API with clear endpoint declarations
NO EXTERNAL DEPENDENCIES beyond aiohttp

FIXES:
- Added proper like/unlike tracking to prevent duplicate likes
- Added user likes tracking collection
- Added endpoints to get user's liked posts
- Proper like state management
"""

import asyncio
import logging
import hashlib
import hmac
import base64
import time
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

# Import our custom modules
from aioweb import (
    WebApp, APIError, get_json_data, get_query_params, 
    get_path_params, require_fields, validate_field_types, handle_options
)
from db import AsyncJSONDB, create_unique_id, create_timestamp

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize database and web app
db = AsyncJSONDB('./data')
app = WebApp(cors_origins=["*"])

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
TOKEN_EXPIRY_HOURS = 24


# =============================================================================
# Simple Token System (JWT-like without external dependencies)
# =============================================================================

def _create_signature(payload: str, secret: str) -> str:
    """Create HMAC signature for token"""
    return hmac.new(
        secret.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def create_token(user_id: str, username: str) -> str:
    """Create a simple token for a user"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': time.time() + (TOKEN_EXPIRY_HOURS * 3600),  # Expiry in seconds
        'iat': time.time()
    }
    
    # Base64 encode the payload
    payload_json = json.dumps(payload)
    payload_b64 = base64.b64encode(payload_json.encode()).decode()
    
    # Create signature
    signature = _create_signature(payload_b64, SECRET_KEY)
    
    # Combine payload and signature
    return f"{payload_b64}.{signature}"


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a token"""
    try:
        # Split token
        parts = token.split('.')
        if len(parts) != 2:
            raise APIError("Invalid token format", 401)
        
        payload_b64, signature = parts
        
        # Verify signature
        expected_signature = _create_signature(payload_b64, SECRET_KEY)
        if not hmac.compare_digest(signature, expected_signature):
            raise APIError("Invalid token signature", 401)
        
        # Decode payload
        payload_json = base64.b64decode(payload_b64.encode()).decode()
        payload = json.loads(payload_json)
        
        # Check expiry
        if time.time() > payload.get('exp', 0):
            raise APIError("Token has expired", 401)
        
        return payload
        
    except (ValueError, json.JSONDecodeError):
        raise APIError("Invalid token", 401)


# =============================================================================
# Utility Functions
# =============================================================================

def hash_password(password: str) -> str:
    """Hash a password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    return hash_password(password) == hashed


async def get_current_user(request):
    """Get current user from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        raise APIError("Missing or invalid authorization header", 401)
    
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    payload = verify_token(token)
    
    # Get user from database
    users = await db.get_collection('users')
    user = await users.get(payload['user_id'])
    
    if not user:
        raise APIError("User not found", 401)
    
    # Add the user ID as _key for consistency with database operations
    user['_key'] = payload['user_id']
    
    return user


async def get_like_key(user_id: str, post_id: str) -> str:
    """Generate a unique key for user-post like relationship"""
    return f"{user_id}_{post_id}"


async def user_has_liked_post(user_id: str, post_id: str) -> bool:
    """Check if user has liked a specific post"""
    likes = await db.get_collection('post_likes')
    like_key = await get_like_key(user_id, post_id)
    return await likes.exists(like_key)


async def get_user_liked_posts(user_id: str) -> list:
    """Get all post IDs that a user has liked"""
    likes = await db.get_collection('post_likes')
    
    def filter_user_likes(like_record):
        return like_record.get('user_id') == user_id
    
    user_likes = await likes.find(filter_func=filter_user_likes)
    return [like['post_id'] for like in user_likes]


# =============================================================================
# Authentication Endpoints
# =============================================================================

@app.post('/api/auth/register')
async def register_user(request):
    """Register a new user"""
    data = get_json_data(request)
    
    # Validate required fields
    require_fields(data, ['username', 'email', 'password'])
    validate_field_types(data, {
        'username': str,
        'email': str,
        'password': str
    })
    
    # Additional validation
    if len(data['password']) < 6:
        raise APIError("Password must be at least 6 characters long", 400)
    
    if '@' not in data['email'] or '.' not in data['email']:
        raise APIError("Invalid email format", 400)
    
    # Validate username format
    if len(data['username']) < 3:
        raise APIError("Username must be at least 3 characters long", 400)
    
    users = await db.get_collection('users')
    
    # Check if user already exists
    existing_users = await users.find(
        lambda user: user.get('username') == data['username'] or user.get('email') == data['email']
    )
    
    if existing_users:
        raise APIError("Username or email already exists", 409)
    
    # Create new user
    user_id = await create_unique_id()
    user_data = {
        'username': data['username'],
        'email': data['email'],
        'password_hash': hash_password(data['password']),
        'created_at': await create_timestamp(),
        'last_login': None,
        'is_active': True
    }
    
    await users.set(user_id, user_data)
    
    # Create token
    token = create_token(user_id, data['username'])
    
    return app.json_response({
        'message': 'User registered successfully',
        'user_id': user_id,
        'username': data['username'],
        'token': token
    }, status=201)


@app.post('/api/auth/login')
async def login_user(request):
    """Login user"""
    data = get_json_data(request)
    
    require_fields(data, ['username', 'password'])
    
    users = await db.get_collection('users')
    
    # Find user by username
    user_list = await users.find(
        lambda user: user.get('username') == data['username']
    )
    
    if not user_list:
        raise APIError("Invalid username or password", 401)
    
    user = user_list[0]
    user_id = user['_key']
    
    # Verify password
    if not verify_password(data['password'], user['password_hash']):
        raise APIError("Invalid username or password", 401)
    
    if not user.get('is_active', True):
        raise APIError("Account is deactivated", 401)
    
    # Update last login
    await users.update(user_id, {'last_login': await create_timestamp()})
    
    # Create token
    token = create_token(user_id, user['username'])
    
    return app.json_response({
        'message': 'Login successful',
        'user_id': user_id,
        'username': user['username'],
        'token': token
    })


@app.get('/api/auth/profile')
async def get_profile(request):
    """Get current user profile"""
    user = await get_current_user(request)
    
    # Remove sensitive data
    profile = {k: v for k, v in user.items() if k != 'password_hash'}
    
    return app.json_response(profile)


# =============================================================================
# Posts/Content Management Endpoints
# =============================================================================

@app.post('/api/posts')
async def create_post(request):
    """Create a new post"""
    user = await get_current_user(request)
    data = get_json_data(request)
    
    require_fields(data, ['title', 'content'])
    validate_field_types(data, {
        'title': str,
        'content': str
    })
    
    # Validate title and content length
    if len(data['title'].strip()) == 0:
        raise APIError("Title cannot be empty", 400)
    
    if len(data['content'].strip()) == 0:
        raise APIError("Content cannot be empty", 400)
    
    posts = await db.get_collection('posts')
    
    post_id = await create_unique_id()
    post_data = {
        'title': data['title'].strip(),
        'content': data['content'].strip(),
        'author_id': user['_key'],
        'author_username': user['username'],
        'created_at': await create_timestamp(),
        'updated_at': await create_timestamp(),
        'tags': data.get('tags', []) if isinstance(data.get('tags'), list) else [],
        'is_published': data.get('is_published', True),
        'views': 0,
        'likes': 0
    }
    
    await posts.set(post_id, post_data)
    
    return app.json_response({
        'message': 'Post created successfully',
        'post_id': post_id,
        'post': post_data
    }, status=201)


@app.get('/api/posts')
async def get_posts(request):
    """Get posts with optional filtering"""
    query_params = get_query_params(request)
    
    limit = min(int(query_params.get('limit', 10)), 100)  # Max 100 posts
    author_id = query_params.get('author_id')
    tag = query_params.get('tag')
    published_only = query_params.get('published', 'true').lower() == 'true'
    
    posts = await db.get_collection('posts')
    
    # Define filter function
    def post_filter(post):
        if published_only and not post.get('is_published', True):
            return False
        
        if author_id and post.get('author_id') != author_id:
            return False
        
        if tag and tag not in post.get('tags', []):
            return False
        
        return True
    
    post_list = await posts.find(filter_func=post_filter, limit=limit)
    
    # Sort by creation date (newest first)
    post_list.sort(key=lambda x: x.get('created_at', 0), reverse=True)
    
    return app.json_response({
        'posts': post_list,
        'count': len(post_list)
    })


@app.get('/api/posts/liked')
async def get_user_liked_posts(request):
    """Get posts that the current user has liked"""
    user = await get_current_user(request)
    
    liked_post_ids = await get_user_liked_posts(user['_key'])
    
    return app.json_response({
        'liked_posts': liked_post_ids,
        'count': len(liked_post_ids)
    })


@app.get('/api/posts/{post_id}')
async def get_post(request):
    """Get a specific post"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post:
        raise APIError("Post not found", 404)
    
    # Increment view count
    try:
        await posts.increment(post_id, 'views')
        post['views'] = post.get('views', 0) + 1
    except Exception as e:
        logger.warning(f"Failed to increment views for post {post_id}: {e}")
    
    return app.json_response(post)


@app.put('/api/posts/{post_id}')
async def update_post(request):
    """Update a post"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    data = get_json_data(request)
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post:
        raise APIError("Post not found", 404)
    
    # Check ownership
    if post['author_id'] != user['_key']:
        raise APIError("Unauthorized to edit this post", 403)
    
    # Update allowed fields
    updates = {}
    for field in ['title', 'content', 'tags', 'is_published']:
        if field in data:
            if field == 'title' and data[field]:
                updates[field] = data[field].strip()
            elif field == 'content' and data[field]:
                updates[field] = data[field].strip()
            elif field == 'tags' and isinstance(data[field], list):
                updates[field] = data[field]
            elif field == 'is_published' and isinstance(data[field], bool):
                updates[field] = data[field]
    
    updates['updated_at'] = await create_timestamp()
    
    await posts.update(post_id, updates)
    
    return app.json_response({
        'message': 'Post updated successfully',
        'post_id': post_id
    })


@app.delete('/api/posts/{post_id}')
async def delete_post(request):
    """Delete a post"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post:
        raise APIError("Post not found", 404)
    
    # Check ownership
    if post['author_id'] != user['_key']:
        raise APIError("Unauthorized to delete this post", 403)
    
    # Delete the post
    await posts.delete(post_id)
    
    # Clean up likes for this post
    likes = await db.get_collection('post_likes')
    post_likes = await likes.find(lambda like: like.get('post_id') == post_id)
    
    for like in post_likes:
        await likes.delete(like['_key'])
    
    return app.json_response({
        'message': 'Post deleted successfully'
    })


@app.post('/api/posts/{post_id}/like')
async def like_post(request):
    """Like a post (only if not already liked)"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    user_id = user['_key']
    
    posts = await db.get_collection('posts')
    likes = await db.get_collection('post_likes')
    
    # Check if post exists
    if not await posts.exists(post_id):
        raise APIError("Post not found", 404)
    
    # Check if user has already liked this post
    if await user_has_liked_post(user_id, post_id):
        raise APIError("You have already liked this post", 400)
    
    # Create like record
    like_key = await get_like_key(user_id, post_id)
    like_data = {
        'user_id': user_id,
        'post_id': post_id,
        'created_at': await create_timestamp()
    }
    
    try:
        # Add like record
        await likes.set(like_key, like_data)
        
        # Increment post likes count
        new_likes = await posts.increment(post_id, 'likes')
        
        return app.json_response({
            'message': 'Post liked successfully',
            'likes': new_likes
        })
        
    except Exception as e:
        logger.error(f"Failed to like post {post_id} by user {user_id}: {e}")
        raise APIError("Failed to like post", 500)


@app.post('/api/posts/{post_id}/unlike')
async def unlike_post(request):
    """Unlike a post (only if already liked)"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    user_id = user['_key']
    
    posts = await db.get_collection('posts')
    likes = await db.get_collection('post_likes')
    
    # Check if post exists
    if not await posts.exists(post_id):
        raise APIError("Post not found", 404)
    
    # Check if user has actually liked this post
    if not await user_has_liked_post(user_id, post_id):
        raise APIError("You have not liked this post", 400)
    
    # Remove like record
    like_key = await get_like_key(user_id, post_id)
    
    try:
        # Remove like record
        await likes.delete(like_key)
        
        # Decrement post likes count (ensure it doesn't go below 0)
        post = await posts.get(post_id)
        current_likes = max(0, post.get('likes', 0) - 1)
        await posts.update(post_id, {'likes': current_likes})
        
        return app.json_response({
            'message': 'Post unliked successfully',
            'likes': current_likes
        })
        
    except Exception as e:
        logger.error(f"Failed to unlike post {post_id} by user {user_id}: {e}")
        raise APIError("Failed to unlike post", 500)


# =============================================================================
# Data Management Endpoints
# =============================================================================

@app.get('/api/collections')
async def list_collections(request):
    """List all collections in the database"""
    await get_current_user(request)  # Verify authentication
    
    collections = await db.list_collections()
    return app.json_response({
        'collections': collections
    })


@app.get('/api/collections/{collection_name}/stats')
async def get_collection_stats(request):
    """Get statistics for a collection"""
    await get_current_user(request)
    path_params = get_path_params(request)
    collection_name = path_params['collection_name']
    
    # Validate collection name
    valid_collections = ['users', 'posts', 'post_likes']
    if collection_name not in valid_collections:
        raise APIError(f"Invalid collection name. Valid collections: {', '.join(valid_collections)}", 400)
    
    collection = await db.get_collection(collection_name)
    count = await collection.count()
    keys = await collection.keys()
    
    return app.json_response({
        'collection': collection_name,
        'count': count,
        'keys': keys[:10],  # First 10 keys as sample
        'total_keys': len(keys)
    })


# =============================================================================
# Session Management (Alternative to tokens)
# =============================================================================

# In-memory session store (for simple use cases)
_sessions = {}


@app.post('/api/auth/session-login')
async def session_login(request):
    """Login with session-based authentication (alternative to tokens)"""
    data = get_json_data(request)
    
    require_fields(data, ['username', 'password'])
    
    users = await db.get_collection('users')
    
    # Find user by username
    user_list = await users.find(
        lambda user: user.get('username') == data['username']
    )
    
    if not user_list:
        raise APIError("Invalid username or password", 401)
    
    user = user_list[0]
    user_id = user['_key']
    
    # Verify password
    if not verify_password(data['password'], user['password_hash']):
        raise APIError("Invalid username or password", 401)
    
    # Create session
    session_id = await create_unique_id()
    _sessions[session_id] = {
        'user_id': user_id,
        'username': user['username'],
        'created_at': time.time(),
        'expires_at': time.time() + (TOKEN_EXPIRY_HOURS * 3600)
    }
    
    # Update last login
    await users.update(user_id, {'last_login': await create_timestamp()})
    
    return app.json_response({
        'message': 'Login successful',
        'session_id': session_id,
        'user_id': user_id,
        'username': user['username']
    })


@app.post('/api/auth/session-logout')
async def session_logout(request):
    """Logout and destroy session"""
    data = get_json_data(request)
    session_id = data.get('session_id')
    
    if session_id and session_id in _sessions:
        del _sessions[session_id]
    
    return app.json_response({
        'message': 'Logged out successfully'
    })


# =============================================================================
# Health and Status Endpoints
# =============================================================================

@app.get('/api/health')
async def health_check(request):
    """Health check endpoint"""
    return app.json_response({
        'status': 'healthy',
        'timestamp': await create_timestamp(),
        'version': '1.0.0'
    })


@app.get('/api/status')
async def get_status(request):
    """Get API status and statistics"""
    collections = await db.list_collections()
    
    stats = {}
    for collection_name in collections:
        try:
            collection = await db.get_collection(collection_name)
            stats[collection_name] = await collection.count()
        except Exception as e:
            logger.warning(f"Failed to get stats for collection {collection_name}: {e}")
            stats[collection_name] = -1
    
    return app.json_response({
        'status': 'running',
        'collections': stats,
        'sessions': len(_sessions),
        'uptime': time.time(),
        'timestamp': await create_timestamp()
    })


@app.get('/')
async def root_endpoint(request):
    """Root endpoint with API information"""
    return app.json_response({
        'name': 'Flat Structured API',
        'version': '1.0.0',
        'description': 'A simple aiohttp API with concurrent JSON database - NO DEPENDENCIES',
        'dependencies': ['aiohttp only'],
        'features': [
            'JWT-like tokens (built-in)',
            'Session-based auth',
            'Concurrent JSON database',
            'CORS support',
            'File I/O via thread pools',
            'Windows file system compatibility',
            'Like/Unlike tracking with duplicate prevention'
        ],
        'endpoints': {
            'auth': '/api/auth/*',
            'posts': '/api/posts/*',
            'collections': '/api/collections/*',
            'health': '/api/health',
            'status': '/api/status'
        }
    })


# Handle CORS preflight requests
@app.options('/api/{path:.*}')
async def handle_cors_preflight(request):
    """Handle CORS preflight requests"""
    return await handle_options(request)


# =============================================================================
# Application Lifecycle
# =============================================================================

async def startup():
    """Application startup tasks"""
    logger.info("Starting up the dependency-free API server...")
    
    # Initialize default collections or data if needed
    try:
        users = await db.get_collection('users')
        posts = await db.get_collection('posts')
        post_likes = await db.get_collection('post_likes')  # New collection for likes
        
        logger.info("Database collections initialized")
        logger.info("Like/Unlike tracking system enabled")
        logger.info("No external dependencies required beyond aiohttp!")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


async def cleanup():
    """Application cleanup tasks"""
    logger.info("Shutting down the API server...")
    try:
        await db.close()
        # Clear sessions
        _sessions.clear()
        logger.info("Cleanup completed successfully")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")


# Override the default startup/cleanup
app.startup = startup
app.cleanup = cleanup


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == '__main__':
    import sys
    
    # Parse command line arguments
    host = '0.0.0.0'
    port = 8080
    debug = False
    
    if '--host' in sys.argv:
        host = sys.argv[sys.argv.index('--host') + 1]
    
    if '--port' in sys.argv:
        port = int(sys.argv[sys.argv.index('--port') + 1])
    
    if '--debug' in sys.argv:
        debug = True
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Starting dependency-free API server on {host}:{port} (debug={debug})")
    logger.info("Dependencies: aiohttp only!")
    logger.info("Features: Like/Unlike tracking with duplicate prevention")
    
    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)