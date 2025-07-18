#!/usr/bin/env python3
"""
COMPLETE API with BOTH original functionality AND new public/anonymous support
- All original features preserved: file upload, sharing, authenticated posts, search, etc.
- New public features added: anonymous posting, public frontpage, nested comments
- No functionality removed, only enhanced
"""

import asyncio
import logging
import hashlib
import hmac
import base64
import time
import json
import os
import mimetypes
import shutil
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response, StreamResponse

# Import our custom modules
from aioweb import (
    WebApp, APIError, get_json_data, get_query_params, 
    get_path_params, require_fields, validate_field_types, handle_options
)
from db import AsyncJSONDB, create_unique_id, create_timestamp

# Import search engine
from search_engine import create_search_engine, SearchResult

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize database and web app
db = AsyncJSONDB('./data')
app = WebApp(cors_origins=["*"])

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
TOKEN_EXPIRY_HOURS = 24
FILES_DIRECTORY = "./files"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size

# Initialize search engine (will be set during startup)
search_engine = None

# Ensure files directory exists
Path(FILES_DIRECTORY).mkdir(parents=True, exist_ok=True)


# =============================================================================
# ENHANCED CORS Helper Function - FIXED for file:// protocol
# =============================================================================

def add_cors_headers(headers_dict: Dict[str, str], origin: str):
    """Add CORS headers to response headers - handles file:// protocol AND image preview"""
    if origin == 'null':
        # Handle file:// protocol specifically
        headers_dict['Access-Control-Allow-Origin'] = 'null'
    elif origin:
        # Handle specific origins
        headers_dict['Access-Control-Allow-Origin'] = origin
    else:
        # Handle no origin (direct access)
        headers_dict['Access-Control-Allow-Origin'] = '*'
    
    headers_dict.update({
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400'
    })


# =============================================================================
# Content-Disposition Helper Function - NEW for proper image preview
# =============================================================================

def get_content_disposition(mime_type: str, filename: str, force_download: bool = False) -> str:
    """
    Determine the appropriate Content-Disposition header based on file type and request
    """
    # Images, PDFs, and text files can be displayed inline by default
    inline_types = [
        'image/', 'text/', 'application/pdf', 'application/json',
        'video/', 'audio/'  # Modern browsers can handle these inline
    ]
    
    # Check if this is a type that can be displayed inline
    can_display_inline = any(mime_type.startswith(t) for t in inline_types)
    
    if force_download or not can_display_inline:
        return f'attachment; filename="{filename}"'
    else:
        return f'inline; filename="{filename}"'


def get_file_icon_unicode(mime_type: str) -> str:
    """Get Unicode emoji icon for file type"""
    if mime_type.startswith('image/'):
        return '🖼️'
    elif mime_type.startswith('video/'):
        return '🎥'
    elif mime_type.startswith('audio/'):
        return '🎵'
    elif 'pdf' in mime_type:
        return '📄'
    elif any(x in mime_type for x in ['word', 'document']):
        return '📝'
    elif any(x in mime_type for x in ['excel', 'spreadsheet']):
        return '📊'
    elif any(x in mime_type for x in ['zip', 'archive', 'compressed']):
        return '📦'
    elif 'text' in mime_type:
        return '📃'
    else:
        return '📁'


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


async def get_current_user_optional(request):
    """Get current user from Authorization header (returns None if not authenticated)"""
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return None
    
    token = auth_header[7:]  # Remove 'Bearer ' prefix
    payload = verify_token(token)
    
    if not payload:
        return None
    
    # Get user from database
    users = await db.get_collection('users')
    user = await users.get(payload['user_id'])
    
    if not user:
        return None
    
    # Add the user ID as _key for consistency with database operations
    user['_key'] = payload['user_id']
    
    return user


async def get_current_user(request):
    """Get current user from Authorization header"""
    user = await get_current_user_optional(request)
    if not user:
        raise APIError("Missing or invalid authorization header", 401)
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


def generate_file_hash(file_path: str) -> str:
    """Generate SHA-256 hash of file content"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def get_file_mime_type(filename: str) -> str:
    """Get MIME type for a file"""
    mime_type, _ = mimetypes.guess_type(filename)
    return mime_type or 'application/octet-stream'


def safe_filename(filename: str) -> str:
    """Create a safe filename by removing potentially harmful characters"""
    # Remove path separators and other potentially harmful characters
    safe_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    return ''.join(c for c in filename if c in safe_chars) or 'unnamed_file'


async def create_share_token(file_id: str) -> str:
    """Create a share token for public file access"""
    share_data = {
        'file_id': file_id,
        'created_at': time.time(),
        # Share tokens don't expire by default, but you could add expiry here
    }
    
    payload_json = json.dumps(share_data)
    payload_b64 = base64.b64encode(payload_json.encode()).decode()
    signature = _create_signature(payload_b64, SECRET_KEY)
    
    return f"{payload_b64}.{signature}"


async def verify_share_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify a share token"""
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return None
        
        payload_b64, signature = parts
        expected_signature = _create_signature(payload_b64, SECRET_KEY)
        
        if not hmac.compare_digest(signature, expected_signature):
            return None
        
        payload_json = base64.b64decode(payload_b64.encode()).decode()
        return json.loads(payload_json)
    except:
        return None


# =============================================================================
# Comment System Functions (NEW)
# =============================================================================

async def build_comment_tree(comments: list) -> list:
    """Build a nested comment tree structure"""
    comment_dict = {comment['_key']: comment for comment in comments}
    root_comments = []
    
    # Initialize replies list for each comment
    for comment in comments:
        comment['replies'] = []
    
    # Build the tree
    for comment in comments:
        parent_id = comment.get('parent_comment_id')
        if parent_id and parent_id in comment_dict:
            comment_dict[parent_id]['replies'].append(comment)
        else:
            root_comments.append(comment)
    
    # Sort by timestamp (oldest first for natural reading order)
    def sort_comments(comment_list):
        comment_list.sort(key=lambda x: x.get('created_at', 0))
        for comment in comment_list:
            sort_comments(comment['replies'])
    
    sort_comments(root_comments)
    return root_comments


async def get_comment_count(post_id: str) -> int:
    """Get total comment count for a post"""
    comments = await db.get_collection('comments')
    post_comments = await comments.find(lambda c: c.get('post_id') == post_id)
    return len(post_comments)


# =============================================================================
# NEW PUBLIC ENDPOINTS - No Authentication Required
# =============================================================================

@app.get('/api/public/posts')
async def get_public_posts(request):
    """Get public posts without authentication"""
    query_params = get_query_params(request)
    
    limit = min(int(query_params.get('limit', 20)), 100)
    offset = int(query_params.get('offset', 0))
    tag = query_params.get('tag')
    author = query_params.get('author')
    
    posts = await db.get_collection('posts')
    
    # Filter for published posts only
    def post_filter(post):
        if not post.get('is_published', True):
            return False
        
        if tag and tag not in post.get('tags', []):
            return False
        
        if author and post.get('author_username', '').lower() != author.lower():
            return False
        
        return True
    
    all_posts = await posts.find(filter_func=post_filter)
    
    # Sort by creation date (newest first)
    all_posts.sort(key=lambda x: x.get('created_at', 0), reverse=True)
    
    # Apply pagination
    paginated_posts = all_posts[offset:offset + limit]
    
    # Add comment counts to each post
    for post in paginated_posts:
        post['comment_count'] = await get_comment_count(post['_key'])
    
    return app.json_response({
        'posts': paginated_posts,
        'count': len(paginated_posts),
        'total': len(all_posts),
        'has_more': offset + limit < len(all_posts)
    })


@app.get('/api/public/posts/{post_id}')
async def get_public_post(request):
    """Get a specific public post without authentication"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post or not post.get('is_published', True):
        raise APIError("Post not found", 404)
    
    # Increment view count
    try:
        await posts.increment(post_id, 'views')
        post['views'] = post.get('views', 0) + 1
    except Exception as e:
        logger.warning(f"Failed to increment views for post {post_id}: {e}")
    
    # Add comment count
    post['comment_count'] = await get_comment_count(post_id)
    
    return app.json_response(post)


@app.get('/api/public/posts/{post_id}/comments')
async def get_public_post_comments(request):
    """Get comments for a post without authentication"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    
    # Verify post exists and is published
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post or not post.get('is_published', True):
        raise APIError("Post not found", 404)
    
    comments = await db.get_collection('comments')
    post_comments = await comments.find(lambda c: c.get('post_id') == post_id)
    
    # Build comment tree with nested replies
    comment_tree = await build_comment_tree(post_comments)
    
    return app.json_response({
        'comments': comment_tree,
        'count': len(post_comments)
    })


@app.post('/api/public/posts/{post_id}/comments')
async def add_public_comment(request):
    """Add a comment to a post without authentication"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    data = get_json_data(request)
    
    # Verify post exists and is published
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post or not post.get('is_published', True):
        raise APIError("Post not found", 404)
    
    # Validate required fields
    require_fields(data, ['content', 'author_name'])
    validate_field_types(data, {
        'content': str,
        'author_name': str
    })
    
    if len(data['content'].strip()) == 0:
        raise APIError("Comment content cannot be empty", 400)
    
    if len(data['author_name'].strip()) == 0:
        raise APIError("Author name cannot be empty", 400)
    
    # Optional parent comment for nested replies
    parent_comment_id = data.get('parent_comment_id')
    if parent_comment_id:
        comments = await db.get_collection('comments')
        parent_comment = await comments.get(parent_comment_id)
        if not parent_comment or parent_comment.get('post_id') != post_id:
            raise APIError("Invalid parent comment", 400)
    
    # Create comment
    comment_id = await create_unique_id()
    comment_data = {
        'post_id': post_id,
        'parent_comment_id': parent_comment_id,
        'content': data['content'].strip(),
        'author_name': data['author_name'].strip()[:100],  # Limit name length
        'author_email': data.get('author_email', '').strip()[:255],  # Optional email
        'author_website': data.get('author_website', '').strip()[:255],  # Optional website
        'created_at': await create_timestamp(),
        'updated_at': await create_timestamp(),
        'is_anonymous': True,
        'ip_address': request.remote or 'unknown'  # For spam prevention
    }
    
    comments = await db.get_collection('comments')
    await comments.set(comment_id, comment_data)
    
    # Update search index for comments
    if search_engine:
        try:
            await search_engine.add_document(
                doc_id=comment_id,
                doc_type='comment',
                title=f"Comment on: {post.get('title', 'Post')}",
                content=comment_data['content'],
                author=comment_data['author_name'],
                metadata={
                    'post_id': post_id,
                    'created_at': comment_data['created_at'],
                    'anonymous': True
                }
            )
        except Exception as e:
            logger.warning(f"Failed to add comment {comment_id} to search index: {e}")
    
    return app.json_response({
        'message': 'Comment added successfully',
        'comment_id': comment_id,
        'comment': comment_data
    }, status=201)


@app.post('/api/public/posts')
async def create_public_post(request):
    """Create a new public post without authentication"""
    data = get_json_data(request)
    
    require_fields(data, ['title', 'content', 'author_name'])
    validate_field_types(data, {
        'title': str,
        'content': str,
        'author_name': str
    })
    
    if len(data['title'].strip()) == 0:
        raise APIError("Title cannot be empty", 400)
    
    if len(data['content'].strip()) == 0:
        raise APIError("Content cannot be empty", 400)
    
    if len(data['author_name'].strip()) == 0:
        raise APIError("Author name cannot be empty", 400)
    
    posts = await db.get_collection('posts')
    
    post_id = await create_unique_id()
    post_data = {
        'title': data['title'].strip(),
        'content': data['content'].strip(),
        'author_name': data['author_name'].strip()[:100],  # Limit name length
        'author_email': data.get('author_email', '').strip()[:255],  # Optional
        'author_website': data.get('author_website', '').strip()[:255],  # Optional
        'created_at': await create_timestamp(),
        'updated_at': await create_timestamp(),
        'tags': data.get('tags', []) if isinstance(data.get('tags'), list) else [],
        'is_published': True,  # Public posts are always published
        'is_anonymous': True,
        'views': 0,
        'likes': 0,
        'ip_address': request.remote or 'unknown'
    }
    
    # Handle edit password
    if data.get('new_edit_password'):
        post_data['edit_password'] = hash_password(data['new_edit_password'])
    
    await posts.set(post_id, post_data)
    
    # Update search index
    if search_engine:
        try:
            await search_engine.add_document(
                doc_id=post_id,
                doc_type='post',
                title=post_data['title'],
                content=post_data['content'],
                author=post_data['author_name'],
                metadata={
                    'tags': post_data['tags'],
                    'created_at': post_data['created_at'],
                    'views': post_data['views'],
                    'likes': post_data['likes'],
                    'published': post_data['is_published'],
                    'anonymous': True
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update search index for new post {post_id}: {e}")
    
    return app.json_response({
        'message': 'Post created successfully',
        'post_id': post_id,
        'post': post_data
    }, status=201)


@app.put('/api/public/posts/{post_id}')
async def update_public_post(request):
    """Update a public post (with password if set, or open editing)"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    data = get_json_data(request)
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post or not post.get('is_anonymous', False):
        raise APIError("Post not found or not editable", 404)
    
    # Check if post has an edit password
    edit_password = post.get('edit_password')
    if edit_password:
        provided_password = data.get('edit_password', '')
        if not provided_password or hash_password(provided_password) != edit_password:
            raise APIError("Invalid edit password", 403)
    
    # Update allowed fields
    updates = {}
    for field in ['title', 'content', 'tags', 'author_name', 'author_email', 'author_website']:
        if field in data:
            if field in ['title', 'content', 'author_name'] and data[field]:
                updates[field] = data[field].strip()
            elif field in ['author_email', 'author_website'] and data[field]:
                updates[field] = data[field].strip()[:255]
            elif field == 'tags' and isinstance(data[field], list):
                updates[field] = data[field]
    
    # Allow setting an edit password for future edits
    if 'new_edit_password' in data and data['new_edit_password']:
        updates['edit_password'] = hash_password(data['new_edit_password'])
    
    updates['updated_at'] = await create_timestamp()
    
    await posts.update(post_id, updates)
    
    # Update search index
    if search_engine:
        try:
            updated_post = {**post, **updates}
            await search_engine.update_document(
                doc_id=post_id,
                doc_type='post',
                title=updated_post['title'],
                content=updated_post['content'],
                author=updated_post.get('author_name', 'Anonymous'),
                metadata={
                    'tags': updated_post['tags'],
                    'created_at': updated_post['created_at'],
                    'views': updated_post.get('views', 0),
                    'likes': updated_post.get('likes', 0),
                    'published': updated_post['is_published'],
                    'anonymous': True
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update search index for post {post_id}: {e}")
    
    return app.json_response({
        'message': 'Post updated successfully',
        'post_id': post_id
    })


@app.post('/api/public/posts/{post_id}/like')
async def like_public_post(request):
    """Like a public post (anonymous)"""
    path_params = get_path_params(request)
    post_id = path_params['post_id']
    
    posts = await db.get_collection('posts')
    post = await posts.get(post_id)
    
    if not post or not post.get('is_published', True):
        raise APIError("Post not found", 404)
    
    # For anonymous likes, we'll just increment the counter
    # In a real system, you might want to track by IP or use cookies
    try:
        new_likes = await posts.increment(post_id, 'likes')
        
        return app.json_response({
            'message': 'Post liked successfully',
            'likes': new_likes
        })
        
    except Exception as e:
        logger.error(f"Failed to like post {post_id}: {e}")
        raise APIError("Failed to like post", 500)


# =============================================================================
# PUBLIC SEARCH - No Authentication Required
# =============================================================================

@app.get('/api/public/search')
async def search_public_content(request):
    """Public search across content"""
    query_params = get_query_params(request)
    
    query = query_params.get('q', '').strip()
    if not query:
        return app.json_response({
            'results': [],
            'total': 0,
            'query': query,
            'suggestions': []
        })
    
    limit = min(int(query_params.get('limit', 20)), 100)
    types = query_params.get('types', '').split(',') if query_params.get('types') else None
    
    # Build filters for public content only
    filters = {'min_score': 0.01}
    if types:
        valid_types = [t.strip() for t in types if t.strip() in ['post', 'comment']]
        if valid_types:
            filters['types'] = valid_types
    
    try:
        results = await search_engine.search(query, filters, limit)
        
        # Filter results to only include published content
        public_results = []
        for result in results:
            if result.type == 'post':
                # Check if post is published
                posts = await db.get_collection('posts')
                post = await posts.get(result.id)
                if post and post.get('is_published', True):
                    public_results.append(result)
            elif result.type == 'comment':
                # Check if parent post is published
                comments = await db.get_collection('comments')
                comment = await comments.get(result.id)
                if comment:
                    posts = await db.get_collection('posts')
                    post = await posts.get(comment.get('post_id'))
                    if post and post.get('is_published', True):
                        public_results.append(result)
        
        # Convert to dictionaries
        result_dicts = []
        for result in public_results:
            result_dict = {
                'id': result.id,
                'type': result.type,
                'title': result.title,
                'content': result.content[:500] + '...' if len(result.content) > 500 else result.content,
                'author': result.author,
                'score': result.score,
                'highlights': result.highlights,
                'metadata': result.metadata,
                'created_at': result.created_at
            }
            result_dicts.append(result_dict)
        
        suggestions = await search_engine.get_suggestions(query, 5)
        
        return app.json_response({
            'results': result_dicts,
            'total': len(result_dicts),
            'query': query,
            'suggestions': suggestions
        })
        
    except Exception as e:
        logger.error(f"Public search error: {e}")
        raise APIError(f"Search failed: {str(e)}", 500)


# =============================================================================
# ORIGINAL Authentication Endpoints (PRESERVED)
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
    
    # Add user to search index
    if search_engine:
        try:
            await search_engine.add_document(
                doc_id=user_id,
                doc_type='user',
                title=data['username'],
                content=data['email'],
                author=data['username'],
                metadata={
                    'created_at': user_data['created_at'],
                    'active': user_data['is_active']
                }
            )
        except Exception as e:
            logger.warning(f"Failed to add user {user_id} to search index: {e}")
    
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
# ORIGINAL Advanced Search Endpoints (PRESERVED)
# =============================================================================

@app.get('/api/search')
async def search_content(request):
    """Advanced search across all content types"""
    query_params = get_query_params(request)
    
    # Get search query
    query = query_params.get('q', '').strip()
    if not query:
        return app.json_response({
            'results': [],
            'total': 0,
            'query': query,
            'suggestions': []
        })
    
    # Parse search parameters
    limit = min(int(query_params.get('limit', 50)), 200)
    types = query_params.get('types', '').split(',') if query_params.get('types') else None
    author = query_params.get('author', '')
    min_score = float(query_params.get('min_score', 0.01))
    
    # Parse date filters
    date_from = None
    date_to = None
    if query_params.get('date_from'):
        try:
            date_from = float(query_params.get('date_from'))
        except ValueError:
            pass
    
    if query_params.get('date_to'):
        try:
            date_to = float(query_params.get('date_to'))
        except ValueError:
            pass
    
    # Build filters
    filters = {'min_score': min_score}
    if types:
        # Clean up type names
        valid_types = [t.strip() for t in types if t.strip() in ['post', 'file', 'user', 'comment']]
        if valid_types:
            filters['types'] = valid_types
    
    if author:
        filters['author'] = author
    
    if date_from is not None:
        filters['date_from'] = date_from
    
    if date_to is not None:
        filters['date_to'] = date_to
    
    try:
        # Perform search
        results = await search_engine.search(query, filters, limit)
        
        # Convert SearchResult objects to JSON-serializable dictionaries
        result_dicts = []
        for result in results:
            result_dict = {
                'id': result.id,
                'type': result.type,
                'title': result.title,
                'content': result.content[:500] + '...' if len(result.content) > 500 else result.content,
                'author': result.author,
                'score': result.score,
                'highlights': result.highlights,
                'metadata': result.metadata,
                'created_at': result.created_at
            }
            result_dicts.append(result_dict)
        
        # Get search suggestions
        suggestions = await search_engine.get_suggestions(query, 5)
        
        return app.json_response({
            'results': result_dicts,
            'total': len(result_dicts),
            'query': query,
            'suggestions': suggestions,
            'filters_applied': filters
        })
        
    except Exception as e:
        logger.error(f"Search error: {e}")
        raise APIError(f"Search failed: {str(e)}", 500)


@app.get('/api/search/suggestions')
async def get_search_suggestions(request):
    """Get real-time search suggestions"""
    query_params = get_query_params(request)
    query = query_params.get('q', '').strip()
    limit = min(int(query_params.get('limit', 10)), 20)
    
    if not query or len(query) < 2:
        return app.json_response({
            'suggestions': [],
            'query': query
        })
    
    try:
        suggestions = await search_engine.get_suggestions(query, limit)
        return app.json_response({
            'suggestions': suggestions,
            'query': query
        })
    except Exception as e:
        logger.error(f"Suggestions error: {e}")
        return app.json_response({
            'suggestions': [],
            'query': query,
            'error': str(e)
        })


@app.get('/api/search/stats')
async def get_search_stats(request):
    """Get search engine statistics"""
    await get_current_user(request)  # Require authentication
    
    try:
        stats = search_engine.get_stats()
        return app.json_response(stats)
    except Exception as e:
        logger.error(f"Search stats error: {e}")
        raise APIError(f"Failed to get search stats: {str(e)}", 500)


@app.post('/api/search/reindex')
async def reindex_search(request):
    """Manually trigger search index rebuild"""
    await get_current_user(request)  # Require authentication
    
    if search_engine.indexing_in_progress:
        raise APIError("Indexing already in progress", 409)
    
    try:
        # Start reindexing in background
        asyncio.create_task(search_engine.rebuild_index())
        
        return app.json_response({
            'message': 'Search index rebuild started',
            'status': 'in_progress'
        })
    except Exception as e:
        logger.error(f"Reindex error: {e}")
        raise APIError(f"Failed to start reindexing: {str(e)}", 500)


# =============================================================================
# ORIGINAL File Upload and Management Endpoints (PRESERVED)
# =============================================================================

@app.post('/api/files/upload')
async def upload_file(request: Request):
    """Upload one or more files and update search index"""
    user = await get_current_user(request)
    
    if not request.content_type or not request.content_type.startswith('multipart/'):
        raise APIError("Request must be multipart/form-data", 400)
    
    reader = await request.multipart()
    uploaded_files = []
    files_collection = await db.get_collection('files')
    
    async for field in reader:
        if field.name == 'file' or field.name == 'files' or field.name.startswith('file'):
            if not field.filename:
                continue
            
            # Generate unique file ID and storage path
            file_id = await create_unique_id()
            original_filename = field.filename
            safe_name = safe_filename(original_filename)
            file_extension = Path(original_filename).suffix
            stored_filename = f"{file_id}_{safe_name}"
            file_path = Path(FILES_DIRECTORY) / stored_filename
            
            # Read and save file
            try:
                file_size = 0
                with open(file_path, 'wb') as f:
                    while True:
                        chunk = await field.read_chunk(8192)
                        if not chunk:
                            break
                        
                        file_size += len(chunk)
                        
                        # Check file size limit
                        if file_size > MAX_FILE_SIZE:
                            f.close()
                            file_path.unlink()  # Delete the file
                            raise APIError(f"File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB", 413)
                        
                        f.write(chunk)
                
                # Generate file hash
                file_hash = generate_file_hash(str(file_path))
                
                # Store file metadata
                file_metadata = {
                    'original_filename': original_filename,
                    'stored_filename': stored_filename,
                    'file_size': file_size,
                    'mime_type': get_file_mime_type(original_filename),
                    'file_hash': file_hash,
                    'owner_id': user['_key'],
                    'owner_username': user['username'],
                    'uploaded_at': await create_timestamp(),
                    'downloads': 0,
                    'views': 0,
                    'is_public': False,
                    'share_token': None,
                    'description': '',
                    'tags': []
                }
                
                await files_collection.set(file_id, file_metadata)
                
                # Update search index
                if search_engine:
                    try:
                        # Try to extract text content if it's a text file
                        content = file_metadata['description']
                        if search_engine.text_extractor.can_extract(original_filename, file_metadata['mime_type']):
                            try:
                                extracted_text = await search_engine.text_extractor.extract_text(
                                    stored_filename, original_filename, file_metadata['mime_type']
                                )
                                if extracted_text:
                                    content = f"{content} {extracted_text}".strip()
                            except Exception as e:
                                logger.warning(f"Failed to extract content for search indexing: {e}")
                        
                        await search_engine.add_document(
                            doc_id=file_id,
                            doc_type='file',
                            title=original_filename,
                            content=content,
                            author=user['username'],
                            metadata={
                                'filename': original_filename,
                                'tags': file_metadata['tags'],
                                'created_at': file_metadata['uploaded_at'],
                                'file_size': file_metadata['file_size'],
                                'mime_type': file_metadata['mime_type'],
                                'downloads': file_metadata['downloads'],
                                'views': file_metadata['views'],
                                'public': file_metadata['is_public'],
                                'description': file_metadata['description']
                            }
                        )
                    except Exception as e:
                        logger.warning(f"Failed to add file {file_id} to search index: {e}")
                
                uploaded_files.append({
                    'file_id': file_id,
                    'original_filename': original_filename,
                    'file_size': file_size,
                    'mime_type': file_metadata['mime_type']
                })
                
            except Exception as e:
                # Clean up file if error occurred
                if file_path.exists():
                    file_path.unlink()
                
                if isinstance(e, APIError):
                    raise e
                
                logger.error(f"Error uploading file {original_filename}: {e}")
                raise APIError(f"Failed to upload file {original_filename}", 500)
    
    if not uploaded_files:
        raise APIError("No files were uploaded", 400)
    
    return app.json_response({
        'message': f'{len(uploaded_files)} file(s) uploaded successfully',
        'files': uploaded_files
    }, status=201)


@app.get('/api/files')
async def list_user_files(request):
    """List current user's files"""
    user = await get_current_user(request)
    query_params = get_query_params(request)
    
    limit = min(int(query_params.get('limit', 50)), 200)
    include_public = query_params.get('include_public', 'false').lower() == 'true'
    
    files_collection = await db.get_collection('files')
    
    def file_filter(file_record):
        # User's own files or public files if requested
        if file_record.get('owner_id') == user['_key']:
            return True
        if include_public and file_record.get('is_public', False):
            return True
        return False
    
    user_files = await files_collection.find(filter_func=file_filter, limit=limit)
    
    # Sort by upload date (newest first)
    user_files.sort(key=lambda x: x.get('uploaded_at', 0), reverse=True)
    
    # Remove sensitive information for public files not owned by user
    filtered_files = []
    for file_record in user_files:
        if file_record.get('owner_id') != user['_key']:
            # For other users' public files, only show limited info
            filtered_files.append({
                '_key': file_record['_key'],
                'original_filename': file_record['original_filename'],
                'file_size': file_record['file_size'],
                'mime_type': file_record['mime_type'],
                'uploaded_at': file_record['uploaded_at'],
                'downloads': file_record['downloads'],
                'views': file_record.get('views', 0),
                'owner_username': file_record['owner_username'],
                'description': file_record.get('description', ''),
                'tags': file_record.get('tags', [])
            })
        else:
            filtered_files.append(file_record)
    
    return app.json_response({
        'files': filtered_files,
        'count': len(filtered_files)
    })


@app.get('/api/files/{file_id}')
async def get_file_info(request):
    """Get file metadata with preview URLs"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    file_id = path_params['file_id']
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check permissions
    if file_record['owner_id'] != user['_key'] and not file_record.get('is_public', False):
        raise APIError("Unauthorized to view this file", 403)
    
    # Add convenience URLs
    base_url = f"/api/files/{file_id}"
    file_record['urls'] = {
        'download': f"{base_url}/download",
        'preview': f"{base_url}/download?preview=true",
        'force_download': f"{base_url}/download?download=true"
    }
    
    # Add display information
    file_record['display'] = {
        'can_preview': file_record['mime_type'].startswith(('image/', 'text/', 'application/pdf')),
        'is_image': file_record['mime_type'].startswith('image/'),
        'is_video': file_record['mime_type'].startswith('video/'),
        'is_audio': file_record['mime_type'].startswith('audio/'),
        'icon': get_file_icon_unicode(file_record['mime_type'])
    }
    
    return app.json_response(file_record)


@app.get('/api/files/{file_id}/download')
async def download_file(request):
    """Download or preview a file - ENHANCED with proper CORS and Content-Disposition"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    query_params = get_query_params(request)
    file_id = path_params['file_id']
    
    # Check request parameters
    force_download = query_params.get('download') == 'true'
    is_preview = query_params.get('preview') == 'true'
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check permissions
    if file_record['owner_id'] != user['_key'] and not file_record.get('is_public', False):
        raise APIError("Unauthorized to access this file", 403)
    
    file_path = Path(FILES_DIRECTORY) / file_record['stored_filename']
    
    if not file_path.exists():
        raise APIError("File not found on disk", 404)
    
    # Increment appropriate counter
    if is_preview:
        # Increment view counter for previews
        try:
            current_views = file_record.get('views', 0)
            await files_collection.update(file_id, {'views': current_views + 1})
        except Exception as e:
            logger.warning(f"Failed to increment view count for file {file_id}: {e}")
    else:
        # Increment download counter for downloads
        try:
            await files_collection.increment(file_id, 'downloads')
        except Exception as e:
            logger.warning(f"Failed to increment download count for file {file_id}: {e}")
    
    # Get origin for CORS
    origin = request.headers.get('Origin', '')
    
    # Determine content disposition
    content_disposition = get_content_disposition(
        file_record['mime_type'], 
        file_record['original_filename'], 
        force_download
    )
    
    # Prepare headers with CORS support
    headers = {
        'Content-Type': file_record['mime_type'],
        'Content-Disposition': content_disposition,
        'Content-Length': str(file_record['file_size'])
    }
    
    # Add caching headers for better performance
    if not force_download:
        headers.update({
            'Cache-Control': 'public, max-age=3600',  # Cache for 1 hour
            'ETag': f'"{file_record.get("file_hash", file_id)}"',  # Use file hash as ETag
        })
    
    # Add CORS headers for file:// protocol support
    add_cors_headers(headers, origin)
    
    # Create streaming response with CORS headers
    response = StreamResponse(
        status=200,
        headers=headers
    )
    
    await response.prepare(request)
    
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                await response.write(chunk)
    except Exception as e:
        logger.warning(f"Client disconnected during file transfer {file_id}: {e}")
        # Client probably disconnected, which is normal
        pass
    
    try:
        await response.write_eof()
    except Exception as e:
        logger.warning(f"Client disconnected while finishing file transfer {file_id}: {e}")
        # Client disconnection is normal
        pass
    
    return response


@app.put('/api/files/{file_id}')
async def update_file_metadata(request):
    """Update file metadata and search index"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    file_id = path_params['file_id']
    data = get_json_data(request)
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check ownership
    if file_record['owner_id'] != user['_key']:
        raise APIError("Unauthorized to modify this file", 403)
    
    # Update allowed fields
    updates = {}
    
    if 'description' in data and isinstance(data['description'], str):
        updates['description'] = data['description'][:500]  # Limit description length
    
    if 'tags' in data and isinstance(data['tags'], list):
        # Validate tags
        valid_tags = [tag for tag in data['tags'] if isinstance(tag, str) and len(tag.strip()) > 0]
        updates['tags'] = valid_tags[:10]  # Limit to 10 tags
    
    if 'is_public' in data and isinstance(data['is_public'], bool):
        updates['is_public'] = data['is_public']
    
    updates['updated_at'] = await create_timestamp()
    
    await files_collection.update(file_id, updates)
    
    # Update search index
    if search_engine:
        try:
            updated_file = {**file_record, **updates}
            
            # Rebuild content with updated description
            content = updated_file['description']
            if search_engine.text_extractor.can_extract(
                updated_file['original_filename'], 
                updated_file['mime_type']
            ):
                try:
                    extracted_text = await search_engine.text_extractor.extract_text(
                        updated_file['stored_filename'], 
                        updated_file['original_filename'], 
                        updated_file['mime_type']
                    )
                    if extracted_text:
                        content = f"{content} {extracted_text}".strip()
                except Exception as e:
                    logger.warning(f"Failed to extract content for search update: {e}")
            
            await search_engine.update_document(
                doc_id=file_id,
                doc_type='file',
                title=updated_file['original_filename'],
                content=content,
                author=updated_file['owner_username'],
                metadata={
                    'filename': updated_file['original_filename'],
                    'tags': updated_file['tags'],
                    'created_at': updated_file['uploaded_at'],
                    'file_size': updated_file['file_size'],
                    'mime_type': updated_file['mime_type'],
                    'downloads': updated_file.get('downloads', 0),
                    'views': updated_file.get('views', 0),
                    'public': updated_file['is_public'],
                    'description': updated_file['description']
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update file {file_id} in search index: {e}")
    
    return app.json_response({
        'message': 'File metadata updated successfully',
        'file_id': file_id
    })


@app.delete('/api/files/{file_id}')
async def delete_file(request):
    """Delete a file and update search index"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    file_id = path_params['file_id']
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check ownership
    if file_record['owner_id'] != user['_key']:
        raise APIError("Unauthorized to delete this file", 403)
    
    # Delete file from disk
    file_path = Path(FILES_DIRECTORY) / file_record['stored_filename']
    
    try:
        if file_path.exists():
            file_path.unlink()
    except Exception as e:
        logger.warning(f"Failed to delete file from disk: {e}")
    
    # Delete from database
    await files_collection.delete(file_id)
    
    # Update search index
    if search_engine:
        try:
            await search_engine.remove_document(file_id)
        except Exception as e:
            logger.warning(f"Failed to remove file {file_id} from search index: {e}")
    
    return app.json_response({
        'message': 'File deleted successfully'
    })


@app.post('/api/files/{file_id}/share')
async def create_file_share(request):
    """Create a public share link for a file"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    file_id = path_params['file_id']
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check ownership
    if file_record['owner_id'] != user['_key']:
        raise APIError("Unauthorized to share this file", 403)
    
    # Generate or get existing share token
    share_token = file_record.get('share_token')
    if not share_token:
        share_token = await create_share_token(file_id)
        await files_collection.update(file_id, {
            'share_token': share_token,
            'is_public': True
        })
    
    return app.json_response({
        'message': 'Share link created successfully',
        'share_token': share_token,
        'share_url': f'/api/files/share/{share_token}'
    })


@app.get('/api/files/share/{share_token}')
async def download_shared_file(request):
    """Download a file using share token (no authentication required) - ENHANCED"""
    path_params = get_path_params(request)
    query_params = get_query_params(request)
    share_token = path_params['share_token']
    
    # Check request parameters
    force_download = query_params.get('download') == 'true'
    is_preview = query_params.get('preview') == 'true'
    
    # Verify share token
    share_data = await verify_share_token(share_token)
    if not share_data:
        raise APIError("Invalid share token", 404)
    
    file_id = share_data['file_id']
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record or not file_record.get('is_public', False):
        raise APIError("File not found or not publicly shared", 404)
    
    file_path = Path(FILES_DIRECTORY) / file_record['stored_filename']
    
    if not file_path.exists():
        raise APIError("File not found on disk", 404)
    
    # Increment appropriate counter
    if is_preview:
        try:
            current_views = file_record.get('views', 0)
            await files_collection.update(file_id, {'views': current_views + 1})
        except Exception as e:
            logger.warning(f"Failed to increment view count for shared file {file_id}: {e}")
    else:
        try:
            await files_collection.increment(file_id, 'downloads')
        except Exception as e:
            logger.warning(f"Failed to increment download count for shared file {file_id}: {e}")
    
    # Get origin for CORS
    origin = request.headers.get('Origin', '')
    
    # Determine content disposition
    content_disposition = get_content_disposition(
        file_record['mime_type'], 
        file_record['original_filename'], 
        force_download
    )
    
    # Prepare headers with CORS support
    headers = {
        'Content-Type': file_record['mime_type'],
        'Content-Disposition': content_disposition,
        'Content-Length': str(file_record['file_size'])
    }
    
    # Add caching headers for public files
    if not force_download:
        headers.update({
            'Cache-Control': 'public, max-age=7200',  # Cache for 2 hours for public files
            'ETag': f'"{file_record.get("file_hash", file_id)}"',
        })
    
    # Add CORS headers for file:// protocol support
    add_cors_headers(headers, origin)
    
    # Create streaming response
    response = StreamResponse(
        status=200,
        headers=headers
    )
    
    await response.prepare(request)
    
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                await response.write(chunk)
    except Exception as e:
        logger.warning(f"Client disconnected during shared file transfer {file_id}: {e}")
        pass
    
    try:
        await response.write_eof()
    except Exception as e:
        logger.warning(f"Client disconnected while finishing shared file transfer {file_id}: {e}")
        pass
    
    return response


@app.delete('/api/files/{file_id}/share')
async def revoke_file_share(request):
    """Revoke public sharing for a file"""
    user = await get_current_user(request)
    path_params = get_path_params(request)
    file_id = path_params['file_id']
    
    files_collection = await db.get_collection('files')
    file_record = await files_collection.get(file_id)
    
    if not file_record:
        raise APIError("File not found", 404)
    
    # Check ownership
    if file_record['owner_id'] != user['_key']:
        raise APIError("Unauthorized to modify this file", 403)
    
    # Revoke sharing
    await files_collection.update(file_id, {
        'share_token': None,
        'is_public': False
    })
    
    return app.json_response({
        'message': 'File sharing revoked successfully'
    })


# =============================================================================
# ORIGINAL Posts/Content Management Endpoints (PRESERVED)
# =============================================================================

@app.post('/api/posts')
async def create_post(request):
    """Create a new post and update search index"""
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
        'likes': 0,
        'attached_files': data.get('attached_files', [])
    }
    
    await posts.set(post_id, post_data)
    
    # Update search index
    if search_engine:
        try:
            await search_engine.add_document(
                doc_id=post_id,
                doc_type='post',
                title=post_data['title'],
                content=post_data['content'],
                author=post_data['author_username'],
                metadata={
                    'tags': post_data['tags'],
                    'created_at': post_data['created_at'],
                    'views': post_data['views'],
                    'likes': post_data['likes'],
                    'published': post_data['is_published']
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update search index for new post {post_id}: {e}")
    
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
async def get_current_user_liked_posts_endpoint(request):
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
    """Update a post and search index"""
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
    for field in ['title', 'content', 'tags', 'is_published', 'attached_files']:
        if field in data:
            if field == 'title' and data[field]:
                updates[field] = data[field].strip()
            elif field == 'content' and data[field]:
                updates[field] = data[field].strip()
            elif field == 'tags' and isinstance(data[field], list):
                updates[field] = data[field]
            elif field == 'is_published' and isinstance(data[field], bool):
                updates[field] = data[field]
            elif field == 'attached_files' and isinstance(data[field], list):
                updates[field] = data[field]
    
    updates['updated_at'] = await create_timestamp()
    
    await posts.update(post_id, updates)
    
    # Update search index
    if search_engine:
        try:
            updated_post = {**post, **updates}
            await search_engine.update_document(
                doc_id=post_id,
                doc_type='post',
                title=updated_post['title'],
                content=updated_post['content'],
                author=updated_post['author_username'],
                metadata={
                    'tags': updated_post['tags'],
                    'created_at': updated_post['created_at'],
                    'views': updated_post.get('views', 0),
                    'likes': updated_post.get('likes', 0),
                    'published': updated_post['is_published']
                }
            )
        except Exception as e:
            logger.warning(f"Failed to update search index for post {post_id}: {e}")
    
    return app.json_response({
        'message': 'Post updated successfully',
        'post_id': post_id
    })


@app.delete('/api/posts/{post_id}')
async def delete_post(request):
    """Delete a post and update search index"""
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
    
    # Update search index
    if search_engine:
        try:
            await search_engine.remove_document(post_id)
        except Exception as e:
            logger.warning(f"Failed to remove post {post_id} from search index: {e}")
    
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
# ORIGINAL Data Management Endpoints (PRESERVED)
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
    valid_collections = ['users', 'posts', 'post_likes', 'files', 'comments']
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
# ORIGINAL Session Management (PRESERVED)
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
# ORIGINAL Health and Status Endpoints (PRESERVED)
# =============================================================================

@app.get('/api/health')
async def health_check(request):
    """Health check endpoint"""
    return app.json_response({
        'status': 'healthy',
        'timestamp': await create_timestamp(),
        'version': '3.0.0',
        'features': {
            'public_access': True,
            'anonymous_posting': True,
            'nested_comments': True,
            'search_enabled': search_engine is not None,
            'search_indexing': search_engine.indexing_in_progress if search_engine else False,
            'file_upload': True,
            'file_sharing': True,
            'user_authentication': True
        }
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
    
    # Calculate total file storage used
    total_file_size = 0
    files_count = 0
    try:
        files_dir = Path(FILES_DIRECTORY)
        if files_dir.exists():
            for file_path in files_dir.iterdir():
                if file_path.is_file():
                    total_file_size += file_path.stat().st_size
                    files_count += 1
    except Exception as e:
        logger.warning(f"Failed to calculate file storage stats: {e}")
    
    # Get search stats if available
    search_stats = {}
    if search_engine:
        try:
            search_stats = search_engine.get_stats()
        except Exception as e:
            logger.warning(f"Failed to get search stats: {e}")
    
    return app.json_response({
        'status': 'running',
        'collections': stats,
        'sessions': len(_sessions),
        'file_storage': {
            'total_files': files_count,
            'total_size_bytes': total_file_size,
            'total_size_mb': round(total_file_size / (1024 * 1024), 2)
        },
        'search_engine': search_stats,
        'uptime': time.time(),
        'timestamp': await create_timestamp()
    })


# =============================================================================
# Root Endpoint
# =============================================================================

@app.get('/')
async def root_endpoint(request):
    """Root endpoint with API information"""
    return app.json_response({
        'name': 'Complete File Sharing API with Public Journal',
        'version': '3.0.0',
        'description': 'A comprehensive API with BOTH authenticated features AND public anonymous access',
        'features': [
            'PUBLIC FRONTPAGE ACCESS',
            'Anonymous post creation and editing',
            'Nested comment system',
            'Public search without authentication',
            'FILE UPLOAD AND SHARING',
            'Advanced search engine with TF-IDF',
            'User authentication (optional)',
            'File management and sharing',
            'CORS support for file:// protocol',
            'Text file content indexing',
            'Real-time search suggestions',
            'Session management',
            'Complete database operations'
        ],
        'public_endpoints': {
            'posts': 'GET /api/public/posts',
            'post_detail': 'GET /api/public/posts/{id}',
            'comments': 'GET /api/public/posts/{id}/comments',
            'add_comment': 'POST /api/public/posts/{id}/comments',
            'create_post': 'POST /api/public/posts',
            'edit_post': 'PUT /api/public/posts/{id}',
            'like_post': 'POST /api/public/posts/{id}/like',
            'search': 'GET /api/public/search'
        },
        'authenticated_endpoints': {
            'auth': '/api/auth/*',
            'posts': '/api/posts/*',
            'files': '/api/files/*',
            'search': '/api/search/*',
            'collections': '/api/collections/*',
            'health': '/api/health',
            'status': '/api/status'
        },
        'file_features': {
            'upload': 'POST /api/files/upload',
            'list': 'GET /api/files',
            'download': 'GET /api/files/{id}/download',
            'preview': 'GET /api/files/{id}/download?preview=true',
            'share': 'POST /api/files/{id}/share',
            'public_download': 'GET /api/files/share/{token}',
            'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024)
        }
    })


# Handle CORS preflight requests - ENHANCED
@app.options('/api/{path:.*}')
async def handle_cors_preflight(request):
    """Enhanced OPTIONS handler for CORS preflight"""
    origin = request.headers.get('Origin', '')
    
    headers = {
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Access-Control-Max-Age': '86400'
    }
    
    # Handle origin properly
    if origin == 'null':
        headers['Access-Control-Allow-Origin'] = 'null'
    elif origin:
        headers['Access-Control-Allow-Origin'] = origin
    else:
        headers['Access-Control-Allow-Origin'] = '*'
    
    return web.Response(status=200, headers=headers)


# =============================================================================
# Application Lifecycle with Search Engine Initialization
# =============================================================================

async def startup():
    """Application startup tasks"""
    global search_engine
    
    logger.info("Starting up the COMPLETE API with public AND authenticated features...")
    
    # Ensure directories exist
    Path(FILES_DIRECTORY).mkdir(parents=True, exist_ok=True)
    
    # Initialize default collections or data if needed
    try:
        users = await db.get_collection('users')
        posts = await db.get_collection('posts')
        post_likes = await db.get_collection('post_likes')
        files = await db.get_collection('files')
        comments = await db.get_collection('comments')  # New collection for comments
        
        logger.info("Database collections initialized")
        logger.info("✅ ALL ORIGINAL FEATURES PRESERVED")
        logger.info("✅ File upload and sharing system")
        logger.info(f"✅ Files stored in: {FILES_DIRECTORY}")
        logger.info(f"✅ Maximum file size: {MAX_FILE_SIZE // (1024*1024)}MB")
        logger.info("✅ User authentication system")
        logger.info("✅ CORS fixed for file:// protocol")
        logger.info("✅ Image/video preview with proper headers")
        logger.info("✅ NEW: PUBLIC ACCESS - No login required for reading")
        logger.info("✅ NEW: ANONYMOUS POSTING - Create posts without registration")
        logger.info("✅ NEW: NESTED COMMENTS system")
        logger.info("✅ NEW: PUBLIC SEARCH - Search without authentication")
        
        # Initialize search engine
        logger.info("Initializing advanced search engine...")
        search_engine = create_search_engine(db, FILES_DIRECTORY)
        await search_engine.initialize()
        logger.info("✅ Advanced search engine initialized!")
        logger.info("✅ Text file content extraction enabled")
        logger.info("✅ Real-time search suggestions enabled")
        logger.info("✅ TF-IDF relevance scoring enabled")
        
    except Exception as e:
        logger.error(f"Failed to initialize database or search engine: {e}")
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
    
    print("🚀 Starting COMPLETE API with PUBLIC + AUTHENTICATED features")
    print(f"🌐 Server: {host}:{port}")
    print("✅ ALL ORIGINAL FEATURES PRESERVED:")
    print("  • File upload, sharing, management")
    print("  • User authentication system")
    print("  • Advanced search with TF-IDF scoring")
    print("  • Real-time search suggestions")
    print("  • Text file content extraction")
    print("  • CORS support for file:// protocol")
    print("  • Database collections and stats")
    print("  • Session management")
    print("")
    print("✅ NEW PUBLIC FEATURES ADDED:")
    print("  • Public frontpage - no login required")
    print("  • Anonymous posting and editing")
    print("  • Nested comment system")
    print("  • Public search")
    print("  • Like posts anonymously")
    print("  • No registration pressure")
    print("")
    print("Dependencies: aiohttp only!")
    print("Complete functionality: File sharing + Content management + Public access")
    
    try:
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)