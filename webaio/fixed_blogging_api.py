#!/usr/bin/env python3
"""
AIOHTTP Blogging API - Complete Fixed Implementation
Features: Users, Posts, Comments, Tags, File Uploads, Search, Real-time updates
Security: Token auth, rate limiting, input validation, CORS
Database: Custom async JSON database
"""

import json
import asyncio
import hashlib
import secrets
import datetime
import re
import os
import mimetypes
import zipfile
import base64
import uuid
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager

from aiohttp import web, ClientError, WSMsgType
from aiohttp.client import ClientResponseError, ClientConnectorError
from aiohttp.web import middleware
import ssl
import weakref

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# =============================================================================
# COMMON REUSABLE ABSTRACTIONS
# =============================================================================

@dataclass
class User:
    """User data model"""
    id: str
    username: str
    email: str
    password_hash: str
    salt: str
    role: str = "user"  # user, moderator, admin
    created_at: str = ""
    description: str = ""
    mood: str = ""
    avatar_url: str = ""
    background_url: str = ""
    is_active: bool = True

@dataclass
class Post:
    """Post data model"""
    id: str
    author_id: str
    title: str
    content: str
    category: str
    tags: List[str]
    created_at: str
    updated_at: str
    is_published: bool = True
    attachments: List[Dict] = None
    view_count: int = 0

    def __post_init__(self):
        if self.attachments is None:
            self.attachments = []

@dataclass
class Comment:
    """Comment data model"""
    id: str
    post_id: str
    author_id: str
    content: str
    parent_id: Optional[str]
    mentions: List[str]
    created_at: str
    is_deleted: bool = False

    def __post_init__(self):
        if self.mentions is None:
            self.mentions = []

class SecurityUtils:
    """Security utilities for password hashing and token generation"""
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a random salt for password hashing"""
        logger.debug("Generating new salt")
        return secrets.token_hex(32)
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        logger.debug("Hashing password")
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, salt: str, hash_stored: str) -> bool:
        """Verify password against stored hash"""
        logger.debug("Verifying password")
        return SecurityUtils.hash_password(password, salt) == hash_stored
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure random token"""
        logger.debug("Generating new token")
        return secrets.token_urlsafe(32)

class ValidationUtils:
    """Input validation utilities"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format"""
        pattern = r'^[a-zA-Z0-9_]{3,30}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def sanitize_input(text: str) -> str:
        """Sanitize text input"""
        if not isinstance(text, str):
            return ""
        # Remove potentially dangerous characters
        return re.sub(r'[<>"\']', '', text.strip())
    
    @staticmethod
    def extract_mentions(content: str) -> List[str]:
        """Extract @mentions from content"""
        pattern = r'@(\w+)'
        return re.findall(pattern, content)

class DateTimeUtils:
    """DateTime utilities with timezone awareness"""
    
    @staticmethod
    def now_iso() -> str:
        """Get current datetime in ISO format (timezone-aware)"""
        return datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    @staticmethod
    def parse_iso(iso_string: str) -> datetime.datetime:
        """Parse ISO datetime string"""
        return datetime.datetime.fromisoformat(iso_string)

# =============================================================================
# CUSTOM ASYNC JSON DATABASE
# =============================================================================

class AsyncJSONDatabase:
    """
    Custom asynchronous concurrent JSON database
    Thread-safe with file locking and in-memory caching
    """
    
    def __init__(self, db_path: str = "database"):
        self.db_path = Path(db_path)
        self.db_path.mkdir(exist_ok=True)
        self._locks = {}
        self._cache = {}
        logger.info(f"Initialized AsyncJSONDatabase at {self.db_path}")
    
    def _get_lock(self, collection: str) -> asyncio.Lock:
        """Get or create lock for collection"""
        if collection not in self._locks:
            self._locks[collection] = asyncio.Lock()
        return self._locks[collection]
    
    def _get_file_path(self, collection: str) -> Path:
        """Get file path for collection"""
        return self.db_path / f"{collection}.json"
    
    async def _load_collection(self, collection: str) -> Dict:
        """Load collection from file"""
        file_path = self._get_file_path(collection)
        
        if collection in self._cache:
            logger.debug(f"Loading {collection} from cache")
            return self._cache[collection]
        
        try:
            if file_path.exists():
                logger.debug(f"Loading {collection} from file")
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                self._cache[collection] = data
                return data
            else:
                logger.debug(f"Creating new collection: {collection}")
                self._cache[collection] = {}
                return {}
        except Exception as e:
            logger.error(f"Error loading collection {collection}: {e}")
            return {}
    
    async def _save_collection(self, collection: str, data: Dict):
        """Save collection to file"""
        file_path = self._get_file_path(collection)
        try:
            logger.debug(f"Saving {collection} to file")
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self._cache[collection] = data
        except Exception as e:
            logger.error(f"Error saving collection {collection}: {e}")
            raise
    
    async def insert(self, collection: str, document: Dict) -> str:
        """Insert document into collection"""
        async with self._get_lock(collection):
            logger.debug(f"Inserting document into {collection}")
            data = await self._load_collection(collection)
            
            doc_id = document.get('id', str(uuid.uuid4()))
            document['id'] = doc_id
            data[doc_id] = document
            
            await self._save_collection(collection, data)
            logger.info(f"Inserted document {doc_id} into {collection}")
            return doc_id
    
    async def find_by_id(self, collection: str, doc_id: str) -> Optional[Dict]:
        """Find document by ID"""
        async with self._get_lock(collection):
            logger.debug(f"Finding document {doc_id} in {collection}")
            data = await self._load_collection(collection)
            return data.get(doc_id)
    
    async def find_all(self, collection: str) -> List[Dict]:
        """Find all documents in collection"""
        async with self._get_lock(collection):
            logger.debug(f"Finding all documents in {collection}")
            data = await self._load_collection(collection)
            return list(data.values())
    
    async def find_by_field(self, collection: str, field: str, value: Any) -> List[Dict]:
        """Find documents by field value"""
        async with self._get_lock(collection):
            logger.debug(f"Finding documents in {collection} where {field}={value}")
            data = await self._load_collection(collection)
            results = []
            for doc in data.values():
                if doc.get(field) == value:
                    results.append(doc)
            return results
    
    async def update(self, collection: str, doc_id: str, updates: Dict):
        """Update document"""
        async with self._get_lock(collection):
            logger.debug(f"Updating document {doc_id} in {collection}")
            data = await self._load_collection(collection)
            
            if doc_id in data:
                data[doc_id].update(updates)
                await self._save_collection(collection, data)
                logger.info(f"Updated document {doc_id} in {collection}")
                return True
            return False
    
    async def delete(self, collection: str, doc_id: str):
        """Delete document"""
        async with self._get_lock(collection):
            logger.debug(f"Deleting document {doc_id} from {collection}")
            data = await self._load_collection(collection)
            
            if doc_id in data:
                del data[doc_id]
                await self._save_collection(collection, data)
                logger.info(f"Deleted document {doc_id} from {collection}")
                return True
            return False
    
    async def search(self, collection: str, query: str) -> List[Dict]:
        """Search documents by text query"""
        async with self._get_lock(collection):
            logger.debug(f"Searching {collection} for query: {query}")
            data = await self._load_collection(collection)
            results = []
            query_lower = query.lower()
            
            for doc in data.values():
                # Search in all string fields
                for value in doc.values():
                    if isinstance(value, str) and query_lower in value.lower():
                        results.append(doc)
                        break
                    elif isinstance(value, list):
                        # Search in list items (like tags)
                        for item in value:
                            if isinstance(item, str) and query_lower in item.lower():
                                results.append(doc)
                                break
            
            return results

# =============================================================================
# RATE LIMITING
# =============================================================================

class RateLimiter:
    """Rate limiter to prevent abuse"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}
        logger.info(f"Initialized RateLimiter: {max_requests} requests per {window_seconds}s")
    
    async def is_allowed(self, client_ip: str) -> bool:
        """Check if request is allowed for client IP"""
        now = datetime.datetime.now(datetime.timezone.utc)
        
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        # Clean old requests
        cutoff = now - datetime.timedelta(seconds=self.window_seconds)
        self.requests[client_ip] = [
            req_time for req_time in self.requests[client_ip] 
            if req_time > cutoff
        ]
        
        # Check if under limit
        if len(self.requests[client_ip]) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return False
        
        # Add current request
        self.requests[client_ip].append(now)
        return True

# =============================================================================
# WEBSOCKET MANAGER FOR LIVE UPDATES
# =============================================================================

class WebSocketManager:
    """Manage WebSocket connections for live updates"""
    
    def __init__(self):
        self.connections: Set[web.WebSocketResponse] = set()
        logger.info("Initialized WebSocketManager")
    
    def add_connection(self, ws: web.WebSocketResponse):
        """Add WebSocket connection"""
        self.connections.add(ws)
        logger.debug(f"Added WebSocket connection. Total: {len(self.connections)}")
    
    def remove_connection(self, ws: web.WebSocketResponse):
        """Remove WebSocket connection"""
        self.connections.discard(ws)
        logger.debug(f"Removed WebSocket connection. Total: {len(self.connections)}")
    
    async def broadcast(self, message: Dict):
        """Broadcast message to all connections"""
        if not self.connections:
            return
        
        logger.debug(f"Broadcasting to {len(self.connections)} connections")
        disconnected = set()
        
        for ws in self.connections.copy():
            try:
                if ws.closed:
                    disconnected.add(ws)
                else:
                    await ws.send_str(json.dumps(message))
            except Exception as e:
                logger.error(f"Error sending to WebSocket: {e}")
                disconnected.add(ws)
        
        # Remove disconnected connections
        for ws in disconnected:
            self.remove_connection(ws)

# =============================================================================
# FILE UPLOAD HANDLER
# =============================================================================

class FileUploadHandler:
    """Handle file uploads with security checks"""
    
    def __init__(self, upload_dir: str = "uploads"):
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(exist_ok=True)
        self.max_file_size = 50 * 1024 * 1024  # 50MB
        logger.info(f"Initialized FileUploadHandler at {self.upload_dir}")
    
    def _get_safe_filename(self, filename: str) -> str:
        """Generate safe filename"""
        # Remove path traversal attempts
        filename = os.path.basename(filename)
        # Remove dangerous characters
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
        # Add timestamp to avoid conflicts
        name, ext = os.path.splitext(filename)
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d_%H%M%S')
        return f"{name}_{timestamp}{ext}"
    
    async def save_file(self, file_data: bytes, filename: str, user_id: str) -> Dict:
        """Save uploaded file"""
        try:
            logger.debug(f"Saving file: {filename} for user {user_id}")
            
            if len(file_data) > self.max_file_size:
                raise ValueError(f"File too large: {len(file_data)} bytes")
            
            safe_filename = self._get_safe_filename(filename)
            file_path = self.upload_dir / user_id
            file_path.mkdir(exist_ok=True)
            full_path = file_path / safe_filename
            
            with open(full_path, 'wb') as f:
                f.write(file_data)
            
            # Get file info
            file_info = {
                'id': str(uuid.uuid4()),
                'filename': safe_filename,
                'original_filename': filename,
                'path': str(full_path),
                'size': len(file_data),
                'mimetype': mimetypes.guess_type(filename)[0] or 'application/octet-stream',
                'uploaded_by': user_id,
                'uploaded_at': DateTimeUtils.now_iso()
            }
            
            logger.info(f"Saved file {safe_filename} ({len(file_data)} bytes)")
            return file_info
            
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            raise

# =============================================================================
# MIDDLEWARES
# =============================================================================

@middleware
async def cors_middleware(request, handler):
    """CORS middleware"""
    logger.debug(f"CORS middleware: {request.method} {request.path}")
    
    if request.method == 'OPTIONS':
        response = web.Response()
    else:
        try:
            response = await handler(request)
        except Exception as e:
            logger.error(f"Handler error: {e}")
            response = web.json_response({'error': 'Internal server error'}, status=500)
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '86400'
    
    return response

@middleware
async def rate_limit_middleware(request, handler):
    """Rate limiting middleware"""
    rate_limiter = request.app['rate_limiter']
    client_ip = request.remote or '127.0.0.1'
    
    logger.debug(f"Rate limit check for {client_ip}")
    
    if not await rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return web.json_response({'error': 'Rate limit exceeded'}, status=429)
    
    return await handler(request)

@middleware
async def auth_middleware(request, handler):
    """Authentication middleware"""
    # Skip auth for public endpoints
    public_endpoints = ['/auth/login', '/auth/register', '/health', '/ws']
    if request.path in public_endpoints or request.method == 'OPTIONS':
        return await handler(request)
    
    # Check for auth token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        logger.debug(f"No auth token for {request.path}")
        return web.json_response({'error': 'Authentication required'}, status=401)
    
    token = auth_header[7:]  # Remove 'Bearer '
    db = request.app['db']
    
    # Find user by token
    users = await db.find_by_field('users', 'token', token)
    if not users:
        logger.debug(f"Invalid token: {token}")
        return web.json_response({'error': 'Invalid token'}, status=401)
    
    user = users[0]
    if not user.get('is_active', True):
        logger.debug(f"Inactive user: {user['id']}")
        return web.json_response({'error': 'Account inactive'}, status=401)
    
    # Add user to request
    request['user'] = user
    logger.debug(f"Authenticated user: {user['username']}")
    
    return await handler(request)

# =============================================================================
# API HANDLERS
# =============================================================================

class AuthHandler:
    """Authentication handlers"""
    
    @staticmethod
    async def register(request):
        """Register new user"""
        try:
            data = await request.json()
            logger.debug(f"Register attempt: {data.get('username')}")
            
            # Validate input
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            
            if not ValidationUtils.validate_username(username):
                return web.json_response({'error': 'Invalid username format'}, status=400)
            
            if not ValidationUtils.validate_email(email):
                return web.json_response({'error': 'Invalid email format'}, status=400)
            
            if len(password) < 6:
                return web.json_response({'error': 'Password must be at least 6 characters'}, status=400)
            
            db = request.app['db']
            
            # Check if username/email exists
            existing_users = await db.find_by_field('users', 'username', username)
            if existing_users:
                return web.json_response({'error': 'Username already exists'}, status=400)
            
            existing_emails = await db.find_by_field('users', 'email', email)
            if existing_emails:
                return web.json_response({'error': 'Email already exists'}, status=400)
            
            # Create user
            salt = SecurityUtils.generate_salt()
            password_hash = SecurityUtils.hash_password(password, salt)
            token = SecurityUtils.generate_token()
            
            user = User(
                id=str(uuid.uuid4()),
                username=username,
                email=email,
                password_hash=password_hash,
                salt=salt,
                created_at=DateTimeUtils.now_iso()
            )
            
            user_dict = asdict(user)
            user_dict['token'] = token
            
            await db.insert('users', user_dict)
            
            logger.info(f"User registered: {username}")
            return web.json_response({
                'message': 'User registered successfully',
                'token': token,
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
            })
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return web.json_response({'error': 'Registration failed'}, status=500)
    
    @staticmethod
    async def login(request):
        """Login user"""
        try:
            data = await request.json()
            logger.debug(f"Login attempt: {data.get('username')}")
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return web.json_response({'error': 'Username and password required'}, status=400)
            
            db = request.app['db']
            
            # Find user
            users = await db.find_by_field('users', 'username', username)
            if not users:
                return web.json_response({'error': 'Invalid credentials'}, status=401)
            
            user = users[0]
            
            # Verify password
            if not SecurityUtils.verify_password(password, user['salt'], user['password_hash']):
                return web.json_response({'error': 'Invalid credentials'}, status=401)
            
            if not user.get('is_active', True):
                return web.json_response({'error': 'Account inactive'}, status=401)
            
            # Generate new token
            token = SecurityUtils.generate_token()
            await db.update('users', user['id'], {'token': token})
            
            logger.info(f"User logged in: {username}")
            return web.json_response({
                'message': 'Login successful',
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'role': user['role']
                }
            })
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return web.json_response({'error': 'Login failed'}, status=500)

class UserHandler:
    """User management handlers"""
    
    @staticmethod
    async def get_profile(request):
        """Get user profile"""
        try:
            user_id = request.match_info.get('user_id')
            if not user_id:
                user_id = request['user']['id']  # Current user
            
            db = request.app['db']
            user = await db.find_by_id('users', user_id)
            
            if not user:
                return web.json_response({'error': 'User not found'}, status=404)
            
            # Remove sensitive data
            profile = {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role'],
                'created_at': user['created_at'],
                'description': user.get('description', ''),
                'mood': user.get('mood', ''),
                'avatar_url': user.get('avatar_url', ''),
                'background_url': user.get('background_url', ''),
                'is_active': user.get('is_active', True)
            }
            
            logger.debug(f"Profile retrieved: {user['username']}")
            return web.json_response({'user': profile})
            
        except Exception as e:
            logger.error(f"Get profile error: {e}")
            return web.json_response({'error': 'Failed to get profile'}, status=500)
    
    @staticmethod
    async def update_profile(request):
        """Update user profile"""
        try:
            data = await request.json()
            user = request['user']
            db = request.app['db']
            
            # Allowed fields to update
            allowed_fields = ['description', 'mood', 'avatar_url', 'background_url']
            updates = {}
            
            for field in allowed_fields:
                if field in data:
                    updates[field] = ValidationUtils.sanitize_input(str(data[field]))
            
            if updates:
                await db.update('users', user['id'], updates)
                logger.info(f"Profile updated: {user['username']}")
                return web.json_response({'message': 'Profile updated successfully'})
            else:
                return web.json_response({'error': 'No valid fields to update'}, status=400)
                
        except Exception as e:
            logger.error(f"Update profile error: {e}")
            return web.json_response({'error': 'Failed to update profile'}, status=500)

class PostHandler:
    """Post management handlers"""
    
    @staticmethod
    async def create_post(request):
        """Create new post"""
        try:
            data = await request.json()
            user = request['user']
            
            title = data.get('title', '').strip()
            content = data.get('content', '').strip()
            category = data.get('category', 'general').strip()
            tags = data.get('tags', [])
            
            if not title or not content:
                return web.json_response({'error': 'Title and content required'}, status=400)
            
            # Sanitize input
            title = ValidationUtils.sanitize_input(title)
            content = ValidationUtils.sanitize_input(content)
            category = ValidationUtils.sanitize_input(category)
            
            # Validate tags
            if not isinstance(tags, list):
                tags = []
            tags = [ValidationUtils.sanitize_input(tag) for tag in tags if tag]
            
            post = Post(
                id=str(uuid.uuid4()),
                author_id=user['id'],
                title=title,
                content=content,
                category=category,
                tags=tags,
                created_at=DateTimeUtils.now_iso(),
                updated_at=DateTimeUtils.now_iso()
            )
            
            db = request.app['db']
            await db.insert('posts', asdict(post))
            
            # Broadcast new post to WebSocket connections
            ws_manager = request.app['ws_manager']
            await ws_manager.broadcast({
                'type': 'new_post',
                'post': asdict(post),
                'author': user['username']
            })
            
            logger.info(f"Post created: {post.id} by {user['username']}")
            return web.json_response({
                'message': 'Post created successfully',
                'post': asdict(post)
            }, status=201)
            
        except Exception as e:
            logger.error(f"Create post error: {e}")
            return web.json_response({'error': 'Failed to create post'}, status=500)
    
    @staticmethod
    async def get_posts(request):
        """Get posts with pagination"""
        try:
            # Pagination parameters
            page = int(request.query.get('page', 1))
            limit = min(int(request.query.get('limit', 10)), 50)  # Max 50 per page
            offset = (page - 1) * limit
            
            # Filter parameters
            category = request.query.get('category')
            author_id = request.query.get('author_id')
            
            db = request.app['db']
            all_posts = await db.find_all('posts')
            
            # Filter posts
            filtered_posts = []
            for post in all_posts:
                if not post.get('is_published', True):
                    continue
                if category and post.get('category') != category:
                    continue
                if author_id and post.get('author_id') != author_id:
                    continue
                filtered_posts.append(post)
            
            # Sort by created_at (newest first)
            filtered_posts.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            # Paginate
            paginated_posts = filtered_posts[offset:offset + limit]
            
            # Add author info
            for post in paginated_posts:
                author = await db.find_by_id('users', post['author_id'])
                post['author'] = author['username'] if author else 'Unknown'
            
            logger.debug(f"Retrieved {len(paginated_posts)} posts (page {page})")
            return web.json_response({
                'posts': paginated_posts,
                'pagination': {
                    'page': page,
                    'limit': limit,
                    'total': len(filtered_posts),
                    'pages': (len(filtered_posts) + limit - 1) // limit
                }
            })
            
        except Exception as e:
            logger.error(f"Get posts error: {e}")
            return web.json_response({'error': 'Failed to get posts'}, status=500)
    
    @staticmethod
    async def get_post(request):
        """Get single post with comments"""
        try:
            post_id = request.match_info['post_id']
            db = request.app['db']
            
            post = await db.find_by_id('posts', post_id)
            if not post:
                return web.json_response({'error': 'Post not found'}, status=404)
            
            # Increment view count
            await db.update('posts', post_id, {
                'view_count': post.get('view_count', 0) + 1
            })
            
            # Get author info
            author = await db.find_by_id('users', post['author_id'])
            post['author'] = author['username'] if author else 'Unknown'
            
            # Get comments
            comments = await db.find_by_field('comments', 'post_id', post_id)
            
            # Add author info to comments and organize hierarchically
            comment_authors = {}
            for comment in comments:
                if comment['author_id'] not in comment_authors:
                    author = await db.find_by_id('users', comment['author_id'])
                    comment_authors[comment['author_id']] = author['username'] if author else 'Unknown'
                comment['author'] = comment_authors[comment['author_id']]
            
            # Organize comments hierarchically
            top_level_comments = []
            replies = {}
            
            for comment in comments:
                if comment.get('is_deleted'):
                    continue
                if not comment.get('parent_id'):
                    top_level_comments.append(comment)
                else:
                    parent_id = comment['parent_id']
                    if parent_id not in replies:
                        replies[parent_id] = []
                    replies[parent_id].append(comment)
            
            # Add replies to comments
            def add_replies(comment):
                comment_id = comment['id']
                comment['replies'] = replies.get(comment_id, [])
                for reply in comment['replies']:
                    add_replies(reply)
            
            for comment in top_level_comments:
                add_replies(comment)
            
            post['comments'] = top_level_comments
            
            logger.debug(f"Retrieved post: {post_id}")
            return web.json_response({'post': post})
            
        except Exception as e:
            logger.error(f"Get post error: {e}")
            return web.json_response({'error': 'Failed to get post'}, status=500)
    
    @staticmethod
    async def search_posts(request):
        """Search posts and comments"""
        try:
            query = request.query.get('q', '').strip()
            if not query:
                return web.json_response({'error': 'Search query required'}, status=400)
            
            db = request.app['db']
            
            # Search posts
            post_results = await db.search('posts', query)
            
            # Search comments
            comment_results = await db.search('comments', query)
            
            # Get unique posts from comment results
            post_ids_from_comments = set()
            for comment in comment_results:
                if not comment.get('is_deleted'):
                    post_ids_from_comments.add(comment['post_id'])
            
            # Add posts that have matching comments
            for post_id in post_ids_from_comments:
                post = await db.find_by_id('posts', post_id)
                if post and post not in post_results:
                    post_results.append(post)
            
            # Filter published posts only
            results = [post for post in post_results if post.get('is_published', True)]
            
            # Add author info
            for post in results:
                author = await db.find_by_id('users', post['author_id'])
                post['author'] = author['username'] if author else 'Unknown'
            
            # Sort by relevance (created_at for now)
            results.sort(key=lambda x: x.get('created_at', ''), reverse=True)
            
            logger.debug(f"Search '{query}' returned {len(results)} results")
            return web.json_response({
                'query': query,
                'results': results,
                'count': len(results)
            })
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return web.json_response({'error': 'Search failed'}, status=500)

class CommentHandler:
    """Comment management handlers"""
    
    @staticmethod
    async def create_comment(request):
        """Create new comment"""
        try:
            data = await request.json()
            user = request['user']
            
            post_id = data.get('post_id', '').strip()
            content = data.get('content', '').strip()
            parent_id = data.get('parent_id')
            
            if not post_id or not content:
                return web.json_response({'error': 'Post ID and content required'}, status=400)
            
            db = request.app['db']
            
            # Verify post exists
            post = await db.find_by_id('posts', post_id)
            if not post:
                return web.json_response({'error': 'Post not found'}, status=404)
            
            # Verify parent comment exists (if specified)
            if parent_id:
                parent_comment = await db.find_by_id('comments', parent_id)
                if not parent_comment:
                    return web.json_response({'error': 'Parent comment not found'}, status=404)
            
            # Sanitize content and extract mentions
            content = ValidationUtils.sanitize_input(content)
            mentions = ValidationUtils.extract_mentions(content)
            
            comment = Comment(
                id=str(uuid.uuid4()),
                post_id=post_id,
                author_id=user['id'],
                content=content,
                parent_id=parent_id,
                mentions=mentions,
                created_at=DateTimeUtils.now_iso()
            )
            
            await db.insert('comments', asdict(comment))
            
            # Broadcast new comment to WebSocket connections
            ws_manager = request.app['ws_manager']
            await ws_manager.broadcast({
                'type': 'new_comment',
                'comment': asdict(comment),
                'author': user['username'],
                'post_id': post_id
            })
            
            logger.info(f"Comment created: {comment.id} by {user['username']}")
            return web.json_response({
                'message': 'Comment created successfully',
                'comment': asdict(comment)
            }, status=201)
            
        except Exception as e:
            logger.error(f"Create comment error: {e}")
            return web.json_response({'error': 'Failed to create comment'}, status=500)

class FileHandler:
    """File management handlers"""
    
    @staticmethod
    async def upload_file(request):
        """Upload file"""
        try:
            user = request['user']
            
            if not request.content_type or not request.content_type.startswith('multipart/'):
                return web.json_response({'error': 'Multipart form data required'}, status=400)
            
            reader = await request.multipart()
            field = await reader.next()
            
            if not field or field.name != 'file':
                return web.json_response({'error': 'No file provided'}, status=400)
            
            filename = field.filename
            if not filename:
                return web.json_response({'error': 'No filename provided'}, status=400)
            
            # Read file data
            file_data = await field.read()
            
            # Save file
            file_handler = request.app['file_handler']
            file_info = await file_handler.save_file(file_data, filename, user['id'])
            
            # Save file info to database
            db = request.app['db']
            await db.insert('files', file_info)
            
            logger.info(f"File uploaded: {filename} by {user['username']}")
            return web.json_response({
                'message': 'File uploaded successfully',
                'file': file_info
            }, status=201)
            
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return web.json_response({'error': f'Upload failed: {str(e)}'}, status=500)
    
    @staticmethod
    async def get_file(request):
        """Serve uploaded file"""
        try:
            file_id = request.match_info['file_id']
            db = request.app['db']
            
            file_info = await db.find_by_id('files', file_id)
            if not file_info:
                return web.json_response({'error': 'File not found'}, status=404)
            
            file_path = Path(file_info['path'])
            if not file_path.exists():
                return web.json_response({'error': 'File not found on disk'}, status=404)
            
            # Return file
            return web.FileResponse(
                file_path,
                headers={
                    'Content-Type': file_info['mimetype'],
                    'Content-Disposition': f'inline; filename="{file_info["filename"]}"'
                }
            )
            
        except Exception as e:
            logger.error(f"Get file error: {e}")
            return web.json_response({'error': 'Failed to get file'}, status=500)

# =============================================================================
# WEBSOCKET HANDLER
# =============================================================================

async def websocket_handler(request):
    """WebSocket handler for live updates"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    ws_manager = request.app['ws_manager']
    ws_manager.add_connection(ws)
    
    logger.info("WebSocket connection established")
    
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    logger.debug(f"WebSocket message: {data}")
                    
                    # Handle different message types
                    if data.get('type') == 'ping':
                        await ws.send_str(json.dumps({'type': 'pong'}))
                        logger.debug("Sent pong response")
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in WebSocket message: {e}")
                    await ws.send_str(json.dumps({'type': 'error', 'message': 'Invalid JSON'}))
                    
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
                break
            elif msg.type == WSMsgType.CLOSE:
                logger.info("WebSocket closed by client")
                break
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_manager.remove_connection(ws)
        logger.info("WebSocket connection closed")
    
    return ws

# =============================================================================
# HEALTH CHECK
# =============================================================================

async def health_check(request):
    """Health check endpoint"""
    return web.json_response({
        'status': 'healthy',
        'timestamp': DateTimeUtils.now_iso(),
        'version': '1.0.0'
    })

# =============================================================================
# APPLICATION SETUP
# =============================================================================

async def init_default_data(app):
    """Initialize default data"""
    logger.info("Initializing default data")
    db = app['db']
    
    # Create admin user if no users exist
    users = await db.find_all('users')
    if not users:
        logger.info("Creating default admin user")
        salt = SecurityUtils.generate_salt()
        password_hash = SecurityUtils.hash_password('admin123', salt)
        token = SecurityUtils.generate_token()
        
        admin_user = User(
            id=str(uuid.uuid4()),
            username='admin',
            email='admin@example.com',
            password_hash=password_hash,
            salt=salt,
            role='admin',
            created_at=DateTimeUtils.now_iso(),
            description='System Administrator'
        )
        
        user_dict = asdict(admin_user)
        user_dict['token'] = token
        
        await db.insert('users', user_dict)
        logger.info("Default admin user created (username: admin, password: admin123)")

def create_app():
    """Create and configure the application"""
    logger.info("Creating AIOHTTP application")
    
    # Create application
    app = web.Application(middlewares=[
        cors_middleware,
        rate_limit_middleware,
        auth_middleware
    ])
    
    # Initialize components
    app['db'] = AsyncJSONDatabase()
    app['rate_limiter'] = RateLimiter()
    app['ws_manager'] = WebSocketManager()
    app['file_handler'] = FileUploadHandler()
    
    # Add routes
    app.router.add_get('/health', health_check)
    app.router.add_get('/ws', websocket_handler)
    
    # Auth routes
    app.router.add_post('/auth/register', AuthHandler.register)
    app.router.add_post('/auth/login', AuthHandler.login)
    
    # User routes
    app.router.add_get('/users/profile', UserHandler.get_profile)
    app.router.add_get('/users/{user_id}/profile', UserHandler.get_profile)
    app.router.add_put('/users/profile', UserHandler.update_profile)
    
    # Post routes
    app.router.add_post('/posts', PostHandler.create_post)
    app.router.add_get('/posts', PostHandler.get_posts)
    app.router.add_get('/posts/{post_id}', PostHandler.get_post)
    app.router.add_get('/search', PostHandler.search_posts)
    
    # Comment routes
    app.router.add_post('/comments', CommentHandler.create_comment)
    
    # File routes
    app.router.add_post('/files', FileHandler.upload_file)
    app.router.add_get('/files/{file_id}', FileHandler.get_file)
    
    # Static files
    static_dir = Path('static')
    if not static_dir.exists():
        static_dir.mkdir(exist_ok=True)
        logger.info("Created static directory")
    
    app.router.add_static('/', static_dir, name='static')
    
    logger.info("Application created successfully")
    return app

async def init_app():
    """Initialize application with default data"""
    app = create_app()
    await init_default_data(app)
    return app

def main():
    """Main entry point"""
    logger.info("Starting AIOHTTP Blogging API")
    
    # SSL configuration
    ssl_context = None
    port = 8080
    
    cert_file = Path('cert.pem')
    key_file = Path('key.pem')
    
    if cert_file.exists() and key_file.exists():
        logger.info("SSL certificates found, enabling HTTPS")
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_file, key_file)
        port = 443
    else:
        logger.info("SSL certificates not found, using HTTP")
    
    # Create and run application
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        app = loop.run_until_complete(init_app())
        
        logger.info(f"Starting server on port {port}")
        logger.info("🚀 API is ready!")
        logger.info("📝 Default admin account: username=admin, password=admin123")
        logger.info("🌐 WebSocket endpoint: ws://localhost:8080/ws")
        
        web.run_app(
            app,
            host='0.0.0.0',
            port=port,
            ssl_context=ssl_context,
            access_log=logger
        )
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        loop.close()

if __name__ == '__main__':
    main()
