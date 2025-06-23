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
import uuid
import mimetypes
from pathlib import Path
import shutil
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DB_PATH = "auth.db"
UPLOAD_DIR = Path("uploads")

# Ensure upload directory exists
UPLOAD_DIR.mkdir(exist_ok=True)

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
        async with aiosqlite.connect(DB_PATH) as db:
            # Core tables
            await db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT, password_hash TEXT, created_at REAL, last_login REAL)")
            await db.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at REAL, expires_at REAL, ip_address TEXT, user_agent TEXT, FOREIGN KEY (user_id) REFERENCES users (id))")
            
            # ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
            await db.execute("""CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                user_id INTEGER NOT NULL, 
                title TEXT NOT NULL, 
                content TEXT NOT NULL, 
                created_at REAL NOT NULL, 
                updated_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )""")
            
            # Create indices for performance
            await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at)")
            # ===== END ISOLATED SECTION: POSTS =====

            # ===== ISOLATED SECTION: COMMENTS SYSTEM =====
            await db.execute("""CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                parent_comment_id INTEGER,
                content TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (parent_comment_id) REFERENCES comments (id) ON DELETE CASCADE
            )""")
            
            # Create indices for comments
            await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_post_id ON comments(post_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_user_id ON comments(user_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_comment_id)")
            # ===== END ISOLATED SECTION: COMMENTS =====

            # ===== ISOLATED SECTION: FILE UPLOAD SYSTEM =====
            await db.execute("""CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                original_name TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_path TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )""")
            
            # Create index for files
            await db.execute("CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id)")
            # ===== END ISOLATED SECTION: FILES =====

            # ===== ISOLATED SECTION: TAGS SYSTEM =====
            await db.execute("""CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL
            )""")
            await db.execute("""CREATE TABLE IF NOT EXISTS post_tags (
                post_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                PRIMARY KEY (post_id, tag_id),
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
            )""")
            
            # Create indices for tags
            await db.execute("CREATE INDEX IF NOT EXISTS idx_post_tags_post_id ON post_tags(post_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_post_tags_tag_id ON post_tags(tag_id)")
            # ===== END ISOLATED SECTION: TAGS =====

            # ===== ISOLATED SECTION: EDIT PROPOSALS SYSTEM =====
            await db.execute("""CREATE TABLE IF NOT EXISTS post_edit_proposals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                proposer_name TEXT,
                proposer_email TEXT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                created_at REAL NOT NULL,
                reviewed_at REAL,
                reviewed_by INTEGER,
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (reviewed_by) REFERENCES users (id)
            )""")
            
            # Create index for proposals
            await db.execute("CREATE INDEX IF NOT EXISTS idx_proposals_post_id ON post_edit_proposals(post_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_proposals_status ON post_edit_proposals(status)")
            # ===== END ISOLATED SECTION: EDIT PROPOSALS =====

            # ===== ISOLATED SECTION: SEARCH INDICES =====
            # Create FTS virtual table for full-text search
            try:
                await db.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
                    title, content, username, tags,
                    content='',
                    tokenize='porter'
                )""")
                logger.info("FTS5 table created successfully")
            except Exception as e:
                logger.error(f"Failed to create FTS5 table: {e}")
                
            # Create triggers to keep FTS table in sync
            await db.execute("""
                CREATE TRIGGER IF NOT EXISTS posts_fts_insert AFTER INSERT ON posts BEGIN
                    INSERT INTO posts_fts(rowid, title, content, username, tags) 
                    SELECT NEW.id, NEW.title, NEW.content, 
                           (SELECT username FROM users WHERE id = NEW.user_id),
                           (SELECT GROUP_CONCAT(t.name, ' ') FROM tags t 
                            JOIN post_tags pt ON t.id = pt.tag_id 
                            WHERE pt.post_id = NEW.id);
                END
            """)
            
            await db.execute("""
                CREATE TRIGGER IF NOT EXISTS posts_fts_update AFTER UPDATE ON posts BEGIN
                    UPDATE posts_fts SET 
                        title = NEW.title, 
                        content = NEW.content, 
                        username = (SELECT username FROM users WHERE id = NEW.user_id),
                        tags = (SELECT GROUP_CONCAT(t.name, ' ') FROM tags t 
                                JOIN post_tags pt ON t.id = pt.tag_id 
                                WHERE pt.post_id = NEW.id)
                    WHERE rowid = NEW.id;
                END
            """)
            
            await db.execute("""
                CREATE TRIGGER IF NOT EXISTS posts_fts_delete AFTER DELETE ON posts BEGIN
                    DELETE FROM posts_fts WHERE rowid = OLD.id;
                END
            """)
            
            # Trigger for tag updates
            await db.execute("""
                CREATE TRIGGER IF NOT EXISTS posts_fts_tag_update AFTER INSERT ON post_tags BEGIN
                    UPDATE posts_fts SET 
                        tags = (SELECT GROUP_CONCAT(t.name, ' ') FROM tags t 
                                JOIN post_tags pt ON t.id = pt.tag_id 
                                WHERE pt.post_id = NEW.post_id)
                    WHERE rowid = NEW.post_id;
                END
            """)
            # ===== END ISOLATED SECTION: SEARCH =====

            # Create session cleanup index
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            
            await db.commit()
            logger.info("Database initialization completed")
    
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
        result = await DB._execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
        logger.info(f"Cleaned up expired sessions")

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
        
        async with aiosqlite.connect(DB_PATH) as db:
            # First verify the post belongs to the user
            post_result = await db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
            post_row = await post_result.fetchone()
            if not post_row or post_row[0] != user_id:
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
            await db.execute(query, params)
            await db.commit()
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

    @staticmethod
    async def get_posts_stats():
        """Get post counts by year/month for sidebar"""
        return await DB._execute("""
            SELECT 
                strftime('%Y', datetime(created_at, 'unixepoch')) as year,
                strftime('%m', datetime(created_at, 'unixepoch')) as month,
                COUNT(*) as count
            FROM posts 
            GROUP BY year, month 
            ORDER BY year DESC, month DESC
        """, fetch='all')
    # ===== END ISOLATED SECTION: POSTS =====

    # ===== ISOLATED SECTION: COMMENTS SYSTEM =====
    @staticmethod
    async def create_comment(post_id, user_id, content, parent_comment_id=None):
        """Create a new comment"""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "INSERT INTO comments (post_id, user_id, parent_comment_id, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (post_id, user_id, parent_comment_id, content, time.time(), time.time())
            )
            await db.commit()
            return cursor.lastrowid

    @staticmethod
    async def get_comments_by_post(post_id):
        """Get all comments for a post in nested structure"""
        return await DB._execute("""
            SELECT c.*, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.post_id = ? 
            ORDER BY c.created_at ASC
        """, (post_id,), 'all')

    @staticmethod
    async def get_comment_by_id(comment_id):
        """Get a specific comment by ID"""
        return await DB._execute("""
            SELECT c.*, u.username 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.id = ?
        """, (comment_id,), 'one')

    @staticmethod
    async def update_comment(comment_id, user_id, content):
        """Update a comment - only the owner can update"""
        async with aiosqlite.connect(DB_PATH) as db:
            result = await db.execute(
                "UPDATE comments SET content = ?, updated_at = ? WHERE id = ? AND user_id = ?",
                (content, time.time(), comment_id, user_id)
            )
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def delete_comment(comment_id, user_id):
        """Delete a comment - only the owner can delete"""
        async with aiosqlite.connect(DB_PATH) as db:
            result = await db.execute("DELETE FROM comments WHERE id = ? AND user_id = ?", (comment_id, user_id))
            await db.commit()
            return result.rowcount > 0
    # ===== END ISOLATED SECTION: COMMENTS =====

    # ===== ISOLATED SECTION: FILE UPLOAD SYSTEM =====
    @staticmethod
    async def create_file(file_id, user_id, original_name, filename, file_path, mime_type, file_size):
        """Create a file record"""
        await DB._execute(
            "INSERT INTO files (id, user_id, original_name, filename, file_path, mime_type, file_size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (file_id, user_id, original_name, filename, file_path, mime_type, file_size, time.time())
        )
        return file_id

    @staticmethod
    async def get_file_by_id(file_id):
        """Get file metadata by ID"""
        return await DB._execute("SELECT * FROM files WHERE id = ?", (file_id,), 'one')

    @staticmethod
    async def delete_file(file_id, user_id):
        """Delete a file - only the owner can delete"""
        async with aiosqlite.connect(DB_PATH) as db:
            result = await db.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, user_id))
            await db.commit()
            return result.rowcount > 0

    @staticmethod
    async def get_files_by_user(user_id, limit=50, offset=0):
        """Get files uploaded by user"""
        return await DB._execute("""
            SELECT f.*, u.username 
            FROM files f 
            JOIN users u ON f.user_id = u.id 
            WHERE f.user_id = ? 
            ORDER BY f.created_at DESC 
            LIMIT ? OFFSET ?
        """, (user_id, limit, offset), 'all')
    # ===== END ISOLATED SECTION: FILES =====

    # ===== ISOLATED SECTION: TAGS SYSTEM =====
    @staticmethod
    async def create_tag(name):
        """Create a new tag"""
        async with aiosqlite.connect(DB_PATH) as db:
            try:
                cursor = await db.execute("INSERT INTO tags (name, created_at) VALUES (?, ?)", (name, time.time()))
                await db.commit()
                return cursor.lastrowid
            except aiosqlite.IntegrityError:
                # Tag already exists, get its ID
                result = await db.execute("SELECT id FROM tags WHERE name = ?", (name,))
                row = await result.fetchone()
                return row[0] if row else None

    @staticmethod
    async def get_all_tags():
        """Get all tags"""
        return await DB._execute("SELECT * FROM tags ORDER BY name", fetch='all')

    @staticmethod
    async def get_tags_by_post(post_id):
        """Get tags for a specific post"""
        return await DB._execute("""
            SELECT t.* FROM tags t 
            JOIN post_tags pt ON t.id = pt.tag_id 
            WHERE pt.post_id = ? 
            ORDER BY t.name
        """, (post_id,), 'all')

    @staticmethod
    async def update_post_tags(post_id, tag_names):
        """Update all tags for a post"""
        async with aiosqlite.connect(DB_PATH) as db:
            # Remove existing tags
            await db.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
            
            # Add new tags
            for tag_name in tag_names:
                tag_name = tag_name.strip().lower()
                if tag_name:
                    # Create tag if doesn't exist (inline to avoid nested connections)
                    try:
                        cursor = await db.execute("INSERT INTO tags (name, created_at) VALUES (?, ?)", (tag_name, time.time()))
                        tag_id = cursor.lastrowid
                    except aiosqlite.IntegrityError:
                        # Tag already exists, get its ID
                        result = await db.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
                        row = await result.fetchone()
                        tag_id = row[0] if row else None
                    
                    if tag_id:
                        try:
                            await db.execute("INSERT INTO post_tags (post_id, tag_id) VALUES (?, ?)", (post_id, tag_id))
                        except aiosqlite.IntegrityError:
                            # Tag already associated with post, skip
                            pass
            await db.commit()
    # ===== END ISOLATED SECTION: TAGS =====

    # ===== ISOLATED SECTION: EDIT PROPOSALS SYSTEM =====
    @staticmethod
    async def create_edit_proposal(post_id, proposer_name, proposer_email, title, content, reason):
        """Create a new edit proposal"""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "INSERT INTO post_edit_proposals (post_id, proposer_name, proposer_email, title, content, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (post_id, proposer_name, proposer_email, title, content, reason, time.time())
            )
            await db.commit()
            return cursor.lastrowid

    @staticmethod
    async def get_proposals_by_post(post_id):
        """Get all proposals for a post"""
        return await DB._execute("""
            SELECT * FROM post_edit_proposals 
            WHERE post_id = ? 
            ORDER BY created_at DESC
        """, (post_id,), 'all')

    @staticmethod
    async def get_proposal_by_id(proposal_id):
        """Get a specific proposal by ID"""
        return await DB._execute("SELECT * FROM post_edit_proposals WHERE id = ?", (proposal_id,), 'one')

    @staticmethod
    async def approve_proposal(proposal_id, reviewer_id):
        """Approve a proposal and apply changes"""
        async with aiosqlite.connect(DB_PATH) as db:
            # Get proposal details
            proposal = await db.execute("SELECT * FROM post_edit_proposals WHERE id = ?", (proposal_id,))
            proposal = await proposal.fetchone()
            if not proposal or proposal[7] != 'pending':  # status column
                return False

            # Update the post
            await db.execute(
                "UPDATE posts SET title = ?, content = ?, updated_at = ? WHERE id = ?",
                (proposal[4], proposal[5], time.time(), proposal[1])  # title, content, post_id
            )
            
            # Mark proposal as approved
            await db.execute(
                "UPDATE post_edit_proposals SET status = 'approved', reviewed_at = ?, reviewed_by = ? WHERE id = ?",
                (time.time(), reviewer_id, proposal_id)
            )
            await db.commit()
            return True

    @staticmethod
    async def reject_proposal(proposal_id, reviewer_id):
        """Reject a proposal"""
        result = await DB._execute(
            "UPDATE post_edit_proposals SET status = 'rejected', reviewed_at = ?, reviewed_by = ? WHERE id = ? AND status = 'pending'",
            (time.time(), reviewer_id, proposal_id)
        )
        return True
    # ===== END ISOLATED SECTION: EDIT PROPOSALS =====

    # ===== ISOLATED SECTION: SEARCH FUNCTIONALITY =====
    @staticmethod
    async def search_posts(query, limit=50, offset=0):
        """Full-text search across posts"""
        try:
            return await DB._execute("""
                SELECT p.*, u.username, 
                       snippet(posts_fts, 1, '<mark>', '</mark>', '...', 32) as content_snippet,
                       bm25(posts_fts) as rank
                FROM posts_fts 
                JOIN posts p ON posts_fts.rowid = p.id 
                JOIN users u ON p.user_id = u.id 
                WHERE posts_fts MATCH ? 
                ORDER BY rank 
                LIMIT ? OFFSET ?
            """, (query, limit, offset), 'all')
        except Exception as e:
            logger.error(f"Search error: {e}")
            # Fallback to simple LIKE search
            return await DB._execute("""
                SELECT p.*, u.username, '' as content_snippet, 0 as rank
                FROM posts p 
                JOIN users u ON p.user_id = u.id 
                WHERE p.title LIKE ? OR p.content LIKE ?
                ORDER BY p.created_at DESC 
                LIMIT ? OFFSET ?
            """, (f'%{query}%', f'%{query}%', limit, offset), 'all')

    @staticmethod
    async def search_posts_count(query):
        """Get total count of search results"""
        try:
            result = await DB._execute(
                "SELECT COUNT(*) as count FROM posts_fts WHERE posts_fts MATCH ?",
                (query,), 'one'
            )
            return result['count'] if result else 0
        except Exception as e:
            logger.error(f"Search count error: {e}")
            # Fallback to simple LIKE search count
            result = await DB._execute(
                "SELECT COUNT(*) as count FROM posts WHERE title LIKE ? OR content LIKE ?",
                (f'%{query}%', f'%{query}%'), 'one'
            )
            return result['count'] if result else 0
    # ===== END ISOLATED SECTION: SEARCH =====

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

def validate_input(data, required_fields, max_lengths=None):
    """Validate input data"""
    errors = []
    
    for field in required_fields:
        if field not in data or not data[field] or not str(data[field]).strip():
            errors.append(f"{field} is required")
    
    if max_lengths:
        for field, max_len in max_lengths.items():
            if field in data and len(str(data[field])) > max_len:
                errors.append(f"{field} too long (max {max_len} chars)")
    
    return errors

@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        response = web.Response()
    else:
        try:
            response = await handler(request)
        except Exception as e:
            logger.error(f"Request error: {e}")
            response = web.json_response({'error': 'Internal server error'}, status=500)
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

def require_auth(handler):
    async def wrapper(request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return web.json_response({'error': 'Unauthorized'}, status=401)
        
        token = auth_header[7:]
        user = await DB.get_user_by_token(token)
        if not user:
            return web.json_response({'error': 'Invalid token'}, status=401)
        
        request['user'] = user
        request['token'] = token
        return await handler(request)
    return wrapper

def optional_auth(handler):
    """Middleware that adds user info if authenticated but doesn't require it"""
    async def wrapper(request):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            user = await DB.get_user_by_token(token)
            if user:
                request['user'] = user
                request['token'] = token
        return await handler(request)
    return wrapper

async def post_register(request):
    try:
        data = await request.json()
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', '')).strip()
        
        # Validate input
        errors = validate_input(data, ['username', 'password'])
        if len(username) < 3:
            errors.append('Username must be at least 3 characters')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters')
        if len(username) > 50:
            errors.append('Username too long (max 50 chars)')
        
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        if await DB.user_exists(username):
            return web.json_response({'error': 'Username already exists'}, status=400)
        
        salt, hash_val = await hash_password(password)
        user_id = await DB.create_user(username, salt, hash_val)
        
        return web.json_response({
            'message': 'User created successfully',
            'user_id': user_id,
            'username': username
        })
    
    except (KeyError, json.JSONDecodeError, ValueError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return web.json_response({'error': 'Registration failed'}, status=500)

async def get_checkusername(request):
    username = request.query.get('username', '').strip()
    if not username:
        return web.json_response({'error': 'Username parameter required'}, status=400)
    
    if len(username) < 3 or len(username) > 50:
        return web.json_response({'available': False, 'reason': 'Invalid length'})
    
    exists = await DB.user_exists(username)
    return web.json_response({'available': not exists})

@require_auth
async def put_changepassword(request):
    try:
        data = await request.json()
        current_password = str(data.get('current_password', '')).strip()
        new_password = str(data.get('new_password', '')).strip()
        
        errors = validate_input(data, ['current_password', 'new_password'])
        if len(new_password) < 6:
            errors.append('New password must be at least 6 characters')
        
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = request['user']
        if not await verify_password(current_password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Current password is incorrect'}, status=400)
        
        salt, hash_val = await hash_password(new_password)
        await DB.update_user_password(user['id'], salt, hash_val)
        return web.json_response({'message': 'Password changed successfully'})
    
    except (KeyError, json.JSONDecodeError, ValueError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Password change error: {e}")
        return web.json_response({'error': 'Password change failed'}, status=500)

async def post_login(request):
    try:
        data = await request.json()
        username = str(data.get('username', '')).strip()
        password = str(data.get('password', '')).strip()
        
        errors = validate_input(data, ['username', 'password'])
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = await DB.get_user_by_username(username)
        if not user or not await verify_password(password, user['salt'], user['password_hash']):
            return web.json_response({'error': 'Invalid username or password'}, status=401)
        
        token = generate_token()
        await DB.create_session(token, user['id'], time.time() + 3600, request.remote, request.headers.get('User-Agent'))
        await DB.update_last_login(user['id'])
        
        return web.json_response({
            'token': token, 
            'expires_in': 3600,
            'user_id': user['id'],
            'username': user['username']
        })
    
    except (KeyError, json.JSONDecodeError, ValueError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Login error: {e}")
        return web.json_response({'error': 'Login failed'}, status=500)

async def post_logout(request):
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        await DB.delete_session(auth_header[7:])
    return web.json_response({'message': 'Logged out successfully'})

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
        return web.json_response({'error': 'Invalid user ID format'}, status=400)
    
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
        return web.json_response({'error': 'Invalid user ID format'}, status=400)
    
    # Check if the current user is trying to delete themselves
    if current_user['id'] != user_id:
        return web.json_response({'error': 'Forbidden: Can only delete your own account'}, status=403)
    
    deleted = await DB.delete_user(user_id)
    
    if not deleted:
        return web.json_response({'error': 'User not found'}, status=404)
    
    return web.json_response({'message': 'User account deleted successfully'})

# ===== ISOLATED SECTION: POSTS ENDPOINTS AND POSTS DATABASE IMPLEMENTATION =====
@require_auth
async def post_posts(request):
    """Create a new post"""
    try:
        data = await request.json()
        title = str(data.get('title', '')).strip()
        content = str(data.get('content', '')).strip()
        tags = data.get('tags', [])
        
        # Validate input
        errors = validate_input(data, ['title', 'content'], {
            'title': 200, 
            'content': 50000
        })
        
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = request['user']
        post_id = await DB.create_post(user['id'], title, content)
        
        # Add tags if provided
        if tags and isinstance(tags, list):
            valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
            if valid_tags:
                await DB.update_post_tags(post_id, valid_tags)
        
        return web.json_response({
            'message': 'Post created successfully',
            'post_id': post_id,
            'title': title
        }, status=201)
    
    except (KeyError, json.JSONDecodeError, ValueError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Post creation error: {e}")
        return web.json_response({'error': 'Failed to create post'}, status=500)

@optional_auth
async def get_posts(request):
    """Get all posts with pagination"""
    try:
        limit = min(int(request.query.get('limit', 10)), 100)  # Default 10, max 100
        offset = int(request.query.get('offset', 0))
        user_id = request.query.get('user_id')  # Optional filter by user
        
        if user_id:
            posts = await DB.get_posts_by_user(int(user_id), limit, offset)
            total_count = await DB.get_user_posts_count(int(user_id))
        else:
            posts = await DB.get_all_posts(limit, offset)
            total_count = await DB.get_posts_count()
        
        # Add tags to each post
        posts_with_tags = []
        for post in posts:
            post_dict = dict(post)
            tags = await DB.get_tags_by_post(post_dict['id'])
            post_dict['tags'] = [dict(tag) for tag in tags]
            posts_with_tags.append(post_dict)
        
        return web.json_response({
            'posts': posts_with_tags,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total_count,
                'has_more': offset + limit < total_count
            }
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
    except Exception as e:
        logger.error(f"Get posts error: {e}")
        return web.json_response({'error': 'Failed to retrieve posts'}, status=500)

@optional_auth
async def get_posts_id(request):
    """Get a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    post = await DB.get_post_by_id(post_id)
    if not post:
        return web.json_response({'error': 'Post not found'}, status=404)
    
    # Add tags
    post_dict = dict(post)
    tags = await DB.get_tags_by_post(post_dict['id'])
    post_dict['tags'] = [dict(tag) for tag in tags]
    
    return web.json_response({'post': post_dict})

@require_auth
async def put_posts_id(request):
    """Update a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        
        title = str(data.get('title', '')).strip() if 'title' in data else None
        content = str(data.get('content', '')).strip() if 'content' in data else None
        tags = data.get('tags', None)
        
        # Validate input
        errors = []
        if title is not None and (not title or len(title) > 200):
            errors.append('Invalid title (1-200 chars)')
        if content is not None and (not content or len(content) > 50000):
            errors.append('Invalid content (1-50000 chars)')
        
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = request['user']
        updated = await DB.update_post(post_id, user['id'], title, content)
        
        if not updated:
            return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
        
        # Update tags if provided
        if tags is not None and isinstance(tags, list):
            valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
            await DB.update_post_tags(post_id, valid_tags)
        
        return web.json_response({'message': 'Post updated successfully'})
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Post update error: {e}")
        return web.json_response({'error': 'Failed to update post'}, status=500)

@require_auth
async def delete_posts_id(request):
    """Delete a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    user = request['user']
    deleted = await DB.delete_post(post_id, user['id'])
    
    if not deleted:
        return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
    
    return web.json_response({'message': 'Post deleted successfully'})

@require_auth
async def get_posts_my(request):
    """Get current user's posts"""
    try:
        limit = min(int(request.query.get('limit', 10)), 100)
        offset = int(request.query.get('offset', 0))
        
        user = request['user']
        posts = await DB.get_posts_by_user(user['id'], limit, offset)
        total_count = await DB.get_user_posts_count(user['id'])
        
        # Add tags to each post
        posts_with_tags = []
        for post in posts:
            post_dict = dict(post)
            tags = await DB.get_tags_by_post(post_dict['id'])
            post_dict['tags'] = [dict(tag) for tag in tags]
            posts_with_tags.append(post_dict)
        
        return web.json_response({
            'posts': posts_with_tags,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total_count,
                'has_more': offset + limit < total_count
            }
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
    except Exception as e:
        logger.error(f"Get my posts error: {e}")
        return web.json_response({'error': 'Failed to retrieve posts'}, status=500)

async def get_posts_stats(request):
    """Get post statistics for sidebar"""
    try:
        stats = await DB.get_posts_stats()
        return web.json_response({'stats': [dict(stat) for stat in stats]})
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        return web.json_response({'error': 'Failed to retrieve statistics'}, status=500)
# ===== END ISOLATED SECTION: POSTS =====

# ===== ISOLATED SECTION: COMMENTS SYSTEM =====
@require_auth
async def post_posts_id_comments(request):
    """Add a comment to a post"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        content = str(data.get('content', '')).strip()
        parent_comment_id = data.get('parent_comment_id')
        
        errors = validate_input(data, ['content'], {'content': 5000})
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        if parent_comment_id is not None:
            try:
                parent_comment_id = int(parent_comment_id)
            except ValueError:
                return web.json_response({'error': 'Invalid parent comment ID'}, status=400)
        
        user = request['user']
        comment_id = await DB.create_comment(post_id, user['id'], content, parent_comment_id)
        
        return web.json_response({
            'message': 'Comment created successfully',
            'comment_id': comment_id
        }, status=201)
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Comment creation error: {e}")
        return web.json_response({'error': 'Failed to create comment'}, status=500)

@optional_auth
async def get_posts_id_comments(request):
    """Get comments for a post"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    try:
        comments = await DB.get_comments_by_post(post_id)
        
        # Build nested structure
        comment_dict = {}
        root_comments = []
        
        for comment in comments:
            comment_data = dict(comment)
            comment_data['replies'] = []
            comment_dict[comment_data['id']] = comment_data
            
            if comment_data['parent_comment_id'] is None:
                root_comments.append(comment_data)
            else:
                parent = comment_dict.get(comment_data['parent_comment_id'])
                if parent:
                    parent['replies'].append(comment_data)
        
        return web.json_response({'comments': root_comments})
    except Exception as e:
        logger.error(f"Get comments error: {e}")
        return web.json_response({'error': 'Failed to retrieve comments'}, status=500)

@require_auth
async def put_comments_id(request):
    """Update a comment"""
    try:
        comment_id = int(request.match_info['id'])
        data = await request.json()
        content = str(data.get('content', '')).strip()
        
        errors = validate_input(data, ['content'], {'content': 5000})
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = request['user']
        updated = await DB.update_comment(comment_id, user['id'], content)
        
        if not updated:
            return web.json_response({'error': 'Comment not found or unauthorized'}, status=404)
        
        return web.json_response({'message': 'Comment updated successfully'})
    
    except ValueError:
        return web.json_response({'error': 'Invalid comment ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Comment update error: {e}")
        return web.json_response({'error': 'Failed to update comment'}, status=500)

@require_auth
async def delete_comments_id(request):
    """Delete a comment"""
    try:
        comment_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid comment ID format'}, status=400)
    
    user = request['user']
    deleted = await DB.delete_comment(comment_id, user['id'])
    
    if not deleted:
        return web.json_response({'error': 'Comment not found or unauthorized'}, status=404)
    
    return web.json_response({'message': 'Comment deleted successfully'})
# ===== END ISOLATED SECTION: COMMENTS =====

# ===== ISOLATED SECTION: FILE UPLOAD SYSTEM =====
@require_auth
async def post_files(request):
    """Upload a file"""
    try:
        reader = await request.multipart()
        field = await reader.next()
        
        if field.name != 'file':
            return web.json_response({'error': 'File field required'}, status=400)
        
        filename = field.filename
        if not filename:
            return web.json_response({'error': 'Filename required'}, status=400)
        
        # Validate file type
        allowed_types = {
            'image/jpeg', 'image/png', 'image/gif', 'image/webp',
            'video/mp4', 'video/webm', 'video/quicktime',
            'application/pdf', 'text/plain', 'text/markdown',
            'application/json', 'text/csv'
        }
        
        # Generate unique file ID and path
        file_id = str(uuid.uuid4())
        file_ext = Path(filename).suffix.lower()
        unique_filename = f"{file_id}{file_ext}"
        
        # Create year/month directory structure
        now = time.time()
        year_month = time.strftime('%Y/%m', time.localtime(now))
        upload_path = UPLOAD_DIR / year_month
        upload_path.mkdir(parents=True, exist_ok=True)
        
        file_path = upload_path / unique_filename
        
        # Save file with size limit
        size = 0
        max_size = 50 * 1024 * 1024  # 50MB
        
        with open(file_path, 'wb') as f:
            while True:
                chunk = await field.read_chunk()
                if not chunk:
                    break
                size += len(chunk)
                
                if size > max_size:
                    f.close()
                    file_path.unlink()  # Delete partial file
                    return web.json_response({'error': 'File too large (max 50MB)'}, status=400)
                
                f.write(chunk)
        
        # Determine MIME type
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Save to database
        user = request['user']
        await DB.create_file(file_id, user['id'], filename, unique_filename, str(file_path), mime_type, size)
        
        return web.json_response({
            'message': 'File uploaded successfully',
            'file_id': file_id,
            'filename': filename,
            'size': size,
            'mime_type': mime_type,
            'url': f'/files/{file_id}'
        }, status=201)
    
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return web.json_response({'error': f'Upload failed: {str(e)}'}, status=500)

async def get_files_id(request):
    """Download/serve a file"""
    try:
        file_id = request.match_info['id']
    except KeyError:
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    
    file_record = await DB.get_file_by_id(file_id)
    if not file_record:
        return web.json_response({'error': 'File not found'}, status=404)
    
    file_path = Path(file_record['file_path'])
    if not file_path.exists():
        return web.json_response({'error': 'File not found on disk'}, status=404)
    
    # Determine if file should be inline or attachment
    inline_types = {'image/', 'text/', 'application/pdf', 'video/'}
    disposition = 'inline' if any(file_record['mime_type'].startswith(t) for t in inline_types) else 'attachment'
    
    response = web.FileResponse(
        file_path,
        headers={
            'Content-Type': file_record['mime_type'],
            'Content-Disposition': f'{disposition}; filename="{file_record["original_name"]}"',
            'Cache-Control': 'public, max-age=86400'  # Cache for 1 day
        }
    )
    return response

@require_auth
async def delete_files_id(request):
    """Delete a file"""
    try:
        file_id = request.match_info['id']
    except KeyError:
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    
    user = request['user']
    file_record = await DB.get_file_by_id(file_id)
    
    if not file_record:
        return web.json_response({'error': 'File not found'}, status=404)
    
    deleted = await DB.delete_file(file_id, user['id'])
    
    if not deleted:
        return web.json_response({'error': 'File not found or unauthorized'}, status=404)
    
    # Delete actual file
    file_path = Path(file_record['file_path'])
    if file_path.exists():
        try:
            file_path.unlink()
        except Exception as e:
            logger.error(f"Failed to delete file {file_path}: {e}")
    
    return web.json_response({'message': 'File deleted successfully'})

@require_auth
async def get_files_my(request):
    """Get current user's files"""
    try:
        limit = min(int(request.query.get('limit', 50)), 100)
        offset = int(request.query.get('offset', 0))
        
        user = request['user']
        files = await DB.get_files_by_user(user['id'], limit, offset)
        
        files_list = []
        for file in files:
            file_dict = dict(file)
            file_dict['url'] = f'/files/{file_dict["id"]}'
            files_list.append(file_dict)
        
        return web.json_response({'files': files_list})
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
    except Exception as e:
        logger.error(f"Get my files error: {e}")
        return web.json_response({'error': 'Failed to retrieve files'}, status=500)
# ===== END ISOLATED SECTION: FILES =====

# ===== ISOLATED SECTION: TAGS SYSTEM =====
async def get_tags(request):
    """Get all tags"""
    try:
        tags = await DB.get_all_tags()
        return web.json_response({'tags': [dict(tag) for tag in tags]})
    except Exception as e:
        logger.error(f"Get tags error: {e}")
        return web.json_response({'error': 'Failed to retrieve tags'}, status=500)

@require_auth
async def post_tags(request):
    """Create a new tag"""
    try:
        data = await request.json()
        name = str(data.get('name', '')).strip().lower()
        
        errors = validate_input(data, ['name'], {'name': 50})
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        tag_id = await DB.create_tag(name)
        
        return web.json_response({
            'message': 'Tag created successfully',
            'tag_id': tag_id,
            'name': name
        }, status=201)
    
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Tag creation error: {e}")
        return web.json_response({'error': 'Failed to create tag'}, status=500)

@require_auth
async def put_posts_id_tags(request):
    """Update tags for a post"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        tags = data.get('tags', [])
        
        if not isinstance(tags, list):
            return web.json_response({'error': 'Tags must be an array'}, status=400)
        
        # Verify post ownership
        post = await DB.get_post_by_id(post_id)
        if not post:
            return web.json_response({'error': 'Post not found'}, status=404)
        
        user = request['user']
        if post['user_id'] != user['id']:
            return web.json_response({'error': 'Unauthorized'}, status=403)
        
        valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
        await DB.update_post_tags(post_id, valid_tags)
        
        return web.json_response({'message': 'Tags updated successfully'})
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Tag update error: {e}")
        return web.json_response({'error': 'Failed to update tags'}, status=500)
# ===== END ISOLATED SECTION: TAGS =====

# ===== ISOLATED SECTION: EDIT PROPOSALS SYSTEM =====
async def post_posts_id_proposals(request):
    """Submit an edit proposal for a post"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        
        proposer_name = str(data.get('proposer_name', '')).strip()
        proposer_email = str(data.get('proposer_email', '')).strip()
        title = str(data.get('title', '')).strip()
        content = str(data.get('content', '')).strip()
        reason = str(data.get('reason', '')).strip()
        
        errors = validate_input(data, ['proposer_name', 'proposer_email', 'title', 'content'], {
            'proposer_name': 100,
            'proposer_email': 100,
            'title': 200,
            'content': 50000,
            'reason': 1000
        })
        
        # Basic email validation
        if '@' not in proposer_email or '.' not in proposer_email:
            errors.append('Invalid email format')
        
        if errors:
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        proposal_id = await DB.create_edit_proposal(post_id, proposer_name, proposer_email, title, content, reason)
        
        return web.json_response({
            'message': 'Edit proposal submitted successfully',
            'proposal_id': proposal_id
        }, status=201)
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Proposal creation error: {e}")
        return web.json_response({'error': 'Failed to submit proposal'}, status=500)

@require_auth
async def get_posts_id_proposals(request):
    """Get edit proposals for a post (post owner only)"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    # Verify post ownership
    post = await DB.get_post_by_id(post_id)
    if not post:
        return web.json_response({'error': 'Post not found'}, status=404)
    
    user = request['user']
    if post['user_id'] != user['id']:
        return web.json_response({'error': 'Unauthorized'}, status=403)
    
    try:
        proposals = await DB.get_proposals_by_post(post_id)
        return web.json_response({'proposals': [dict(proposal) for proposal in proposals]})
    except Exception as e:
        logger.error(f"Get proposals error: {e}")
        return web.json_response({'error': 'Failed to retrieve proposals'}, status=500)

@require_auth
async def put_proposals_id_approve(request):
    """Approve an edit proposal"""
    try:
        proposal_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid proposal ID format'}, status=400)
    
    proposal = await DB.get_proposal_by_id(proposal_id)
    if not proposal:
        return web.json_response({'error': 'Proposal not found'}, status=404)
    
    # Verify post ownership
    post = await DB.get_post_by_id(proposal['post_id'])
    user = request['user']
    if post['user_id'] != user['id']:
        return web.json_response({'error': 'Unauthorized'}, status=403)
    
    approved = await DB.approve_proposal(proposal_id, user['id'])
    
    if not approved:
        return web.json_response({'error': 'Could not approve proposal'}, status=400)
    
    return web.json_response({'message': 'Proposal approved and applied successfully'})

@require_auth
async def put_proposals_id_reject(request):
    """Reject an edit proposal"""
    try:
        proposal_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid proposal ID format'}, status=400)
    
    proposal = await DB.get_proposal_by_id(proposal_id)
    if not proposal:
        return web.json_response({'error': 'Proposal not found'}, status=404)
    
    # Verify post ownership
    post = await DB.get_post_by_id(proposal['post_id'])
    user = request['user']
    if post['user_id'] != user['id']:
        return web.json_response({'error': 'Unauthorized'}, status=403)
    
    await DB.reject_proposal(proposal_id, user['id'])
    
    return web.json_response({'message': 'Proposal rejected successfully'})
# ===== END ISOLATED SECTION: EDIT PROPOSALS =====

# ===== ISOLATED SECTION: SEARCH FUNCTIONALITY =====
@optional_auth
async def get_search(request):
    """Search posts"""
    query = request.query.get('q', '').strip()
    if not query:
        return web.json_response({'error': 'Search query required'}, status=400)
    
    try:
        limit = min(int(request.query.get('limit', 10)), 100)
        offset = int(request.query.get('offset', 0))
        
        posts = await DB.search_posts(query, limit, offset)
        total_count = await DB.search_posts_count(query)
        
        # Add tags to each post
        posts_with_tags = []
        for post in posts:
            post_dict = dict(post)
            tags = await DB.get_tags_by_post(post_dict['id'])
            post_dict['tags'] = [dict(tag) for tag in tags]
            posts_with_tags.append(post_dict)
        
        return web.json_response({
            'posts': posts_with_tags,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'total': total_count,
                'has_more': offset + limit < total_count
            },
            'query': query
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
    except Exception as e:
        logger.error(f"Search error: {e}")
        return web.json_response({'error': 'Search failed'}, status=500)
# ===== END ISOLATED SECTION: SEARCH =====

async def cleanup_task():
    while True:
        await asyncio.sleep(300)  # Run every 5 minutes
        try:
            await DB.cleanup_sessions()
        except Exception as e:
            logger.error(f"Cleanup task error: {e}")

# File watching for development
import sys
import threading

def watch_file():
    try:
        original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        while True: 
            time.sleep(2)
            current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
            if current_hash != original_hash:
                logger.info("File changed, restarting...")
                os.execv(sys.executable, ['python'] + sys.argv)
    except Exception as e:
        logger.error(f"File watcher error: {e}")

# Auto-routing system
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
app.router.add_route('PUT', '/posts/{id}/tags', put_posts_id_tags)
# ===== END ISOLATED SECTION: POSTS =====

# ===== ISOLATED SECTION: COMMENTS SYSTEM =====
app.router.add_route('POST', '/posts/{id}/comments', post_posts_id_comments)
app.router.add_route('GET', '/posts/{id}/comments', get_posts_id_comments)
app.router.add_route('PUT', '/comments/{id}', put_comments_id)
app.router.add_route('DELETE', '/comments/{id}', delete_comments_id)
# ===== END ISOLATED SECTION: COMMENTS =====

# ===== ISOLATED SECTION: FILE UPLOAD SYSTEM =====
app.router.add_route('GET', '/files/{id}', get_files_id)
app.router.add_route('DELETE', '/files/{id}', delete_files_id)
# ===== END ISOLATED SECTION: FILES =====

# ===== ISOLATED SECTION: EDIT PROPOSALS SYSTEM =====
app.router.add_route('POST', '/posts/{id}/proposals', post_posts_id_proposals)
app.router.add_route('GET', '/posts/{id}/proposals', get_posts_id_proposals)
app.router.add_route('PUT', '/proposals/{id}/approve', put_proposals_id_approve)
app.router.add_route('PUT', '/proposals/{id}/reject', put_proposals_id_reject)
# ===== END ISOLATED SECTION: EDIT PROPOSALS =====

# Auto-register other routes
excluded_routes = [
    'get_users_id', 'delete_users_id', 'get_posts_id', 'put_posts_id', 'delete_posts_id', 
    'put_posts_id_tags', 'post_posts_id_comments', 'get_posts_id_comments', 
    'put_comments_id', 'delete_comments_id', 'get_files_id', 'delete_files_id',
    'post_posts_id_proposals', 'get_posts_id_proposals', 'put_proposals_id_approve', 'put_proposals_id_reject'
]

for name, handler in list(globals().items()):
    if name in excluded_routes:
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
    
    print(f"\n📝 Posts API endpoints:")
    print(f"  POST   /posts          - Create new post")
    print(f"  GET    /posts          - List all posts (with pagination)")
    print(f"  GET    /posts/my       - Get current user's posts")
    print(f"  GET    /posts/{{id}}     - Get specific post by ID")
    print(f"  PUT    /posts/{{id}}     - Update specific post (owner only)")
    print(f"  DELETE /posts/{{id}}     - Delete specific post (owner only)")
    print(f"  GET    /posts/stats    - Get post statistics by year/month")
    print(f"  PUT    /posts/{{id}}/tags - Update post tags")
    
    print(f"\n💬 Comments API endpoints:")
    print(f"  POST   /posts/{{id}}/comments - Add comment to post")
    print(f"  GET    /posts/{{id}}/comments - Get comments for post")
    print(f"  PUT    /comments/{{id}}      - Update comment (owner only)")
    print(f"  DELETE /comments/{{id}}      - Delete comment (owner only)")
    
    print(f"\n📁 File API endpoints:")
    print(f"  POST   /files          - Upload file")
    print(f"  GET    /files/{{id}}     - Download/serve file")
    print(f"  DELETE /files/{{id}}     - Delete file (owner only)")
    print(f"  GET    /files/my       - Get current user's files")
    
    print(f"\n🏷️  Tags API endpoints:")
    print(f"  GET    /tags           - Get all tags")
    print(f"  POST   /tags           - Create new tag")
    
    print(f"\n✏️  Edit Proposals API endpoints:")
    print(f"  POST   /posts/{{id}}/proposals    - Submit edit proposal")
    print(f"  GET    /posts/{{id}}/proposals    - Get proposals (owner only)")
    print(f"  PUT    /proposals/{{id}}/approve  - Approve proposal")
    print(f"  PUT    /proposals/{{id}}/reject   - Reject proposal")
    
    print(f"\n🔍 Search API endpoints:")
    print(f"  GET    /search         - Search posts (query parameter 'q')")
    
    print(f"\n🔧 Example API usage:")
    base_url = f"{protocol}://{host}:{port}"
    print(f"# Register new user:")
    print(f"curl -X POST {base_url}/register -H 'Content-Type: application/json' \\")
    print(f"  -d '{{\"username\":\"alice\",\"password\":\"secret123\"}}'")
    print(f"\n# Login:")
    print(f"curl -X POST {base_url}/login -H 'Content-Type: application/json' \\")
    print(f"  -d '{{\"username\":\"alice\",\"password\":\"secret123\"}}'")
    print(f"\n# Get posts:")
    print(f"curl {base_url}/posts")
    print(f"\n# Search posts:")
    print(f"curl '{base_url}/search?q=javascript'")
    print(f"\n# Upload file:")
    print(f"curl -X POST {base_url}/files -H 'Authorization: Bearer YOUR_TOKEN' \\")
    print(f"  -F 'file=@image.jpg'")
    
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