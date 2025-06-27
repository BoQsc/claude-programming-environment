#!/usr/bin/env python3
"""
Auth API - CUSTOM ULTRA-FUZZY SEARCH + FIXED TAGS + 29-DAY SESSIONS
===============================================================================
🧠 NEW: Custom ultra-fuzzy search with native Levenshtein distance implementation
🧠 NEW: Backend fuzzy matching with 40% similarity threshold
🧠 NEW: Scalable fuzzy search for thousands of posts - NO EXTERNAL DEPENDENCIES
🧠 NEW: Multiple fuzzy matching algorithms (exact, partial, word-level, similarity)
🔧 FIXED: Tag counting race condition - atomic operations
🆕 UPDATED: Session expiration extended to 29 days (2,505,600 seconds)
✅ TESTED: Clean database initialization and backward compatibility
✅ WORKING: Tag search with exact matching
✅ WORKING: General search with partial matching (NOW INCLUDES COMMENTS!)
✅ WORKING: Tag counts that update properly WITHOUT RACE CONDITIONS

🎯 CRITICAL FIX: Tag count operations now use single database transaction
🎯 NEW: 29-day session expiration for better user experience
🧠 NEW: Native backend fuzzy search - scalable for large datasets, zero dependencies
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

# Configure logging with more detail
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DB_PATH = "auth.db"
UPLOAD_DIR = Path("uploads")

# 🆕 29-day session expiration (in seconds)
SESSION_DURATION = 29 * 24 * 60 * 60  # 29 days = 2,505,600 seconds

# Ensure upload directory exists
UPLOAD_DIR.mkdir(exist_ok=True)

# 🧠 CUSTOM FUZZY SEARCH CONFIGURATION
FUZZY_CONFIG = {
    'similarity_threshold': 0.4,  # 40% similarity threshold
    'field_weights': {
        'title': 1.2,     # Boost title matches
        'content': 1.0,   # Standard content scoring
        'tag': 1.3,       # Boost tag matches  
        'author': 0.9     # Slightly lower author scoring
    },
    'score_weights': {
        'exact': 100,
        'partial': 60,
        'word_exact': 80,
        'word_partial': 50,
        'fuzzy': 40,
        'recency_bonus': 20,
        'length_bonus': 10
    },
    'min_word_length': 3,  # Minimum word length for fuzzy matching
    'max_fuzzy_distance': 4  # Maximum edit distance for fuzzy matching
}

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
            # Enable foreign keys
            await db.execute("PRAGMA foreign_keys = ON")
            
            # Core tables
            await db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, salt TEXT, password_hash TEXT, created_at REAL, last_login REAL)")
            await db.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created_at REAL, expires_at REAL, ip_address TEXT, user_agent TEXT, FOREIGN KEY (user_id) REFERENCES users (id))")
            
            # Posts table
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

            # Comments table
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

            # Files table
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

            # Tags system - SIMPLIFIED WITHOUT PROBLEMATIC TRIGGERS
            await db.execute("""CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL,
                post_count INTEGER DEFAULT 0
            )""")
            
            await db.execute("""CREATE TABLE IF NOT EXISTS post_tags (
                post_id INTEGER NOT NULL,
                tag_id INTEGER NOT NULL,
                created_at REAL NOT NULL DEFAULT (unixepoch()),
                PRIMARY KEY (post_id, tag_id),
                FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
            )""")
            
            # Create indices for tags
            await db.execute("CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_tags_post_count ON tags(post_count DESC)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_post_tags_post_id ON post_tags(post_id)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_post_tags_tag_id ON post_tags(tag_id)")

            # Edit proposals table
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

            # 🔧 REMOVE ALL PROBLEMATIC TRIGGERS FOR NOW
            await db.execute("DROP TRIGGER IF EXISTS tag_count_insert")
            await db.execute("DROP TRIGGER IF EXISTS tag_count_delete")
            await db.execute("DROP TRIGGER IF EXISTS update_tag_count_insert")
            await db.execute("DROP TRIGGER IF EXISTS update_tag_count_delete")
            
            logger.info("✅ Database initialized without triggers (manual tag count updates)")

            # Create session cleanup index
            await db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)")
            
            await db.commit()
            logger.info("Database initialization completed successfully")

    # 🧠 CUSTOM FUZZY SEARCH IMPLEMENTATION - NO EXTERNAL DEPENDENCIES
    @staticmethod
    def levenshtein_distance(s1, s2):
        """🧠 Calculate Levenshtein distance between two strings"""
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)
        
        # Create matrix
        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        # Initialize first row and column
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        
        # Fill the matrix
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = 1 + min(
                        dp[i-1][j],      # deletion
                        dp[i][j-1],      # insertion
                        dp[i-1][j-1]     # substitution
                    )
        
        return dp[m][n]
    
    @staticmethod
    def similarity_ratio(s1, s2):
        """🧠 Calculate similarity ratio between two strings (0.0 to 1.0)"""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        
        max_len = max(len(s1), len(s2))
        distance = DB.levenshtein_distance(s1.lower(), s2.lower())
        return (max_len - distance) / max_len
    
    @staticmethod
    def partial_ratio(s1, s2):
        """🧠 Calculate partial similarity ratio (substring matching)"""
        if not s1 or not s2:
            return 0.0
        
        s1_lower = s1.lower()
        s2_lower = s2.lower()
        
        # Check if one string is contained in the other
        if s1_lower in s2_lower:
            return 1.0
        if s2_lower in s1_lower:
            return 1.0
        
        # Find best substring match
        shorter, longer = (s1_lower, s2_lower) if len(s1_lower) <= len(s2_lower) else (s2_lower, s1_lower)
        
        best_ratio = 0.0
        for i in range(len(longer) - len(shorter) + 1):
            substring = longer[i:i + len(shorter)]
            ratio = DB.similarity_ratio(shorter, substring)
            best_ratio = max(best_ratio, ratio)
        
        return best_ratio
    
    @staticmethod
    def token_sort_ratio(s1, s2):
        """🧠 Calculate similarity after sorting words"""
        if not s1 or not s2:
            return 0.0
        
        # Sort words in each string
        words1 = sorted(s1.lower().split())
        words2 = sorted(s2.lower().split())
        
        sorted_s1 = ' '.join(words1)
        sorted_s2 = ' '.join(words2)
        
        return DB.similarity_ratio(sorted_s1, sorted_s2)
    
    @staticmethod
    def token_set_ratio(s1, s2):
        """🧠 Calculate similarity using set operations on words"""
        if not s1 or not s2:
            return 0.0
        
        words1 = set(s1.lower().split())
        words2 = set(s2.lower().split())
        
        intersection = words1 & words2
        union = words1 | words2
        
        if not union:
            return 1.0 if not words1 and not words2 else 0.0
        
        return len(intersection) / len(union)
    
    @staticmethod
    def fuzzy_score(query_term, target_text, field_type='content'):
        """🧠 Calculate comprehensive fuzzy score using multiple algorithms"""
        if not query_term or not target_text:
            return 0.0
        
        query_lower = query_term.lower().strip()
        target_lower = target_text.lower().strip()
        
        if not query_lower or not target_lower:
            return 0.0
        
        # Calculate different similarity scores
        ratio_score = DB.similarity_ratio(query_lower, target_lower)
        partial_score = DB.partial_ratio(query_lower, target_lower)
        token_sort_score = DB.token_sort_ratio(query_lower, target_lower)
        token_set_score = DB.token_set_ratio(query_lower, target_lower)
        
        # Take the best score from all algorithms
        best_score = max(ratio_score, partial_score, token_sort_score, token_set_score)
        
        # Apply field-based weights
        field_weight = FUZZY_CONFIG['field_weights'].get(field_type, 1.0)
        weighted_score = best_score * field_weight
        
        logger.debug(f"🧠 Fuzzy scores for '{query_lower}' vs '{target_lower[:50]}...': "
                    f"ratio={ratio_score:.2f}, partial={partial_score:.2f}, "
                    f"token_sort={token_sort_score:.2f}, token_set={token_set_score:.2f}, "
                    f"best={best_score:.2f}, weighted={weighted_score:.2f} ({field_type})")
        
        return weighted_score
    
    @staticmethod
    def calculate_post_fuzzy_relevance(post, search_terms, similarity_threshold=0.4):
        """🧠 Calculate overall fuzzy relevance score for a post"""
        if not search_terms:
            return 0.0
        
        total_score = 0.0
        match_details = []
        
        # Define scoring weights for different fields
        score_weights = FUZZY_CONFIG['score_weights']
        
        for term in search_terms:
            term_scores = {}
            
            # Check title
            title_score = DB.fuzzy_score(term, post.get('title', ''), 'title')
            if title_score >= similarity_threshold:
                weighted_score = title_score * score_weights['fuzzy']
                term_scores['title'] = weighted_score
                
            # Check content  
            content_score = DB.fuzzy_score(term, post.get('content', ''), 'content')
            if content_score >= similarity_threshold:
                weighted_score = content_score * score_weights['fuzzy']
                term_scores['content'] = weighted_score
                
            # Check author
            author_score = DB.fuzzy_score(term, post.get('username', ''), 'author')
            if author_score >= similarity_threshold:
                weighted_score = author_score * score_weights['fuzzy']
                term_scores['author'] = weighted_score
                
            # Check tags
            if post.get('tags'):
                best_tag_score = 0.0
                for tag in post['tags']:
                    tag_name = tag.get('name', '') if isinstance(tag, dict) else str(tag)
                    if tag_name:
                        tag_score = DB.fuzzy_score(term, tag_name, 'tag')
                        if tag_score >= similarity_threshold:
                            best_tag_score = max(best_tag_score, tag_score)
                
                if best_tag_score > 0:
                    weighted_score = best_tag_score * score_weights['fuzzy']
                    term_scores['tags'] = weighted_score
            
            # Additional exact and partial matching bonuses
            term_lower = term.lower()
            
            # Exact word matching in title
            if post.get('title', '').lower().find(term_lower) != -1:
                if term_lower in post['title'].lower().split():
                    term_scores['title_exact'] = score_weights['word_exact']
                else:
                    term_scores['title_partial'] = score_weights['word_partial']
            
            # Exact word matching in content
            if post.get('content', '').lower().find(term_lower) != -1:
                content_words = post['content'].lower().split()
                if term_lower in content_words:
                    term_scores['content_exact'] = score_weights['word_exact']
                else:
                    term_scores['content_partial'] = score_weights['word_partial']
            
            # Get best score for this term
            if term_scores:
                best_field = max(term_scores.keys(), key=lambda k: term_scores[k])
                best_score = term_scores[best_field]
                total_score += best_score
                match_details.append(f"'{term}' in {best_field} ({best_score:.1f})")
                logger.debug(f"🧠 Term '{term}' best match: {best_field} = {best_score:.1f}")
        
        # Add recency bonus (newer posts get slight boost)
        if post.get('created_at'):
            days_old = (time.time() - post['created_at']) / (24 * 60 * 60)
            recency_bonus = max(0, score_weights['recency_bonus'] - days_old * 0.1)
            if recency_bonus > 1:
                total_score += recency_bonus
                match_details.append(f"recency bonus ({recency_bonus:.1f})")
        
        # Add content length factor (longer posts get small bonus)
        if post.get('content'):
            length_bonus = min(score_weights['length_bonus'], (len(post['content']) / 1000) * score_weights['length_bonus'])
            if length_bonus > 1:
                total_score += length_bonus
                match_details.append(f"length bonus ({length_bonus:.1f})")
        
        if match_details:
            logger.info(f"🧠 Post '{post.get('title', '')[:50]}...' fuzzy score: {total_score:.1f} "
                       f"({', '.join(match_details)})")
        
        return total_score

    # 🔧 ENHANCED: Search functionality with custom fuzzy search
    @staticmethod
    async def search_posts(query, limit=50, offset=0):
        """🧠 ENHANCED: Search with backend custom fuzzy matching"""
        query = query.strip()
        if not query:
            return []
            
        logger.info(f"🔍 Starting custom fuzzy search for: '{query}'")
        
        try:
            # Step 1: Try traditional SQL search first (fast)
            search_pattern = f'%{query.lower()}%'
            
            sql_results = await DB._execute("""
                SELECT DISTINCT p.*, u.username, '' as content_snippet, 0 as rank
                FROM posts p 
                JOIN users u ON p.user_id = u.id 
                WHERE (
                    LOWER(p.title) LIKE ? 
                    OR LOWER(p.content) LIKE ? 
                    OR LOWER(u.username) LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM post_tags pt 
                        JOIN tags t ON pt.tag_id = t.id 
                        WHERE pt.post_id = p.id AND LOWER(t.name) LIKE ?
                    )
                    OR EXISTS (
                        SELECT 1 FROM comments c 
                        WHERE c.post_id = p.id AND LOWER(c.content) LIKE ?
                    )
                )
                ORDER BY p.created_at DESC 
                LIMIT ? OFFSET ?
            """, (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern, limit, offset), 'all')
            
            logger.info(f"🔍 SQL search found {len(sql_results)} results")
            
            # Step 2: If we have enough results from SQL, return them
            if sql_results and len(sql_results) >= limit:
                logger.info(f"✅ SQL search sufficient, returning {len(sql_results)} results")
                return sql_results or []
            
            # Step 3: Enhance with custom fuzzy search
            logger.info(f"🧠 SQL search insufficient ({len(sql_results)} results), adding custom fuzzy search...")
            
            # Get more posts for fuzzy matching (but not all - be reasonable)
            fuzzy_limit = min(1000, limit * 20)  # Get up to 1000 posts for fuzzy matching
            
            all_posts = await DB._execute("""
                SELECT p.*, u.username 
                FROM posts p 
                JOIN users u ON p.user_id = u.id 
                ORDER BY p.created_at DESC 
                LIMIT ?
            """, (fuzzy_limit,), 'all')
            
            logger.info(f"🧠 Loaded {len(all_posts)} posts for custom fuzzy matching")
            
            if all_posts:
                # Add tags to posts for fuzzy matching
                posts_with_tags = []
                for post in all_posts:
                    post_dict = dict(post)
                    try:
                        tags = await DB.get_tags_by_post(post_dict['id'])
                        post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
                    except:
                        post_dict['tags'] = []
                    posts_with_tags.append(post_dict)
                
                # Parse search terms
                search_terms = [term.strip() for term in query.lower().split() if term.strip()]
                logger.info(f"🧠 Custom fuzzy searching for terms: {search_terms}")
                
                # Calculate fuzzy scores
                scored_posts = []
                similarity_threshold = FUZZY_CONFIG['similarity_threshold']  # 40% similarity threshold
                
                for post in posts_with_tags:
                    fuzzy_score = DB.calculate_post_fuzzy_relevance(post, search_terms, similarity_threshold)
                    if fuzzy_score > 0:
                        post['fuzzy_score'] = fuzzy_score
                        scored_posts.append(post)
                
                logger.info(f"🧠 Custom fuzzy search found {len(scored_posts)} relevant posts")
                
                # Sort by fuzzy score (descending) and apply pagination
                scored_posts.sort(key=lambda p: p.get('fuzzy_score', 0), reverse=True)
                
                # Add the SQL results to the top (they're more exact matches)
                sql_posts_ids = {post['id'] for post in sql_results} if sql_results else set()
                fuzzy_only_posts = [p for p in scored_posts if p['id'] not in sql_posts_ids]
                
                # Combine: SQL results first, then best fuzzy results
                all_results = list(sql_results) if sql_results else []
                remaining_slots = limit - len(all_results)
                
                if remaining_slots > 0:
                    all_results.extend(fuzzy_only_posts[:remaining_slots])
                
                logger.info(f"🧠 Combined search: {len(sql_results or [])} SQL + {len(all_results) - len(sql_results or [])} fuzzy = {len(all_results)} total")
                
                # Apply offset after combining results
                final_results = all_results[offset:offset + limit]
                
                return final_results
            
            # Step 4: Fallback to SQL results only
            logger.info(f"🔍 Returning SQL-only results: {len(sql_results)}")
            return sql_results or []
            
        except Exception as e:
            logger.error(f"❌ Enhanced search error: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return []

    @staticmethod
    async def search_posts_count(query):
        """🧠 ENHANCED: Get search count including fuzzy results"""
        query = query.strip()
        if not query:
            return 0
            
        try:
            # Get SQL count first
            search_pattern = f'%{query.lower()}%'
            
            sql_result = await DB._execute("""
                SELECT COUNT(DISTINCT p.id) as count 
                FROM posts p 
                JOIN users u ON p.user_id = u.id 
                WHERE (
                    LOWER(p.title) LIKE ? 
                    OR LOWER(p.content) LIKE ? 
                    OR LOWER(u.username) LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM post_tags pt 
                        JOIN tags t ON pt.tag_id = t.id 
                        WHERE pt.post_id = p.id AND LOWER(t.name) LIKE ?
                    )
                    OR EXISTS (
                        SELECT 1 FROM comments c 
                        WHERE c.post_id = p.id AND LOWER(c.content) LIKE ?
                    )
                )
            """, (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern), 'one')
            
            sql_count = sql_result['count'] if sql_result else 0
            
            # If we have low SQL count, get a more accurate count with fuzzy
            if sql_count < 10:  # Only do expensive fuzzy count if needed
                logger.info(f"🧠 Getting custom fuzzy search count (SQL found {sql_count})")
                
                # This is expensive but necessary for accurate pagination
                fuzzy_results = await DB.search_posts(query, limit=1000, offset=0)
                fuzzy_count = len(fuzzy_results)
                
                logger.info(f"🧠 Custom fuzzy search count: {fuzzy_count} total results")
                return fuzzy_count
            
            return sql_count
            
        except Exception as e:
            logger.error(f"❌ Search count error: {e}")
            return 0

    # 🔧 ORIGINAL: Keep the original search_posts method as search_posts_sql for backward compatibility
    @staticmethod
    async def search_posts_sql(query, limit=50, offset=0):
        """🔧 ORIGINAL: Basic SQL search without fuzzy matching - IMPROVED VERSION"""
        query = query.strip()
        if not query:
            return []
            
        # Case-insensitive search pattern
        search_pattern = f'%{query.lower()}%'
        
        logger.info(f"Searching for: '{query}' with pattern: '{search_pattern}'")
        
        try:
            # Enhanced search that properly includes comments
            results = await DB._execute("""
                SELECT DISTINCT p.*, u.username, '' as content_snippet, 0 as rank
                FROM posts p 
                JOIN users u ON p.user_id = u.id 
                WHERE (
                    LOWER(p.title) LIKE ? 
                    OR LOWER(p.content) LIKE ? 
                    OR LOWER(u.username) LIKE ?
                    OR EXISTS (
                        SELECT 1 FROM post_tags pt 
                        JOIN tags t ON pt.tag_id = t.id 
                        WHERE pt.post_id = p.id AND LOWER(t.name) LIKE ?
                    )
                    OR EXISTS (
                        SELECT 1 FROM comments c 
                        WHERE c.post_id = p.id AND LOWER(c.content) LIKE ?
                    )
                )
                ORDER BY p.created_at DESC 
                LIMIT ? OFFSET ?
            """, (search_pattern, search_pattern, search_pattern, search_pattern, search_pattern, limit, offset), 'all')
            
            logger.info(f"Search found {len(results) if results else 0} posts")
            return results or []
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return []
    
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
    async def renew_session(token):
        """🆕 NEW: Renew session expiry time on activity"""
        new_expiry = time.time() + SESSION_DURATION
        result = await DB._execute("UPDATE sessions SET expires_at = ? WHERE token = ? AND expires_at > ?", 
                                 (new_expiry, token, time.time()))
        return new_expiry if result else None
    
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

    # Posts operations
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
        
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys
                await db.execute("PRAGMA foreign_keys = ON")
                
                # First verify the post belongs to the user
                post_result = await db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
                post_row = await post_result.fetchone()
                if not post_row or post_row[0] != user_id:
                    logger.warning(f"Post {post_id} not found or not owned by user {user_id}")
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
                
                logger.info(f"Post {post_id} updated successfully by user {user_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error updating post {post_id}: {e}")
            return False
    
    @staticmethod
    async def delete_post(post_id, user_id):
        """Delete a post - only the owner can delete - SIMPLIFIED VERSION"""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys
                await db.execute("PRAGMA foreign_keys = ON")
                
                # First verify the post exists and belongs to the user
                post_result = await db.execute("SELECT user_id FROM posts WHERE id = ?", (post_id,))
                post_row = await post_result.fetchone()
                if not post_row:
                    logger.warning(f"Post {post_id} not found")
                    return False
                if post_row[0] != user_id:
                    logger.warning(f"Post {post_id} not owned by user {user_id}")
                    return False
                
                # Manually delete related records in correct order
                logger.info(f"Deleting related records for post {post_id}")
                
                # Delete post_tags first
                result = await db.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
                logger.info(f"Deleted {result.rowcount} post_tags for post {post_id}")
                
                # Delete comments
                result = await db.execute("DELETE FROM comments WHERE post_id = ?", (post_id,))
                logger.info(f"Deleted {result.rowcount} comments for post {post_id}")
                
                # Delete proposals
                result = await db.execute("DELETE FROM post_edit_proposals WHERE post_id = ?", (post_id,))
                logger.info(f"Deleted {result.rowcount} proposals for post {post_id}")
                
                # Finally delete the post itself
                result = await db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
                await db.commit()
                
                if result.rowcount > 0:
                    logger.info(f"Post {post_id} deleted successfully by user {user_id}")
                    return True
                else:
                    logger.warning(f"Failed to delete post {post_id} - no rows affected")
                    return False
                    
        except Exception as e:
            logger.error(f"Error deleting post {post_id}: {e}")
            return False
    
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

    # Comments operations
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

    # File operations
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

    # 🔧 FIXED: Clean, working tags system
    @staticmethod
    async def create_or_get_tag(name):
        """Create or get a tag - CLEAN VERSION"""
        name = name.strip().lower()
        if not name:
            return None
            
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys
                await db.execute("PRAGMA foreign_keys = ON")
                
                # First try to get existing tag
                cursor = await db.execute("SELECT id FROM tags WHERE name = ?", (name,))
                result = await cursor.fetchone()
                
                if result:
                    tag_id = result[0]
                    logger.debug(f"Found existing tag: {name} (ID: {tag_id})")
                    return tag_id
                
                # Create new tag
                cursor = await db.execute(
                    "INSERT INTO tags (name, created_at, post_count) VALUES (?, ?, 0)", 
                    (name, time.time())
                )
                await db.commit()
                tag_id = cursor.lastrowid
                logger.info(f"Created new tag: {name} (ID: {tag_id})")
                return tag_id
                
        except Exception as e:
            logger.error(f"Failed to create/get tag '{name}': {e}")
            return None

    # 🎯 CRITICAL FIX: Atomic tag operations to prevent race conditions
    @staticmethod
    async def get_all_tags_with_accurate_counts():
        """🎯 FIXED: Get all tags with ATOMIC count update - NO RACE CONDITIONS!"""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys and WAL mode for better concurrency
                await db.execute("PRAGMA foreign_keys = ON")
                await db.execute("PRAGMA journal_mode = WAL")
                
                logger.info("🎯 ATOMIC TAG OPERATION: Updating counts and retrieving tags in single transaction")
                
                # Step 1: Create tags table if it doesn't exist (safety check)
                await db.execute("""CREATE TABLE IF NOT EXISTS tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at REAL NOT NULL,
                    post_count INTEGER DEFAULT 0
                )""")
                
                # Step 2: Update all tag counts atomically within this transaction
                logger.debug("📊 Updating tag post counts...")
                await db.execute("""
                    UPDATE tags SET post_count = (
                        SELECT COUNT(DISTINCT pt.post_id) 
                        FROM post_tags pt 
                        WHERE pt.tag_id = tags.id
                    )
                """)
                
                # Step 3: Get current state for debugging
                debug_result = await db.execute("""
                    SELECT t.id, t.name, t.post_count, 
                           COALESCE((SELECT COUNT(DISTINCT pt.post_id) FROM post_tags pt WHERE pt.tag_id = t.id), 0) as actual_count
                    FROM tags t 
                    ORDER BY t.post_count DESC, t.name ASC
                """)
                debug_rows = await debug_result.fetchall()
                
                logger.info("🔍 Tag count verification:")
                for row in debug_rows:
                    tag_id, name, stored_count, actual_count = row
                    logger.info(f"  Tag '{name}' (ID: {tag_id}): stored={stored_count}, actual={actual_count}")
                    if stored_count != actual_count:
                        logger.warning(f"  ⚠️  MISMATCH for tag '{name}': stored={stored_count} vs actual={actual_count}")
                
                # Step 4: Remove tags with zero posts
                delete_result = await db.execute("DELETE FROM tags WHERE post_count = 0")
                if delete_result.rowcount > 0:
                    logger.info(f"🗑️  Removed {delete_result.rowcount} empty tags")
                
                # Step 5: Get final tags in same transaction (ensures consistency)
                final_result = await db.execute("""
                    SELECT id, name, created_at, post_count 
                    FROM tags 
                    WHERE post_count > 0
                    ORDER BY post_count DESC, name ASC
                """)
                tags = await final_result.fetchall()
                
                await db.commit()
                
                logger.info(f"✅ ATOMIC OPERATION COMPLETE: Retrieved {len(tags)} tags with accurate counts")
                
                # Convert to list of dicts and ensure we have proper data
                result = []
                for tag in tags:
                    result.append({
                        'id': tag[0],
                        'name': tag[1],
                        'created_at': tag[2],
                        'post_count': tag[3]
                    })
                
                return result
                
        except Exception as e:
            logger.error(f"❌ ATOMIC TAG OPERATION FAILED: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return []

    @staticmethod
    async def get_all_tags():
        """Get all tags ordered by popularity - REDIRECTS TO ATOMIC VERSION WITH FALLBACK"""
        try:
            # Try the atomic version first
            return await DB.get_all_tags_with_accurate_counts()
        except Exception as e:
            logger.error(f"Atomic tag retrieval failed: {e}, using simple fallback")
            # Fallback to simple query
            try:
                return await DB._execute("""
                    SELECT id, name, created_at, 
                           COALESCE(post_count, 0) as post_count 
                    FROM tags 
                    WHERE COALESCE(post_count, 0) > 0
                    ORDER BY post_count DESC, name ASC
                """, fetch='all')
            except Exception as fallback_error:
                logger.error(f"Even fallback failed: {fallback_error}")
                return []

    @staticmethod
    async def get_tags_by_post(post_id):
        """Get tags for a specific post"""
        return await DB._execute("""
            SELECT t.id, t.name, t.created_at, t.post_count
            FROM tags t 
            JOIN post_tags pt ON t.id = pt.tag_id 
            WHERE pt.post_id = ? 
            ORDER BY t.name
        """, (post_id,), 'all')

    @staticmethod
    async def update_tag_counts():
        """🎯 FIXED: Standalone tag count update with detailed logging and error handling"""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys and optimizations
                await db.execute("PRAGMA foreign_keys = ON")
                await db.execute("PRAGMA journal_mode = WAL")
                
                logger.info("🔧 MANUAL TAG COUNT UPDATE - Starting...")
                
                # Safety check - ensure tables exist
                await db.execute("""CREATE TABLE IF NOT EXISTS tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at REAL NOT NULL,
                    post_count INTEGER DEFAULT 0
                )""")
                
                await db.execute("""CREATE TABLE IF NOT EXISTS post_tags (
                    post_id INTEGER NOT NULL,
                    tag_id INTEGER NOT NULL,
                    created_at REAL NOT NULL DEFAULT (unixepoch()),
                    PRIMARY KEY (post_id, tag_id),
                    FOREIGN KEY (post_id) REFERENCES posts (id) ON DELETE CASCADE,
                    FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
                )""")
                
                # Get current post_tags data for debugging
                post_tags_result = await db.execute("SELECT post_id, tag_id FROM post_tags ORDER BY tag_id")
                post_tags_data = await post_tags_result.fetchall()
                logger.info(f"📊 post_tags table has {len(post_tags_data)} entries")
                
                # Group by tag_id to see actual counts
                from collections import defaultdict
                tag_post_counts = defaultdict(set)
                for post_id, tag_id in post_tags_data:
                    tag_post_counts[tag_id].add(post_id)
                
                logger.info("📊 Calculated post counts per tag_id:")
                for tag_id, post_ids in tag_post_counts.items():
                    logger.info(f"  Tag ID {tag_id}: {len(post_ids)} unique posts - {sorted(list(post_ids))}")
                
                # Get current stored counts for comparison
                existing_tags_result = await db.execute("SELECT id, name, post_count FROM tags ORDER BY id")
                existing_tags = await existing_tags_result.fetchall()
                logger.info("📊 Current stored counts:")
                for tag_id, name, post_count in existing_tags:
                    actual_count = len(tag_post_counts.get(tag_id, set()))
                    status = "✅" if post_count == actual_count else "❌"
                    logger.info(f"  {status} Tag '{name}' (ID: {tag_id}): stored={post_count}, actual={actual_count}")
                
                # Update all tag counts
                update_result = await db.execute("""
                    UPDATE tags SET post_count = (
                        SELECT COUNT(DISTINCT pt.post_id) 
                        FROM post_tags pt 
                        WHERE pt.tag_id = tags.id
                    )
                """)
                
                # Verify the update worked
                updated_tags_result = await db.execute("SELECT id, name, post_count FROM tags ORDER BY post_count DESC, name ASC")
                updated_tags = await updated_tags_result.fetchall()
                logger.info("📊 UPDATED tag counts:")
                for tag_id, name, post_count in updated_tags:
                    logger.info(f"  Tag '{name}' (ID: {tag_id}): count={post_count}")
                
                # Remove tags with zero posts
                delete_result = await db.execute("DELETE FROM tags WHERE post_count = 0")
                deleted_count = delete_result.rowcount
                
                await db.commit()
                
                logger.info(f"✅ Tag count update completed successfully!")
                logger.info(f"   - Updated counts for {len(updated_tags)} tags")
                logger.info(f"   - Removed {deleted_count} empty tags")
                
                return True
                
        except Exception as e:
            logger.error(f"❌ Manual tag count update failed: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False

    @staticmethod
    async def update_post_tags(post_id, tag_names):
        """🎯 FIXED: Update tags for a post with atomic count update"""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                # Enable foreign keys and optimizations
                await db.execute("PRAGMA foreign_keys = ON")
                await db.execute("PRAGMA journal_mode = WAL")
                
                logger.info(f"🏷️  Updating tags for post {post_id}: {tag_names}")
                
                # Remove existing tags
                result = await db.execute("DELETE FROM post_tags WHERE post_id = ?", (post_id,))
                logger.debug(f"  Removed {result.rowcount} existing tags for post {post_id}")
                
                # Add new tags
                for tag_name in tag_names:
                    if not tag_name or not tag_name.strip():
                        continue
                        
                    tag_name = tag_name.strip().lower()
                    logger.debug(f"  Processing tag: {tag_name}")
                    
                    # Create or get tag within the same transaction
                    cursor = await db.execute("SELECT id FROM tags WHERE name = ?", (tag_name,))
                    result = await cursor.fetchone()
                    
                    if result:
                        tag_id = result[0]
                        logger.debug(f"    Found existing tag: {tag_name} (ID: {tag_id})")
                    else:
                        # Create new tag
                        try:
                            cursor = await db.execute(
                                "INSERT INTO tags (name, created_at, post_count) VALUES (?, ?, 0)", 
                                (tag_name, time.time())
                            )
                            tag_id = cursor.lastrowid
                            logger.info(f"    Created new tag: {tag_name} (ID: {tag_id})")
                        except Exception as tag_create_error:
                            logger.error(f"    Failed to create tag {tag_name}: {tag_create_error}")
                            continue
                    
                    if tag_id:
                        try:
                            await db.execute(
                                "INSERT OR IGNORE INTO post_tags (post_id, tag_id, created_at) VALUES (?, ?, ?)", 
                                (post_id, tag_id, time.time())
                            )
                            logger.debug(f"    Associated tag {tag_name} (ID: {tag_id}) with post {post_id}")
                        except Exception as assoc_error:
                            logger.error(f"    Failed to associate tag {tag_name} with post {post_id}: {assoc_error}")
                            continue
                
                # 🎯 CRITICAL: Update tag counts atomically within the same transaction
                logger.debug("🔄 Updating tag counts atomically...")
                await db.execute("""
                    UPDATE tags SET post_count = (
                        SELECT COUNT(DISTINCT pt.post_id) 
                        FROM post_tags pt 
                        WHERE pt.tag_id = tags.id
                    )
                """)
                
                # Commit everything together atomically
                await db.commit()
                
                logger.info(f"✅ Successfully updated tags for post {post_id} with atomic count update")
                return True
                
        except Exception as e:
            logger.error(f"❌ Tag update failed for post {post_id}: {e}")
            return False

    @staticmethod
    async def search_posts_by_tag(tag_name, limit=50, offset=0):
        """🔧 FIXED: Search posts by EXACT tag name"""
        tag_name = tag_name.strip().lower()
        return await DB._execute("""
            SELECT p.*, u.username 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            JOIN post_tags pt ON p.id = pt.post_id 
            JOIN tags t ON pt.tag_id = t.id 
            WHERE t.name = ?
            ORDER BY p.created_at DESC 
            LIMIT ? OFFSET ?
        """, (tag_name, limit, offset), 'all')

    @staticmethod
    async def get_popular_tags(limit=20):
        """🎯 FIXED: Get most popular tags with atomic count update"""
        try:
            # Use the atomic version to ensure accurate counts
            all_tags = await DB.get_all_tags_with_accurate_counts()
            
            # Filter out tags with zero posts and limit
            popular_tags = [tag for tag in all_tags if tag['post_count'] > 0][:limit]
            
            logger.info(f"📈 Retrieved {len(popular_tags)} popular tags (limit: {limit})")
            return popular_tags
            
        except Exception as e:
            logger.error(f"❌ Failed to get popular tags: {e}")
            return []

    # Edit proposals operations
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

# Async password functions
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
        
        # 🆕 NEW: Automatically renew session on authenticated activity
        try:
            new_expiry = await DB.renew_session(token)
            if new_expiry:
                logger.debug(f"Session renewed for user {user['username']} until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_expiry))}")
        except Exception as e:
            logger.error(f"Failed to renew session: {e}")
        
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
                # 🆕 NEW: Automatically renew session on any authenticated activity
                try:
                    new_expiry = await DB.renew_session(token)
                    if new_expiry:
                        logger.debug(f"Session renewed for user {user['username']} until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_expiry))}")
                except Exception as e:
                    logger.error(f"Failed to renew session: {e}")
                    
                request['user'] = user
                request['token'] = token
        return await handler(request)
    return wrapper

# Authentication endpoints
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
        # 🆕 UPDATED: Use 29-day session duration
        expires_at = time.time() + SESSION_DURATION
        await DB.create_session(token, user['id'], expires_at, request.remote, request.headers.get('User-Agent'))
        await DB.update_last_login(user['id'])
        
        logger.info(f"User {username} logged in with 29-day session (expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expires_at))})")
        
        return web.json_response({
            'token': token, 
            'expires_in': SESSION_DURATION,  # 🆕 UPDATED: Return 29-day duration
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
async def post_renew_session(request):
    """🆕 NEW: Dedicated endpoint to renew session on user activity"""
    try:
        user = request['user']
        token = request['token']
        
        # Renew the session
        new_expiry = await DB.renew_session(token)
        if not new_expiry:
            return web.json_response({'error': 'Failed to renew session'}, status=400)
        
        logger.info(f"Session explicitly renewed for user {user['username']} until {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(new_expiry))}")
        
        return web.json_response({
            'message': 'Session renewed successfully',
            'expires_at': new_expiry,
            'expires_in': SESSION_DURATION
        })
        
    except Exception as e:
        logger.error(f"Session renewal error: {e}")
        return web.json_response({'error': 'Session renewal failed'}, status=500)

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

# Posts endpoints
@require_auth
async def post_posts(request):
    """Create a new post with working tags"""
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
        
        # Create post
        post_id = await DB.create_post(user['id'], title, content)
        
        # Process tags
        if tags and isinstance(tags, list):
            valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
            if valid_tags:
                await DB.update_post_tags(post_id, valid_tags)
        
        return web.json_response({
            'message': 'Post created successfully!',
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
    """Get all posts with pagination and tags"""
    try:
        limit = min(int(request.query.get('limit', 10)), 100)
        offset = int(request.query.get('offset', 0))
        user_id = request.query.get('user_id')
        
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
            try:
                tags = await DB.get_tags_by_post(post_dict['id'])
                post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
            except Exception:
                post_dict['tags'] = []
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
    """Get a specific post by ID with tags"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    post = await DB.get_post_by_id(post_id)
    if not post:
        return web.json_response({'error': 'Post not found'}, status=404)
    
    # Add tags
    post_dict = dict(post)
    try:
        tags = await DB.get_tags_by_post(post_dict['id'])
        post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
    except Exception:
        post_dict['tags'] = []
    
    return web.json_response({'post': post_dict})

@require_auth
async def put_posts_id(request):
    """Update a specific post by ID with tags"""
    try:
        post_id = int(request.match_info['id'])
        data = await request.json()
        
        title = str(data.get('title', '')).strip() if 'title' in data else None
        content = str(data.get('content', '')).strip() if 'content' in data else None
        tags = data.get('tags', None)
        
        logger.info(f"Updating post {post_id} with title={bool(title)}, content={bool(content)}, tags={tags}")
        
        # Validate input
        errors = []
        if title is not None and (not title or len(title) > 200):
            errors.append('Invalid title (1-200 chars)')
        if content is not None and (not content or len(content) > 50000):
            errors.append('Invalid content (1-50000 chars)')
        
        if errors:
            logger.warning(f"Validation errors for post {post_id}: {errors}")
            return web.json_response({'error': '; '.join(errors)}, status=400)
        
        user = request['user']
        
        # Update post
        try:
            updated = await DB.update_post(post_id, user['id'], title, content)
            if not updated:
                logger.warning(f"Failed to update post {post_id} for user {user['id']}")
                return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
        except Exception as update_error:
            logger.error(f"Error updating post {post_id}: {update_error}")
            return web.json_response({'error': 'Failed to update post content'}, status=500)
        
        # Update tags if provided
        if tags is not None and isinstance(tags, list):
            try:
                valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
                logger.info(f"Updating tags for post {post_id}: {valid_tags}")
                tag_success = await DB.update_post_tags(post_id, valid_tags)
                if not tag_success:
                    logger.warning(f"Failed to update tags for post {post_id}")
                    # Don't fail the whole request if just tags fail
            except Exception as tag_error:
                logger.error(f"Error updating tags for post {post_id}: {tag_error}")
                # Don't fail the whole request if just tags fail
        
        logger.info(f"Successfully updated post {post_id}")
        return web.json_response({'message': 'Post updated successfully'})
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error updating post: {e}")
        return web.json_response({'error': 'Failed to update post'}, status=500)

@require_auth
async def delete_posts_id(request):
    """Delete a specific post by ID"""
    try:
        post_id = int(request.match_info['id'])
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    
    try:
        user = request['user']
        deleted = await DB.delete_post(post_id, user['id'])
        
        if not deleted:
            return web.json_response({'error': 'Post not found or unauthorized'}, status=404)
        
        return web.json_response({'message': 'Post deleted successfully'})
        
    except Exception as e:
        logger.error(f"Delete post error: {e}")
        return web.json_response({'error': 'Failed to delete post'}, status=500)

@require_auth
async def get_posts_my(request):
    """Get current user's posts with tags"""
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
            try:
                tags = await DB.get_tags_by_post(post_dict['id'])
                post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
            except Exception:
                post_dict['tags'] = []
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

# Comments endpoints (keeping existing working code)
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

# 🎯 FIXED: Tags endpoints with atomic operations
async def get_tags(request):
    """🎯 FIXED: Get all tags with atomic count update - NO RACE CONDITIONS"""
    try:
        # Use the atomic version to get tags with accurate counts
        tags = await DB.get_all_tags_with_accurate_counts()
        
        logger.info(f"📊 Returned {len(tags)} tags with accurate counts")
        
        return web.json_response({
            'tags': tags,
            'count': len(tags)
        })
    except Exception as e:
        logger.error(f"Get tags error: {e}")
        
        # Try fallback approach
        try:
            logger.info("🔄 Using fallback tag retrieval...")
            fallback_tags = await DB._execute("""
                SELECT id, name, created_at, COALESCE(post_count, 0) as post_count 
                FROM tags 
                ORDER BY post_count DESC, name ASC
            """, fetch='all')
            
            # Convert to proper format
            tags_list = []
            for tag in fallback_tags:
                tags_list.append({
                    'id': tag['id'],
                    'name': tag['name'], 
                    'created_at': tag['created_at'],
                    'post_count': tag['post_count'] or 0
                })
            
            return web.json_response({
                'tags': tags_list,
                'count': len(tags_list),
                'fallback': True
            })
        except Exception as fallback_error:
            logger.error(f"Fallback also failed: {fallback_error}")
            return web.json_response({
                'error': 'Failed to retrieve tags',
                'tags': [],
                'count': 0
            }, status=500)

async def get_tags_popular(request):
    """🎯 FIXED: Get popular tags with atomic count update"""
    try:
        limit = min(int(request.query.get('limit', 20)), 50)
        
        # Use the improved version that ensures accurate counts
        tags = await DB.get_popular_tags(limit)
        
        logger.info(f"📈 Returned {len(tags)} popular tags (limit: {limit})")
        
        return web.json_response({
            'tags': tags,
            'count': len(tags)
        })
    except ValueError:
        return web.json_response({'error': 'Invalid limit parameter'}, status=400)
    except Exception as e:
        logger.error(f"Get popular tags error: {e}")
        
        # Try fallback approach
        try:
            logger.info("🔄 Using fallback popular tags retrieval...")
            limit = min(int(request.query.get('limit', 20)), 50)
            
            fallback_tags = await DB._execute("""
                SELECT id, name, created_at, COALESCE(post_count, 0) as post_count 
                FROM tags 
                WHERE COALESCE(post_count, 0) > 0
                ORDER BY post_count DESC, name ASC
                LIMIT ?
            """, (limit,), 'all')
            
            # Convert to proper format
            tags_list = []
            for tag in fallback_tags:
                tags_list.append({
                    'id': tag['id'],
                    'name': tag['name'], 
                    'created_at': tag['created_at'],
                    'post_count': tag['post_count'] or 0
                })
            
            return web.json_response({
                'tags': tags_list,
                'count': len(tags_list),
                'fallback': True
            })
        except Exception as fallback_error:
            logger.error(f"Popular tags fallback failed: {fallback_error}")
            return web.json_response({
                'error': 'Failed to retrieve popular tags',
                'tags': [],
                'count': 0
            }, status=500)

@optional_auth
async def get_tags_name_posts(request):
    """🔧 FIXED: Get posts by exact tag name"""
    try:
        tag_name = request.match_info['name']
        limit = min(int(request.query.get('limit', 10)), 100)
        offset = int(request.query.get('offset', 0))
        
        posts = await DB.search_posts_by_tag(tag_name, limit, offset)
        
        # Add tags to each post
        posts_with_tags = []
        for post in posts:
            post_dict = dict(post)
            try:
                tags = await DB.get_tags_by_post(post_dict['id'])
                post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
            except Exception:
                post_dict['tags'] = []
            posts_with_tags.append(post_dict)
        
        return web.json_response({
            'posts': posts_with_tags,
            'tag_name': tag_name,
            'pagination': {
                'limit': limit,
                'offset': offset,
                'has_more': len(posts) >= limit
            }
        })
    
    except ValueError:
        return web.json_response({'error': 'Invalid pagination parameters'}, status=400)
    except Exception as e:
        logger.error(f"Get posts by tag error: {e}")
        return web.json_response({'error': 'Failed to retrieve posts'}, status=500)

# 🔧 ENHANCED: Search endpoint with custom fuzzy search
@optional_auth
async def get_search(request):
    """🧠 ENHANCED: Search posts with custom backend fuzzy matching"""
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
            try:
                tags = await DB.get_tags_by_post(post_dict['id'])
                post_dict['tags'] = [dict(tag) for tag in tags] if tags else []
            except Exception:
                post_dict['tags'] = []
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

# Keep all other existing endpoints (file upload, proposals, etc.)
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
                    file_path.unlink()
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
            'Cache-Control': 'public, max-age=86400'
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

# Edit proposals endpoints (keeping existing working code)
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

# 🎯 FIXED: Debug endpoint to manually refresh tag counts - WITH ATOMIC OPERATIONS
async def post_debug_refresh_tags(request):
    """🎯 FIXED: Manually refresh tag counts with atomic operations and proper error handling"""
    try:
        logger.info("🔧 Manual tag count refresh requested - USING ATOMIC OPERATIONS")
        
        # Use the atomic version for consistent results
        tags = await DB.get_all_tags_with_accurate_counts()
        
        # Also trigger a manual update for extra safety
        manual_success = await DB.update_tag_counts()
        
        # Get fresh tags after manual update
        if manual_success:
            fresh_tags = await DB.get_all_tags_with_accurate_counts()
            if len(fresh_tags) > len(tags):
                tags = fresh_tags
        
        logger.info(f"🎯 Debug refresh complete: {len(tags)} tags with accurate counts")
        
        return web.json_response({
            'message': 'Tag counts refreshed successfully using atomic operations',
            'tags': tags,
            'debug': 'All tag counts updated atomically - check server logs for detailed information',
            'count': len(tags),
            'manual_update_success': manual_success
        })
            
    except Exception as e:
        logger.error(f"❌ Debug refresh error: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        
        # Try a fallback approach
        try:
            logger.info("🔄 Attempting fallback tag retrieval...")
            fallback_tags = await DB.get_all_tags()
            return web.json_response({
                'message': 'Partial success - used fallback tag retrieval',
                'tags': fallback_tags,
                'debug': f'Primary method failed: {str(e)}, but fallback succeeded',
                'count': len(fallback_tags),
                'error': str(e)
            })
        except Exception as fallback_error:
            logger.error(f"❌ Fallback also failed: {fallback_error}")
            return web.json_response({
                'error': f'Debug refresh failed: {str(e)}. Fallback also failed: {str(fallback_error)}',
                'debug': 'Both primary and fallback methods failed - check server logs'
            }, status=500)

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
        
        # Process tags
        valid_tags = [tag.strip() for tag in tags if isinstance(tag, str) and tag.strip()]
        success = await DB.update_post_tags(post_id, valid_tags)
        
        if success:
            return web.json_response({
                'message': 'Tags updated successfully',
                'tags': valid_tags
            })
        else:
            return web.json_response({'error': 'Failed to update tags'}, status=500)
    
    except ValueError:
        return web.json_response({'error': 'Invalid post ID format'}, status=400)
    except (KeyError, json.JSONDecodeError):
        return web.json_response({'error': 'Invalid request format'}, status=400)
    except Exception as e:
        logger.error(f"Tag update error: {e}")
        return web.json_response({'error': 'Failed to update tags'}, status=500)

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

# Posts parameterized routes
app.router.add_route('GET', '/posts/{id}', get_posts_id)
app.router.add_route('PUT', '/posts/{id}', put_posts_id)
app.router.add_route('DELETE', '/posts/{id}', delete_posts_id)
app.router.add_route('PUT', '/posts/{id}/tags', put_posts_id_tags)

# Comments parameterized routes
app.router.add_route('POST', '/posts/{id}/comments', post_posts_id_comments)
app.router.add_route('GET', '/posts/{id}/comments', get_posts_id_comments)
app.router.add_route('PUT', '/comments/{id}', put_comments_id)
app.router.add_route('DELETE', '/comments/{id}', delete_comments_id)

# Files parameterized routes
app.router.add_route('GET', '/files/{id}', get_files_id)
app.router.add_route('DELETE', '/files/{id}', delete_files_id)

# Tags parameterized routes
app.router.add_route('GET', '/tags/{name}/posts', get_tags_name_posts)

# Edit proposals parameterized routes
app.router.add_route('POST', '/posts/{id}/proposals', post_posts_id_proposals)
app.router.add_route('GET', '/posts/{id}/proposals', get_posts_id_proposals)
app.router.add_route('PUT', '/proposals/{id}/approve', put_proposals_id_approve)
app.router.add_route('PUT', '/proposals/{id}/reject', put_proposals_id_reject)

# Auto-register other routes
excluded_routes = [
    'get_users_id', 'delete_users_id', 'get_posts_id', 'put_posts_id', 'delete_posts_id', 
    'put_posts_id_tags', 'post_posts_id_comments', 'get_posts_id_comments', 
    'put_comments_id', 'delete_comments_id', 'get_files_id', 'delete_files_id',
    'post_posts_id_proposals', 'get_posts_id_proposals', 'put_proposals_id_approve', 
    'put_proposals_id_reject', 'get_tags_name_posts'
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
    print("🧠 CUSTOM ULTRA-FUZZY SEARCH API - NATIVE BACKEND + FIXED TAGS + 29-DAY SESSIONS!")
    print("=" * 80)
    print("🧠 NEW: Custom ultra-fuzzy search with native Levenshtein distance implementation")
    print("🧠 NEW: Zero external dependencies - all fuzzy logic implemented natively")
    print("🧠 NEW: Multiple fuzzy algorithms (exact, partial, word-level, similarity)")
    print("🧠 NEW: Scalable backend fuzzy matching (40% similarity threshold)")
    print("🧠 NEW: Field-weighted scoring with title/tag boosts")
    print("🧠 NEW: Intelligent hybrid search: SQL first, fuzzy enhancement second")
    print("🧠 NEW: Recency bonuses and advanced relevance scoring")
    print("🧠 NEW: Handles thousands of posts efficiently on server-side")
    print("🧠 NEW: Professional-grade string similarity algorithms (ratio, partial, token)")
    print("🧠 NEW: Configurable fuzzy search parameters and weights")
    print("✅ Fixed race condition between tag count update and retrieval")
    print("✅ Post update/delete work without SQL errors")
    print("✅ ATOMIC tag operations - no more inconsistent counts")
    print("✅ Enhanced search includes COMMENTS content!")
    print("✅ Tag search with exact matching")
    print("✅ General search with partial matching")
    print("✅ ROBUST error handling with fallback mechanisms")
    print("✅ Comprehensive logging for debugging")
    print("✅ Database safety checks and table creation")
    print("🆕 NEW: 29-day session expiration for better user experience")
    print("🎯 CRITICAL: All tag operations now use single database transaction")
    print("🎯 CRITICAL: Tag counts are updated and retrieved atomically")
    print("🎯 CRITICAL: No race conditions between separate DB connections")
    print("🎯 CRITICAL: Graceful fallbacks when atomic operations fail")
    print("🧠 CRITICAL: Native fuzzy search scales to thousands of posts")
    print("🧠 CRITICAL: Zero external dependencies - pure Python implementation")
    print("=" * 80)
    
    # Start file watcher for development
    threading.Thread(target=watch_file, daemon=True).start()
    
    # Check for SSL certificates
    cert_file, key_file = check_ssl_certificates()
    
    if cert_file and key_file:
        # HTTPS Production Mode
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_file, key_file)
        
        host = '0.0.0.0'
        port = 8447
        protocol = 'https'
        
        print(f"🔒 SSL certificates found ({cert_file}, {key_file})")
        print(f"🚀 Starting HTTPS API server on {protocol}://{host}:{port}")
        
    else:
        # HTTP Development Mode
        host = 'localhost'
        port = 8080
        protocol = 'http'
        
        print("⚠️  No SSL certificates found - running in HTTP development mode")
        print(f"🚀 Starting HTTP server on {protocol}://{host}:{port}")
    
    print(f"\n🧠 CUSTOM ULTRA-FUZZY SEARCH FEATURES:")
    print(f"  ✅ Native Levenshtein distance implementation - no external libraries!")
    print(f"  • String similarity algorithms: ratio, partial_ratio, token_sort, token_set")
    print(f"  • Field-weighted scoring: title (1.2x), tags (1.3x), content (1.0x), author (0.9x)")
    print(f"  • 40% similarity threshold for permissive matching")
    print(f"  • Intelligent hybrid search: SQL exact matches first, fuzzy enhancement second")
    print(f"  • Scalable search: up to 1000 posts for fuzzy matching")
    print(f"  • Recency bonuses and content length factors")
    print(f"  • Word-level exact and partial matching bonuses")
    print(f"  • Configurable scoring weights and similarity thresholds")
    print(f"  • Examples: 'wologing'→'blogging', 'games'→'game', 'doomsday'→'doom'")
    print(f"  • Zero dependencies - runs on any Python 3.7+ installation")
    
    print(f"\n🎯 CRITICAL TAG FIXES APPLIED:")
    print(f"  • FIXED: Atomic tag operations prevent race conditions")
    print(f"  • FIXED: get_all_tags_with_accurate_counts() uses single DB transaction")
    print(f"  • FIXED: Tag counts updated and retrieved in same atomic operation")
    print(f"  • FIXED: WAL mode enabled for better concurrent access")
    print(f"  • FIXED: update_post_tags() includes atomic count update")
    print(f"  • FIXED: Comprehensive error handling with fallback mechanisms")
    print(f"  • FIXED: Database safety checks prevent table issues")
    print(f"  • FIXED: Debug endpoint with robust error handling")
    print(f"  • FIXED: Multiple fallback approaches for resilience")
    print(f"  🆕 Enhanced search NOW INCLUDES COMMENTS content!")
    print(f"  🎯 All tag endpoints now use atomic operations")
    print(f"  🎯 No more race conditions between DB connections")
    print(f"  🎯 Tag counts are always accurate and consistent")
    print(f"  🎯 Graceful degradation when primary methods fail")
    print(f"  • Check server logs for detailed tag operation information")
    
    print(f"\n🆕 SESSION MANAGEMENT UPDATES:")
    print(f"  • Session duration extended to 29 days ({SESSION_DURATION:,} seconds)")
    print(f"  • 🆕 NEW: Automatic session renewal on user activity")
    print(f"  • 🆕 NEW: Session extended on every authenticated API request")
    print(f"  • 🆕 NEW: Dedicated /renew/session endpoint for explicit renewal")
    print(f"  • Automatic session cleanup every 5 minutes")
    print(f"  • Sessions expire after 29 days of inactivity")
    print(f"  • Login response includes accurate expires_in value")
    print(f"  • Web client will handle expired sessions gracefully")
    print(f"  • Active users never experience session expiry")
    
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