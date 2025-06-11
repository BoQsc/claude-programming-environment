#!/usr/bin/env python3
"""
Advanced Search Engine Module for File Sharing API
Provides sophisticated search capabilities across posts, files, usernames, and file content

FEATURES:
- Full-text search with TF-IDF scoring
- Real-time search suggestions
- File content extraction and indexing
- Fuzzy matching and typo tolerance
- Multi-type search (posts, files, users)
- Relevance scoring and ranking
- Search filters and advanced operators
- Incremental indexing for performance
"""

import re
import math
import asyncio
import logging
import mimetypes
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
import time
import json

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Represents a search result with metadata"""
    id: str
    type: str  # 'post', 'file', 'user'
    title: str
    content: str
    author: str
    score: float
    highlights: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = 0.0


class TextExtractor:
    """Extract text content from various file types"""
    
    # Supported text file extensions
    TEXT_EXTENSIONS = {
        '.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', 
        '.yml', '.yaml', '.ini', '.cfg', '.conf', '.log', '.sql',
        '.sh', '.bat', '.ps1', '.php', '.rb', '.go', '.rs', '.cpp',
        '.c', '.h', '.java', '.cs', '.kt', '.swift', '.r', '.scala',
        '.pl', '.lua', '.vim', '.dockerfile', '.gitignore', '.env',
        '.toml', '.csv', '.tsv', '.properties', '.makefile', '.rake',
        '.gemfile', '.podfile', '.gradle', '.pom', '.cmake', '.m4',
        '.ac', '.am', '.in', '.spec', '.build', '.config', '.settings'
    }
    
    def __init__(self, files_directory: str):
        self.files_directory = Path(files_directory)
    
    def can_extract(self, filename: str, mime_type: str) -> bool:
        """Check if we can extract text from this file"""
        ext = Path(filename).suffix.lower()
        
        # Check by extension
        if ext in self.TEXT_EXTENSIONS:
            return True
        
        # Check by MIME type
        if mime_type.startswith('text/'):
            return True
        
        # Special cases
        if any(x in mime_type for x in ['json', 'xml', 'yaml', 'script']):
            return True
        
        # Check for files without extension that might be text
        if not ext and any(name in filename.lower() for name in [
            'readme', 'license', 'changelog', 'makefile', 'dockerfile',
            'gemfile', 'rakefile', 'procfile', 'requirements'
        ]):
            return True
        
        return False
    
    async def extract_text(self, stored_filename: str, original_filename: str, 
                          mime_type: str, max_size: int = 1024 * 1024) -> Optional[str]:
        """Extract text content from a file"""
        if not self.can_extract(original_filename, mime_type):
            return None
        
        file_path = self.files_directory / stored_filename
        
        if not file_path.exists():
            logger.warning(f"File not found for text extraction: {file_path}")
            return None
        
        # Check file size
        try:
            file_size = file_path.stat().st_size
            if file_size > max_size:
                logger.info(f"File too large for text extraction: {file_path} ({file_size} bytes)")
                return None
            
            if file_size == 0:
                logger.info(f"Empty file, skipping text extraction: {file_path}")
                return None
        except OSError as e:
            logger.warning(f"Could not get file size for {file_path}: {e}")
            return None
        
        try:
            # Try different encodings
            encodings = ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252', 'ascii']
            
            for encoding in encodings:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    
                    # Basic validation - check if content seems like text
                    if self._is_likely_text(content):
                        # Clean and normalize the content
                        content = self._clean_text(content)
                        if content:  # Only return non-empty content
                            logger.debug(f"Successfully extracted {len(content)} characters from {original_filename}")
                            return content
                    else:
                        logger.debug(f"File content doesn't appear to be text: {original_filename}")
                        return None
                    
                except UnicodeDecodeError:
                    continue
                except Exception as e:
                    logger.debug(f"Error reading file {file_path} with {encoding}: {e}")
                    continue
            
            logger.debug(f"Could not decode file with any encoding: {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting text from {file_path}: {e}")
            return None
    
    def _is_likely_text(self, content: str) -> bool:
        """Check if content appears to be text (not binary data)"""
        if not content:
            return False
        
        # Check for too many null bytes (indicates binary)
        null_ratio = content.count('\x00') / len(content)
        if null_ratio > 0.1:  # More than 10% null bytes
            return False
        
        # Check for reasonable ratio of printable characters
        printable_chars = sum(1 for c in content if c.isprintable() or c in '\n\r\t')
        printable_ratio = printable_chars / len(content)
        
        return printable_ratio > 0.7  # At least 70% printable characters
    
    def _clean_text(self, text: str) -> str:
        """Clean and normalize extracted text"""
        if not text:
            return ""
        
        # Remove excessive whitespace but preserve some structure
        # Replace multiple spaces with single space
        text = re.sub(r' {2,}', ' ', text)
        
        # Replace multiple newlines with double newline (paragraph break)
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Remove control characters but keep newlines, tabs, and carriage returns
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]', '', text)
        
        # Limit length to prevent memory issues
        max_length = 100000  # 100KB of text
        if len(text) > max_length:
            text = text[:max_length] + "\n... [truncated]"
        
        return text.strip()


class SearchIndex:
    """In-memory search index with TF-IDF scoring"""
    
    def __init__(self):
        self.documents: Dict[str, Dict] = {}  # doc_id -> document data
        self.term_frequencies: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.document_frequencies: Dict[str, int] = defaultdict(int)
        self.total_documents = 0
        self.last_updated = time.time()
        
        # Stop words - common words to ignore in search
        self.stop_words = {
            'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
            'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have',
            'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should',
            'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'i',
            'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'
        }
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into searchable terms"""
        if not text:
            return []
        
        # Convert to lowercase
        text = text.lower()
        
        # Extract words, emails, file extensions, and code-like patterns
        patterns = [
            r'\b\w+(?:\.\w+)*@\w+(?:\.\w+)+\b',  # Email addresses
            r'\b\w+\.\w{2,4}\b',  # File extensions
            r'\b\w+::\w+\b',  # Namespaced identifiers (e.g., Module::Class)
            r'\b\w+\.\w+\b',  # Dotted identifiers (e.g., obj.method)
            r'\b\w{2,}\b'  # Regular words (2+ characters)
        ]
        
        tokens = []
        for pattern in patterns:
            tokens.extend(re.findall(pattern, text))
        
        # Clean and filter tokens
        cleaned_tokens = []
        for token in tokens:
            # Remove very short tokens and numbers-only tokens
            if len(token) >= 2 and not token.isdigit():
                # Remove stop words
                if token not in self.stop_words:
                    cleaned_tokens.append(token)
        
        return cleaned_tokens
    
    def add_document(self, doc_id: str, doc_type: str, title: str, 
                    content: str, author: str, metadata: Dict = None):
        """Add or update a document in the index"""
        # Remove existing document if it exists
        if doc_id in self.documents:
            self.remove_document(doc_id)
        
        # Combine all searchable text
        searchable_text = f"{title} {content} {author}"
        if metadata:
            # Add searchable metadata
            tags = metadata.get('tags', [])
            if tags:
                searchable_text += " " + " ".join(str(tag) for tag in tags)
            
            filename = metadata.get('filename', '')
            if filename:
                searchable_text += " " + filename
            
            # Add other searchable metadata
            for key in ['description', 'mime_type']:
                value = metadata.get(key, '')
                if value:
                    searchable_text += " " + str(value)
        
        # Tokenize
        tokens = self._tokenize(searchable_text)
        
        if not tokens:
            logger.debug(f"No tokens extracted for document {doc_id}")
            return
        
        # Store document
        self.documents[doc_id] = {
            'type': doc_type,
            'title': title,
            'content': content,
            'author': author,
            'metadata': metadata or {},
            'tokens': tokens,
            'created_at': metadata.get('created_at', time.time()) if metadata else time.time()
        }
        
        # Update term frequencies
        token_counts = Counter(tokens)
        for token, count in token_counts.items():
            # Only count if this is a new document for this term
            if doc_id not in self.term_frequencies[token]:
                self.document_frequencies[token] += 1
            
            self.term_frequencies[token][doc_id] = count
        
        self.total_documents += 1
        self.last_updated = time.time()
        
        logger.debug(f"Indexed document {doc_id} ({doc_type}) with {len(tokens)} tokens")
    
    def remove_document(self, doc_id: str):
        """Remove a document from the index"""
        if doc_id not in self.documents:
            return
        
        doc = self.documents[doc_id]
        tokens = set(doc['tokens'])  # Use set to avoid duplicates
        
        # Update document frequencies
        for token in tokens:
            if doc_id in self.term_frequencies[token]:
                del self.term_frequencies[token][doc_id]
                self.document_frequencies[token] -= 1
                
                # Clean up empty entries
                if self.document_frequencies[token] <= 0:
                    del self.document_frequencies[token]
                if not self.term_frequencies[token]:
                    del self.term_frequencies[token]
        
        del self.documents[doc_id]
        self.total_documents -= 1
        self.last_updated = time.time()
        
        logger.debug(f"Removed document {doc_id} from index")
    
    def search(self, query: str, limit: int = 50, doc_types: List[str] = None,
              min_score: float = 0.01) -> List[SearchResult]:
        """Search the index and return ranked results"""
        if not query.strip():
            return []
        
        # Handle wildcard queries
        if query.strip() == '*':
            return self._get_all_documents(limit, doc_types)
        
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []
        
        # Calculate scores for all documents
        scores = defaultdict(float)
        
        for token in query_tokens:
            if token not in self.term_frequencies:
                continue
            
            # Calculate IDF for this term
            df = self.document_frequencies[token]
            if df == 0:
                continue
            
            idf = math.log(self.total_documents / df)
            
            # Score documents containing this term
            for doc_id, tf in self.term_frequencies[token].items():
                # Apply type filter
                if doc_types and self.documents[doc_id]['type'] not in doc_types:
                    continue
                
                # TF-IDF score with smoothing
                tf_score = 1 + math.log(tf) if tf > 0 else 0
                scores[doc_id] += tf_score * idf
        
        # Boost scores for title matches
        for doc_id, score in list(scores.items()):
            doc = self.documents[doc_id]
            title_tokens = self._tokenize(doc['title'])
            
            # Check for query tokens in title
            title_matches = sum(1 for token in query_tokens if token in title_tokens)
            if title_matches > 0:
                # Boost score by 50% for each title match
                scores[doc_id] += score * 0.5 * title_matches
        
        # Convert to SearchResult objects
        results = []
        for doc_id, score in scores.items():
            if score < min_score:
                continue
            
            doc = self.documents[doc_id]
            
            # Generate highlights
            highlights = self._generate_highlights(doc, query_tokens)
            
            result = SearchResult(
                id=doc_id,
                type=doc['type'],
                title=doc['title'],
                content=doc['content'][:500],  # Truncate long content
                author=doc['author'],
                score=score,
                highlights=highlights,
                metadata=doc['metadata'],
                created_at=doc['created_at']
            )
            results.append(result)
        
        # Sort by score (descending) and recency for ties
        results.sort(key=lambda x: (x.score, x.created_at), reverse=True)
        
        return results[:limit]
    
    def _get_all_documents(self, limit: int, doc_types: List[str] = None) -> List[SearchResult]:
        """Get all documents (for wildcard queries)"""
        results = []
        
        for doc_id, doc in self.documents.items():
            # Apply type filter
            if doc_types and doc['type'] not in doc_types:
                continue
            
            result = SearchResult(
                id=doc_id,
                type=doc['type'],
                title=doc['title'],
                content=doc['content'][:500],
                author=doc['author'],
                score=1.0,  # Equal score for all
                highlights=[],
                metadata=doc['metadata'],
                created_at=doc['created_at']
            )
            results.append(result)
        
        # Sort by recency for wildcard queries
        results.sort(key=lambda x: x.created_at, reverse=True)
        
        return results[:limit]
    
    def _generate_highlights(self, doc: Dict, query_tokens: List[str]) -> List[str]:
        """Generate highlighted snippets for search results"""
        content = doc['content']
        title = doc['title']
        
        highlights = []
        
        # Search in title
        title_lower = title.lower()
        for token in query_tokens:
            if token in title_lower:
                highlighted_title = self._highlight_text(title, token, 100)
                if highlighted_title and highlighted_title not in highlights:
                    highlights.append(highlighted_title)
        
        # Search in content
        if content:
            content_lower = content.lower()
            for token in query_tokens:
                if token in content_lower:
                    # Find context around the match
                    snippet = self._extract_snippet(content, token, 150)
                    if snippet and snippet not in highlights:
                        highlights.append(snippet)
                        
                        # Limit to prevent too many highlights
                        if len(highlights) >= 3:
                            break
        
        return highlights[:3]  # Limit to 3 highlights
    
    def _highlight_text(self, text: str, term: str, max_length: int = 150) -> str:
        """Highlight search term in text"""
        if not text or not term:
            return ""
        
        # Simple case-insensitive highlighting
        pattern = re.compile(re.escape(term), re.IGNORECASE)
        highlighted = pattern.sub(f"**{term}**", text)
        
        if len(highlighted) > max_length:
            highlighted = highlighted[:max_length] + "..."
        
        return highlighted
    
    def _extract_snippet(self, text: str, term: str, context_length: int = 150) -> str:
        """Extract a snippet of text around the search term"""
        if not text or not term:
            return ""
        
        text_lower = text.lower()
        term_lower = term.lower()
        
        pos = text_lower.find(term_lower)
        if pos == -1:
            return ""
        
        # Find start and end positions
        start = max(0, pos - context_length // 2)
        end = min(len(text), pos + len(term) + context_length // 2)
        
        # Try to break on word boundaries
        if start > 0:
            # Find the next space after start
            space_pos = text.find(' ', start)
            if space_pos != -1 and space_pos - start < 20:
                start = space_pos + 1
        
        if end < len(text):
            # Find the previous space before end
            space_pos = text.rfind(' ', 0, end)
            if space_pos != -1 and end - space_pos < 20:
                end = space_pos
        
        snippet = text[start:end]
        
        # Add ellipsis if needed
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        
        # Highlight the term
        snippet = self._highlight_text(snippet, term, len(snippet) + 20)
        
        return snippet
    
    def get_suggestions(self, query: str, limit: int = 10) -> List[str]:
        """Get search suggestions based on partial query"""
        if not query.strip() or len(query.strip()) < 2:
            return []
        
        query = query.lower().strip()
        suggestions = set()
        
        # Look for terms that start with the query
        for term in self.term_frequencies.keys():
            if term.startswith(query) and len(term) > len(query):
                suggestions.add(term)
                if len(suggestions) >= limit * 2:  # Get extra to filter later
                    break
        
        # Look for terms that contain the query
        if len(suggestions) < limit:
            for term in self.term_frequencies.keys():
                if query in term and term not in suggestions and len(term) > 2:
                    suggestions.add(term)
                    if len(suggestions) >= limit * 2:
                        break
        
        # Sort suggestions by frequency (popularity)
        suggestion_list = list(suggestions)
        suggestion_list.sort(key=lambda term: self.document_frequencies.get(term, 0), reverse=True)
        
        return suggestion_list[:limit]


class AdvancedSearchEngine:
    """Main search engine class"""
    
    def __init__(self, db, files_directory: str):
        self.db = db
        self.index = SearchIndex()
        self.text_extractor = TextExtractor(files_directory)
        self.indexing_in_progress = False
        self.last_full_index = 0
        
    async def initialize(self):
        """Initialize the search engine and build initial index"""
        logger.info("Initializing search engine...")
        await self.rebuild_index()
        logger.info("Search engine initialized successfully")
    
    async def rebuild_index(self):
        """Rebuild the entire search index"""
        if self.indexing_in_progress:
            logger.warning("Indexing already in progress")
            return
        
        self.indexing_in_progress = True
        start_time = time.time()
        
        try:
            logger.info("Rebuilding search index...")
            
            # Clear existing index
            self.index = SearchIndex()
            
            # Index posts
            await self._index_posts()
            
            # Index files
            await self._index_files()
            
            # Index users
            await self._index_users()
            
            self.last_full_index = time.time()
            duration = time.time() - start_time
            
            logger.info(f"Search index rebuilt in {duration:.2f}s. "
                       f"Indexed {self.index.total_documents} documents.")
            
        except Exception as e:
            logger.error(f"Error rebuilding search index: {e}")
            raise
        finally:
            self.indexing_in_progress = False
    
    async def _index_posts(self):
        """Index all posts"""
        try:
            posts_collection = await self.db.get_collection('posts')
            all_posts = await posts_collection.find()
            
            indexed_count = 0
            for post in all_posts:
                try:
                    post_id = post['_key']
                    title = post.get('title', '')
                    content = post.get('content', '')
                    author = post.get('author_username', '')
                    tags = post.get('tags', [])
                    created_at = post.get('created_at', time.time())
                    
                    metadata = {
                        'tags': tags,
                        'created_at': created_at,
                        'views': post.get('views', 0),
                        'likes': post.get('likes', 0),
                        'published': post.get('is_published', True)
                    }
                    
                    self.index.add_document(
                        doc_id=post_id,
                        doc_type='post',
                        title=title,
                        content=content,
                        author=author,
                        metadata=metadata
                    )
                    indexed_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to index post {post.get('_key', 'unknown')}: {e}")
            
            logger.info(f"Indexed {indexed_count} posts")
            
        except Exception as e:
            logger.error(f"Error indexing posts: {e}")
    
    async def _index_files(self):
        """Index all files and their content"""
        try:
            files_collection = await self.db.get_collection('files')
            all_files = await files_collection.find()
            
            indexed_count = 0
            content_extracted_count = 0
            
            for file_record in all_files:
                try:
                    file_id = file_record['_key']
                    filename = file_record.get('original_filename', '')
                    stored_filename = file_record.get('stored_filename', '')
                    description = file_record.get('description', '')
                    tags = file_record.get('tags', [])
                    author = file_record.get('owner_username', '')
                    mime_type = file_record.get('mime_type', '')
                    created_at = file_record.get('uploaded_at', time.time())
                    
                    # Start with filename and description as content
                    content = description
                    
                    # Try to extract file content for text files
                    try:
                        extracted_text = await self.text_extractor.extract_text(
                            stored_filename, filename, mime_type
                        )
                        if extracted_text:
                            content = f"{description} {extracted_text}".strip()
                            content_extracted_count += 1
                    except Exception as e:
                        logger.debug(f"Failed to extract content from {filename}: {e}")
                    
                    metadata = {
                        'filename': filename,
                        'tags': tags,
                        'created_at': created_at,
                        'file_size': file_record.get('file_size', 0),
                        'mime_type': mime_type,
                        'downloads': file_record.get('downloads', 0),
                        'views': file_record.get('views', 0),
                        'public': file_record.get('is_public', False),
                        'description': description
                    }
                    
                    self.index.add_document(
                        doc_id=file_id,
                        doc_type='file',
                        title=filename,
                        content=content,
                        author=author,
                        metadata=metadata
                    )
                    
                    indexed_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to index file {file_record.get('_key', 'unknown')}: {e}")
            
            logger.info(f"Indexed {indexed_count} files, extracted content from {content_extracted_count} text files")
            
        except Exception as e:
            logger.error(f"Error indexing files: {e}")
    
    async def _index_users(self):
        """Index user profiles"""
        try:
            users_collection = await self.db.get_collection('users')
            all_users = await users_collection.find()
            
            indexed_count = 0
            for user in all_users:
                try:
                    user_id = user['_key']
                    username = user.get('username', '')
                    email = user.get('email', '')
                    created_at = user.get('created_at', time.time())
                    
                    # Use email as content for search
                    content = email
                    
                    metadata = {
                        'created_at': created_at,
                        'active': user.get('is_active', True),
                        'last_login': user.get('last_login')
                    }
                    
                    self.index.add_document(
                        doc_id=user_id,
                        doc_type='user',
                        title=username,
                        content=content,
                        author=username,
                        metadata=metadata
                    )
                    indexed_count += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to index user {user.get('_key', 'unknown')}: {e}")
            
            logger.info(f"Indexed {indexed_count} users")
            
        except Exception as e:
            logger.error(f"Error indexing users: {e}")
    
    async def search(self, query: str, filters: Dict[str, Any] = None, 
                    limit: int = 50) -> List[SearchResult]:
        """Perform a search query"""
        if not query.strip():
            return []
        
        # Apply filters
        doc_types = None
        if filters:
            if 'types' in filters:
                doc_types = filters['types'] if isinstance(filters['types'], list) else [filters['types']]
        
        # Perform search
        results = self.index.search(
            query=query,
            limit=limit,
            doc_types=doc_types
        )
        
        # Apply additional filters if needed
        if filters:
            results = self._apply_filters(results, filters)
        
        return results
    
    def _apply_filters(self, results: List[SearchResult], filters: Dict[str, Any]) -> List[SearchResult]:
        """Apply additional filters to search results"""
        filtered_results = results
        
        # Filter by author
        if 'author' in filters and filters['author']:
            author_filter = filters['author'].lower()
            filtered_results = [r for r in filtered_results 
                              if author_filter in r.author.lower()]
        
        # Filter by date range
        if 'date_from' in filters or 'date_to' in filters:
            date_from = filters.get('date_from', 0)
            date_to = filters.get('date_to', time.time())
            filtered_results = [r for r in filtered_results 
                              if date_from <= r.created_at <= date_to]
        
        # Filter by minimum score
        if 'min_score' in filters:
            min_score = filters['min_score']
            filtered_results = [r for r in filtered_results if r.score >= min_score]
        
        return filtered_results
    
    async def get_suggestions(self, query: str, limit: int = 10) -> List[str]:
        """Get search suggestions"""
        return self.index.get_suggestions(query, limit)
    
    async def add_document(self, doc_id: str, doc_type: str, title: str,
                          content: str, author: str, metadata: Dict = None):
        """Add a single document to the index"""
        try:
            self.index.add_document(doc_id, doc_type, title, content, author, metadata)
        except Exception as e:
            logger.error(f"Failed to add document {doc_id} to search index: {e}")
    
    async def remove_document(self, doc_id: str):
        """Remove a document from the index"""
        try:
            self.index.remove_document(doc_id)
        except Exception as e:
            logger.error(f"Failed to remove document {doc_id} from search index: {e}")
    
    async def update_document(self, doc_id: str, doc_type: str, title: str,
                             content: str, author: str, metadata: Dict = None):
        """Update a document in the index"""
        try:
            # Remove and re-add (simpler than partial updates)
            self.index.remove_document(doc_id)
            self.index.add_document(doc_id, doc_type, title, content, author, metadata)
        except Exception as e:
            logger.error(f"Failed to update document {doc_id} in search index: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get search engine statistics"""
        return {
            'total_documents': self.index.total_documents,
            'total_terms': len(self.index.term_frequencies),
            'last_updated': self.index.last_updated,
            'last_full_index': self.last_full_index,
            'indexing_in_progress': self.indexing_in_progress,
            'types_breakdown': self._get_type_breakdown(),
            'supported_file_types': list(self.text_extractor.TEXT_EXTENSIONS)
        }
    
    def _get_type_breakdown(self) -> Dict[str, int]:
        """Get breakdown of documents by type"""
        breakdown = defaultdict(int)
        for doc in self.index.documents.values():
            breakdown[doc['type']] += 1
        return dict(breakdown)


# Factory function
def create_search_engine(db, files_directory: str) -> AdvancedSearchEngine:
    """Create and return a search engine instance"""
    return AdvancedSearchEngine(db, files_directory)
