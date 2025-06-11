#!/usr/bin/env python3
"""
Enhanced Advanced Search Engine Module with Partial Matching Support
Provides sophisticated search capabilities with partial word matching, prefix matching, and fuzzy matching

ENHANCED FEATURES:
- Partial word matching (e.g., "pyth" finds "python")
- Prefix matching (e.g., "java" finds "javascript")
- Substring matching (e.g., "script" finds "javascript")
- Enhanced search suggestions with partial matching
- Improved relevance scoring with similarity multipliers
- Better highlighting with partial match detection
- All original features preserved and enhanced
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


class EnhancedSearchIndex:
    """Enhanced search index with partial matching, fuzzy search, and improved relevance scoring"""
    
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
    
    def _find_matching_terms(self, query_token: str, match_type: str = "auto") -> List[Tuple[str, float]]:
        """
        Find terms that match the query token with different strategies
        Returns list of (term, similarity_score) tuples
        """
        matches = []
        query_len = len(query_token)
        
        # Auto-detect best matching strategy based on query length
        if match_type == "auto":
            if query_len <= 2:
                match_type = "prefix"
            elif query_len <= 4:
                match_type = "prefix_and_substring"
            else:
                match_type = "all"
        
        for term in self.term_frequencies.keys():
            similarity = 0.0
            term_len = len(term)
            
            if match_type == "exact":
                # Exact matching only
                if term == query_token:
                    similarity = 1.0
            
            elif match_type == "prefix":
                # Prefix matching with length-based scoring
                if term.startswith(query_token):
                    if term == query_token:
                        similarity = 1.0  # Exact match gets highest score
                    else:
                        # Score based on how much of the term the query covers
                        similarity = 0.8 + 0.2 * (query_len / term_len)
            
            elif match_type == "prefix_and_substring":
                # Prefix matching (higher score) + substring matching
                if term.startswith(query_token):
                    if term == query_token:
                        similarity = 1.0
                    else:
                        similarity = 0.8 + 0.15 * (query_len / term_len)
                elif query_token in term:
                    # Substring match gets lower score
                    similarity = 0.6 + 0.1 * (query_len / term_len)
            
            elif match_type == "all":
                # Exact + prefix + substring + fuzzy
                if term == query_token:
                    similarity = 1.0
                elif term.startswith(query_token):
                    similarity = 0.8 + 0.15 * (query_len / term_len)
                elif query_token in term:
                    similarity = 0.6 + 0.1 * (query_len / term_len)
                elif query_len >= 3 and self._fuzzy_match(query_token, term):
                    # Simple fuzzy matching for typos
                    similarity = 0.3 + 0.2 * self._calculate_similarity(query_token, term)
            
            if similarity > 0:
                matches.append((term, similarity))
        
        # Sort by similarity score (descending) and limit results
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:50]  # Limit to prevent performance issues
    
    def _fuzzy_match(self, query: str, term: str, max_edits: int = 2) -> bool:
        """Simple fuzzy matching using edit distance"""
        if abs(len(query) - len(term)) > max_edits * 2:
            return False
        
        return self._edit_distance(query, term) <= max_edits
    
    def _edit_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance (Levenshtein distance)"""
        if len(s1) > len(s2):
            s1, s2 = s2, s1
        
        distances = range(len(s1) + 1)
        for i2, c2 in enumerate(s2):
            distances_ = [i2 + 1]
            for i1, c1 in enumerate(s1):
                if c1 == c2:
                    distances_.append(distances[i1])
                else:
                    distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
            distances = distances_
        
        return distances[-1]
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity ratio between two strings"""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        
        edit_dist = self._edit_distance(s1, s2)
        return 1.0 - (edit_dist / max_len)
    
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
        """Enhanced search with partial matching support"""
        if not query.strip():
            return []
        
        # Handle wildcard queries
        if query.strip() == '*':
            return self._get_all_documents(limit, doc_types)
        
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return []
        
        # Calculate scores for all documents with enhanced partial matching
        scores = defaultdict(float)
        
        for query_token in query_tokens:
            # Find matching terms (exact, prefix, substring, fuzzy)
            matching_terms = self._find_matching_terms(query_token)
            
            for term, similarity_score in matching_terms:
                if term not in self.term_frequencies:
                    continue
                
                # Calculate IDF for this term
                df = self.document_frequencies[term]
                if df == 0:
                    continue
                
                idf = math.log(self.total_documents / df)
                
                # Score documents containing this term
                for doc_id, tf in self.term_frequencies[term].items():
                    # Apply type filter
                    if doc_types and self.documents[doc_id]['type'] not in doc_types:
                        continue
                    
                    # TF-IDF score with similarity multiplier
                    tf_score = 1 + math.log(tf) if tf > 0 else 0
                    term_score = tf_score * idf * similarity_score
                    scores[doc_id] += term_score
        
        # Enhanced title boost with partial matching
        for doc_id, score in list(scores.items()):
            doc = self.documents[doc_id]
            title_tokens = self._tokenize(doc['title'])
            
            # Check for partial matches in title
            title_boost = 0
            for query_token in query_tokens:
                for title_token in title_tokens:
                    if title_token == query_token:
                        title_boost += 1.0  # Exact title match
                    elif title_token.startswith(query_token):
                        title_boost += 0.8  # Prefix title match
                    elif query_token in title_token:
                        title_boost += 0.6  # Substring title match
                    elif len(query_token) >= 3 and self._fuzzy_match(query_token, title_token):
                        title_boost += 0.4  # Fuzzy title match
            
            if title_boost > 0:
                scores[doc_id] += score * 0.5 * title_boost
        
        # Convert to SearchResult objects
        results = []
        for doc_id, score in scores.items():
            if score < min_score:
                continue
            
            doc = self.documents[doc_id]
            
            # Generate highlights with enhanced partial matching
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
        """Generate highlighted snippets with enhanced partial matching"""
        content = doc['content']
        title = doc['title']
        
        highlights = []
        
        # Search in title with partial matching
        title_lower = title.lower()
        for token in query_tokens:
            if self._find_partial_match_in_text(title_lower, token):
                highlighted_title = self._highlight_text_partial(title, token, 100)
                if highlighted_title and highlighted_title not in highlights:
                    highlights.append(highlighted_title)
        
        # Search in content with partial matching
        if content:
            content_lower = content.lower()
            for token in query_tokens:
                if self._find_partial_match_in_text(content_lower, token):
                    snippet = self._extract_snippet_partial(content, token, 150)
                    if snippet and snippet not in highlights:
                        highlights.append(snippet)
                        
                        # Limit to prevent too many highlights
                        if len(highlights) >= 3:
                            break
        
        return highlights[:3]  # Limit to 3 highlights
    
    def _find_partial_match_in_text(self, text: str, token: str) -> bool:
        """Check if token has partial matches in text"""
        # Exact match
        if token in text:
            return True
        
        # Word boundary matches for partial tokens
        words = re.findall(r'\w+', text)
        for word in words:
            if word.startswith(token) or token in word:
                return True
            # Add fuzzy matching for longer tokens
            if len(token) >= 3 and self._fuzzy_match(token, word):
                return True
        
        return False
    
    def _highlight_text_partial(self, text: str, term: str, max_length: int = 150) -> str:
        """Highlight search term with enhanced partial matching"""
        if not text or not term:
            return ""
        
        # Find the best match in the text
        text_lower = text.lower()
        term_lower = term.lower()
        
        # Try exact match first
        if term_lower in text_lower:
            pattern = re.compile(re.escape(term_lower), re.IGNORECASE)
            highlighted = pattern.sub(f"**{term}**", text)
        else:
            # Try partial word matching
            words = re.findall(r'\w+', text)
            highlighted = text
            best_match = None
            best_score = 0
            
            for word in words:
                word_lower = word.lower()
                score = 0
                
                if word_lower.startswith(term_lower):
                    score = 0.8 + 0.2 * (len(term_lower) / len(word_lower))
                elif term_lower in word_lower:
                    score = 0.6 + 0.1 * (len(term_lower) / len(word_lower))
                elif len(term_lower) >= 3 and self._fuzzy_match(term_lower, word_lower):
                    score = 0.4 * self._calculate_similarity(term_lower, word_lower)
                
                if score > best_score:
                    best_score = score
                    best_match = word
            
            if best_match:
                # Highlight the best matching word
                pattern = re.compile(r'\b' + re.escape(best_match) + r'\b', re.IGNORECASE)
                highlighted = pattern.sub(f"**{best_match}**", highlighted)
        
        if len(highlighted) > max_length:
            highlighted = highlighted[:max_length] + "..."
        
        return highlighted
    
    def _extract_snippet_partial(self, text: str, term: str, context_length: int = 150) -> str:
        """Extract a snippet of text around the search term with partial matching"""
        if not text or not term:
            return ""
        
        text_lower = text.lower()
        term_lower = term.lower()
        
        # Find best match position
        pos = -1
        match_word = term
        
        # Try exact match first
        if term_lower in text_lower:
            pos = text_lower.find(term_lower)
        else:
            # Try word-based partial matching
            words = re.finditer(r'\w+', text)
            best_score = 0
            
            for match in words:
                word = match.group().lower()
                score = 0
                
                if word.startswith(term_lower):
                    score = 0.8
                elif term_lower in word:
                    score = 0.6
                elif len(term_lower) >= 3 and self._fuzzy_match(term_lower, word):
                    score = 0.4
                
                if score > best_score:
                    best_score = score
                    pos = match.start()
                    match_word = match.group()
        
        if pos == -1:
            return ""
        
        # Find start and end positions for context
        start = max(0, pos - context_length // 2)
        end = min(len(text), pos + len(match_word) + context_length // 2)
        
        # Try to break on word boundaries
        if start > 0:
            space_pos = text.find(' ', start)
            if space_pos != -1 and space_pos - start < 20:
                start = space_pos + 1
        
        if end < len(text):
            space_pos = text.rfind(' ', 0, end)
            if space_pos != -1 and end - space_pos < 20:
                end = space_pos
        
        snippet = text[start:end]
        
        # Add ellipsis if needed
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."
        
        # Highlight the match
        snippet = self._highlight_text_partial(snippet, term, len(snippet) + 20)
        
        return snippet
    
    def get_suggestions(self, query: str, limit: int = 10) -> List[str]:
        """Get enhanced search suggestions with partial matching"""
        if not query.strip() or len(query.strip()) < 2:
            return []
        
        query = query.lower().strip()
        
        # Get matching terms with scores
        matching_terms = self._find_matching_terms(query, "prefix_and_substring")
        
        # Sort by frequency and similarity
        scored_suggestions = []
        for term, similarity in matching_terms:
            frequency = self.document_frequencies.get(term, 0)
            # Combined score: similarity * log(frequency + 1)
            score = similarity * math.log(frequency + 1)
            scored_suggestions.append((term, score))
        
        # Sort by score and take top suggestions
        scored_suggestions.sort(key=lambda x: x[1], reverse=True)
        suggestions = [term for term, score in scored_suggestions[:limit]]
        
        return suggestions


class AdvancedSearchEngine:
    """Main search engine class with enhanced partial matching capabilities"""
    
    def __init__(self, db, files_directory: str):
        self.db = db
        self.index = EnhancedSearchIndex()  # Use enhanced index
        self.text_extractor = TextExtractor(files_directory)
        self.indexing_in_progress = False
        self.last_full_index = 0
        
    async def initialize(self):
        """Initialize the search engine and build initial index"""
        logger.info("Initializing enhanced search engine with partial matching support...")
        await self.rebuild_index()
        logger.info("Enhanced search engine initialized successfully!")
    
    async def rebuild_index(self):
        """Rebuild the entire search index"""
        if self.indexing_in_progress:
            logger.warning("Indexing already in progress")
            return
        
        self.indexing_in_progress = True
        start_time = time.time()
        
        try:
            logger.info("Rebuilding search index with enhanced partial matching...")
            
            # Clear existing index
            self.index = EnhancedSearchIndex()
            
            # Index posts
            await self._index_posts()
            
            # Index files
            await self._index_files()
            
            # Index users
            await self._index_users()
            
            self.last_full_index = time.time()
            duration = time.time() - start_time
            
            logger.info(f"Enhanced search index rebuilt in {duration:.2f}s. "
                       f"Indexed {self.index.total_documents} documents with partial matching support.")
            
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
            
            logger.info(f"Indexed {indexed_count} posts with enhanced search capabilities")
            
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
            
            logger.info(f"Indexed {indexed_count} files with enhanced search, "
                       f"extracted content from {content_extracted_count} text files")
            
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
            
            logger.info(f"Indexed {indexed_count} users with enhanced search")
            
        except Exception as e:
            logger.error(f"Error indexing users: {e}")
    
    async def search(self, query: str, filters: Dict[str, Any] = None, 
                    limit: int = 50) -> List[SearchResult]:
        """Perform an enhanced search query with partial matching"""
        if not query.strip():
            return []
        
        # Apply filters
        doc_types = None
        if filters:
            if 'types' in filters:
                doc_types = filters['types'] if isinstance(filters['types'], list) else [filters['types']]
        
        # Perform enhanced search
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
        """Get enhanced search suggestions with partial matching"""
        return self.index.get_suggestions(query, limit)
    
    async def add_document(self, doc_id: str, doc_type: str, title: str,
                          content: str, author: str, metadata: Dict = None):
        """Add a single document to the enhanced index"""
        try:
            self.index.add_document(doc_id, doc_type, title, content, author, metadata)
        except Exception as e:
            logger.error(f"Failed to add document {doc_id} to enhanced search index: {e}")
    
    async def remove_document(self, doc_id: str):
        """Remove a document from the enhanced index"""
        try:
            self.index.remove_document(doc_id)
        except Exception as e:
            logger.error(f"Failed to remove document {doc_id} from enhanced search index: {e}")
    
    async def update_document(self, doc_id: str, doc_type: str, title: str,
                             content: str, author: str, metadata: Dict = None):
        """Update a document in the enhanced index"""
        try:
            # Remove and re-add (simpler than partial updates)
            self.index.remove_document(doc_id)
            self.index.add_document(doc_id, doc_type, title, content, author, metadata)
        except Exception as e:
            logger.error(f"Failed to update document {doc_id} in enhanced search index: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get enhanced search engine statistics"""
        return {
            'total_documents': self.index.total_documents,
            'total_terms': len(self.index.term_frequencies),
            'last_updated': self.index.last_updated,
            'last_full_index': self.last_full_index,
            'indexing_in_progress': self.indexing_in_progress,
            'types_breakdown': self._get_type_breakdown(),
            'supported_file_types': list(self.text_extractor.TEXT_EXTENSIONS),
            'enhanced_features': [
                'Partial word matching',
                'Prefix matching',
                'Substring matching',
                'Fuzzy matching for typos',
                'Enhanced relevance scoring',
                'Improved search suggestions',
                'Better highlighting'
            ]
        }
    
    def _get_type_breakdown(self) -> Dict[str, int]:
        """Get breakdown of documents by type"""
        breakdown = defaultdict(int)
        for doc in self.index.documents.values():
            breakdown[doc['type']] += 1
        return dict(breakdown)


# Factory function
def create_search_engine(db, files_directory: str) -> AdvancedSearchEngine:
    """Create and return an enhanced search engine instance with partial matching"""
    return AdvancedSearchEngine(db, files_directory)