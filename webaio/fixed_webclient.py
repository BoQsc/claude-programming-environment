#!/usr/bin/env python3
"""
Complete Web Client for AIOHTTP Blogging API - Fixed Version
A full-featured web interface running on port 80
Only dependency: aiohttp
"""

import asyncio
import json
import logging
import os
import mimetypes
import uuid
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote, unquote

from aiohttp import web, ClientSession, ClientError, ClientTimeout
import ssl

# Configure comprehensive logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    """Application configuration"""
    
    # Server settings
    HOST = '0.0.0.0'
    PORT = 80
    API_BASE_URL = 'http://localhost:8080'
    
    # Security settings
    SESSION_SECRET = 'your-secret-key-change-in-production'
    SESSION_TIMEOUT = 3600  # 1 hour
    
    # File upload settings
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
    ALLOWED_EXTENSIONS = {'.txt', '.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.gif', '.zip'}
    
    @classmethod
    def log_config(cls):
        """Log current configuration"""
        logger.info("=== WEB CLIENT CONFIGURATION ===")
        logger.info(f"Host: {cls.HOST}")
        logger.info(f"Port: {cls.PORT}")
        logger.info(f"API Base URL: {cls.API_BASE_URL}")
        logger.info(f"Session Timeout: {cls.SESSION_TIMEOUT}s")
        logger.info(f"Max File Size: {cls.MAX_FILE_SIZE} bytes")
        logger.info(f"Allowed Extensions: {cls.ALLOWED_EXTENSIONS}")
        logger.info("================================")

# =============================================================================
# SESSION MANAGER
# =============================================================================

class SessionManager:
    """Manage user sessions"""
    
    def __init__(self):
        self.sessions = {}
        logger.debug("SessionManager initialized")
    
    def create_session(self, user_data: Dict) -> str:
        """Create new session"""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            'user': user_data,
            'created_at': asyncio.get_event_loop().time(),
            'last_activity': asyncio.get_event_loop().time()
        }
        logger.debug(f"Created session {session_id} for user {user_data.get('user', {}).get('username')}")
        return session_id
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session data"""
        if not session_id:
            logger.debug("No session ID provided")
            return None
        
        session = self.sessions.get(session_id)
        if not session:
            logger.debug(f"Session {session_id} not found")
            return None
        
        # Check timeout
        current_time = asyncio.get_event_loop().time()
        if current_time - session['last_activity'] > Config.SESSION_TIMEOUT:
            logger.debug(f"Session {session_id} expired")
            del self.sessions[session_id]
            return None
        
        # Update last activity
        session['last_activity'] = current_time
        logger.debug(f"Session {session_id} validated for user {session['user'].get('user', {}).get('username')}")
        return session
    
    def destroy_session(self, session_id: str):
        """Destroy session"""
        if session_id in self.sessions:
            user = self.sessions[session_id]['user'].get('user', {}).get('username')
            del self.sessions[session_id]
            logger.debug(f"Destroyed session {session_id} for user {user}")
        else:
            logger.debug(f"Attempted to destroy non-existent session {session_id}")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        current_time = asyncio.get_event_loop().time()
        expired = []
        
        for session_id, session in self.sessions.items():
            if current_time - session['last_activity'] > Config.SESSION_TIMEOUT:
                expired.append(session_id)
        
        for session_id in expired:
            user = self.sessions[session_id]['user'].get('user', {}).get('username')
            del self.sessions[session_id]
            logger.debug(f"Cleaned up expired session {session_id} for user {user}")
        
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired sessions")

# =============================================================================
# API CLIENT
# =============================================================================

class APIClient:
    """Client for communicating with the blogging API"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.session: Optional[ClientSession] = None
        logger.debug(f"APIClient initialized with base URL: {self.base_url}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        logger.debug("Creating APIClient session")
        self.session = ClientSession(timeout=ClientTimeout(total=30))
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            logger.debug("Closing APIClient session")
            await self.session.close()
    
    async def request(self, method: str, endpoint: str, **kwargs) -> Dict:
        """Make API request"""
        url = f"{self.base_url}{endpoint}"
        headers = kwargs.pop('headers', {})
        
        logger.debug(f"API Request: {method} {url}")
        logger.debug(f"Headers: {headers}")
        if 'json' in kwargs:
            logger.debug(f"JSON payload: {kwargs['json']}")
        
        try:
            async with self.session.request(method, url, headers=headers, **kwargs) as response:
                logger.debug(f"API Response: {response.status} from {url}")
                
                try:
                    response_data = await response.json()
                    logger.debug(f"Response data: {response_data}")
                except Exception as e:
                    logger.warning(f"Failed to parse JSON response: {e}")
                    response_text = await response.text()
                    response_data = {'error': 'Invalid JSON response', 'text': response_text}
                
                return {
                    'status': response.status,
                    'data': response_data,
                    'headers': dict(response.headers)
                }
        
        except ClientError as e:
            logger.error(f"API client error: {e}")
            return {
                'status': 0,
                'data': {'error': f'Client error: {str(e)}'},
                'headers': {}
            }
        except Exception as e:
            logger.error(f"Unexpected API error: {e}")
            return {
                'status': 0,
                'data': {'error': f'Unexpected error: {str(e)}'},
                'headers': {}
            }
    
    async def auth_request(self, method: str, endpoint: str, token: str, **kwargs) -> Dict:
        """Make authenticated API request"""
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {token}'
        logger.debug(f"Making authenticated request with token: {token[:10]}...")
        return await self.request(method, endpoint, headers=headers, **kwargs)

# =============================================================================
# HTML TEMPLATES
# =============================================================================

class HTMLTemplates:
    """HTML template management"""
    
    @staticmethod
    def base_template(title: str, content: str, extra_head: str = "", extra_scripts: str = "") -> str:
        """Base HTML template"""
        logger.debug(f"Rendering base template with title: {title}")
        
        return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - Blog Platform</title>
    <style>
        /* Global Styles */
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        /* Header */
        .header {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            box-shadow: 0 2px 20px rgba(0, 0, 0, 0.1);
            margin-bottom: 20px;
            border-radius: 10px;
        }}
        
        .nav {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 30px;
        }}
        
        .logo {{
            font-size: 24px;
            font-weight: bold;
            color: #667eea;
            text-decoration: none;
        }}
        
        .nav-links {{
            display: flex;
            list-style: none;
            gap: 20px;
        }}
        
        .nav-links a {{
            text-decoration: none;
            color: #333;
            font-weight: 500;
            padding: 8px 16px;
            border-radius: 20px;
            transition: all 0.3s ease;
        }}
        
        .nav-links a:hover {{
            background: #667eea;
            color: white;
            transform: translateY(-2px);
        }}
        
        /* Content Cards */
        .card {{
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            margin-bottom: 20px;
            transition: transform 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
        }}
        
        /* Forms */
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #555;
        }}
        
        .form-control {{
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e8ed;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s ease;
        }}
        
        .form-control:focus {{
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }}
        
        textarea.form-control {{
            resize: vertical;
            min-height: 120px;
        }}
        
        /* Buttons */
        .btn {{
            display: inline-block;
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 25px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
        }}
        
        .btn-secondary {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        
        .btn-success {{
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }}
        
        .btn-danger {{
            background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);
        }}
        
        /* Messages */
        .alert {{
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }}
        
        .alert-success {{
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }}
        
        .alert-error {{
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }}
        
        .alert-info {{
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
        }}
        
        /* Posts */
        .post {{
            border-bottom: 1px solid #eee;
            padding-bottom: 20px;
            margin-bottom: 20px;
        }}
        
        .post:last-child {{
            border-bottom: none;
            margin-bottom: 0;
        }}
        
        .post-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .post-title {{
            font-size: 24px;
            font-weight: 700;
            color: #333;
            margin-bottom: 10px;
        }}
        
        .post-meta {{
            color: #666;
            font-size: 14px;
        }}
        
        .post-content {{
            margin: 15px 0;
            line-height: 1.8;
        }}
        
        .post-tags {{
            margin-top: 15px;
        }}
        
        .tag {{
            display: inline-block;
            background: rgba(102, 126, 234, 0.1);
            color: #667eea;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 12px;
            margin-right: 8px;
            margin-bottom: 5px;
        }}
        
        /* Comments */
        .comments {{
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
        }}
        
        .comment {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
        }}
        
        .comment-header {{
            font-weight: 600;
            color: #667eea;
            margin-bottom: 8px;
        }}
        
        .comment-content {{
            color: #555;
        }}
        
        /* Loading */
        .loading {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        
        .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }}
        
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        
        /* Responsive */
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .nav {{
                flex-direction: column;
                gap: 15px;
            }}
            
            .nav-links {{
                flex-wrap: wrap;
                gap: 10px;
            }}
            
            .card {{
                padding: 20px;
            }}
        }}
        
        /* File Upload */
        .file-upload {{
            border: 2px dashed #667eea;
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            background: rgba(102, 126, 234, 0.05);
            transition: all 0.3s ease;
        }}
        
        .file-upload:hover {{
            border-color: #764ba2;
            background: rgba(102, 126, 234, 0.1);
        }}
        
        .file-upload.dragover {{
            border-color: #764ba2;
            background: rgba(102, 126, 234, 0.15);
            transform: scale(1.02);
        }}
        
        /* Pagination */
        .pagination {{
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 30px;
        }}
        
        .pagination a {{
            padding: 8px 16px;
            background: rgba(255, 255, 255, 0.9);
            color: #667eea;
            text-decoration: none;
            border-radius: 5px;
            transition: all 0.3s ease;
        }}
        
        .pagination a:hover {{
            background: #667eea;
            color: white;
        }}
        
        .pagination .current {{
            background: #667eea;
            color: white;
        }}
        
        /* Search */
        .search-box {{
            position: relative;
            margin-bottom: 30px;
        }}
        
        .search-input {{
            width: 100%;
            padding: 15px 50px 15px 20px;
            border: 2px solid #e1e8ed;
            border-radius: 25px;
            font-size: 16px;
            background: rgba(255, 255, 255, 0.9);
        }}
        
        .search-btn {{
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #667eea;
            font-size: 18px;
            cursor: pointer;
        }}
        
        /* Connection Status */
        .connection-status {{
            position: fixed;
            top: 10px;
            right: 10px;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            z-index: 1000;
        }}
        
        .connection-status.connected {{
            background: #d4edda;
            color: #155724;
        }}
        
        .connection-status.disconnected {{
            background: #f8d7da;
            color: #721c24;
        }}
        
        .connection-status.connecting {{
            background: #d1ecf1;
            color: #0c5460;
        }}
        
        {extra_head}
    </style>
</head>
<body>
    <div class="connection-status" id="connectionStatus">
        <span id="connectionText">Connecting...</span>
    </div>
    
    <div class="container">
        <header class="header">
            <nav class="nav">
                <a href="/" class="logo">🚀 Blog Platform</a>
                <ul class="nav-links">
                    <li><a href="/">Home</a></li>
                    <li><a href="/posts">Posts</a></li>
                    <li><a href="/create-post">Create Post</a></li>
                    <li><a href="/profile">Profile</a></li>
                    <li><a href="/search">Search</a></li>
                    <li><a href="/logout">Logout</a></li>
                </ul>
            </nav>
        </header>
        
        <main>
            {content}
        </main>
    </div>
    
    <!-- WebSocket for live updates -->
    <script>
        // Debug logging
        function debugLog(message, data = null) {{
            console.log(`[WebClient Debug] ${{new Date().toISOString()}} - ${{message}}`, data || '');
        }}
        
        debugLog('Page loaded', {{
            url: window.location.href,
            userAgent: navigator.userAgent,
            timestamp: new Date().toISOString()
        }});
        
        // Global variables
        let ws = null;
        let reconnectAttempts = 0;
        const maxReconnectAttempts = 5;
        let connectionStatus = document.getElementById('connectionStatus');
        let connectionText = document.getElementById('connectionText');
        
        // Update connection status
        function updateConnectionStatus(status, text) {{
            connectionStatus.className = 'connection-status ' + status;
            connectionText.textContent = text;
            debugLog('Connection status updated', {{status, text}});
        }}
        
        // WebSocket connection
        function connectWebSocket() {{
            debugLog('Attempting WebSocket connection');
            updateConnectionStatus('connecting', 'Connecting...');
            
            try {{
                const wsUrl = 'ws://localhost:8080/ws';
                debugLog('Connecting to WebSocket URL', wsUrl);
                
                ws = new WebSocket(wsUrl);
                
                ws.onopen = function(event) {{
                    debugLog('WebSocket connected successfully');
                    updateConnectionStatus('connected', 'Connected');
                    reconnectAttempts = 0;
                    
                    // Send ping to test connection
                    ws.send(JSON.stringify({{type: 'ping'}}));
                    debugLog('Sent ping message');
                }};
                
                ws.onmessage = function(event) {{
                    debugLog('WebSocket message received', event.data);
                    
                    try {{
                        const data = JSON.parse(event.data);
                        debugLog('Parsed WebSocket data', data);
                        
                        if (data.type === 'pong') {{
                            debugLog('Received pong response');
                        }} else if (data.type === 'new_post') {{
                            debugLog('New post notification', data);
                            showNotification('📝 New post: ' + data.post.title, 'info');
                            // Refresh posts if on posts page
                            if (window.location.pathname === '/posts' || window.location.pathname === '/') {{
                                debugLog('Refreshing posts page due to new post');
                                setTimeout(() => window.location.reload(), 2000);
                            }}
                        }} else if (data.type === 'new_comment') {{
                            debugLog('New comment notification', data);
                            showNotification('💬 New comment on post', 'info');
                            // Refresh if on post detail page
                            if (window.location.pathname.includes('/posts/')) {{
                                setTimeout(() => window.location.reload(), 2000);
                            }}
                        }}
                    }} catch (e) {{
                        debugLog('Error parsing WebSocket message', e);
                    }}
                }};
                
                ws.onclose = function(event) {{
                    debugLog('WebSocket connection closed', {{code: event.code, reason: event.reason}});
                    updateConnectionStatus('disconnected', 'Disconnected');
                    
                    if (reconnectAttempts < maxReconnectAttempts) {{
                        reconnectAttempts++;
                        debugLog(`Attempting reconnection ${{reconnectAttempts}}/${{maxReconnectAttempts}}`);
                        updateConnectionStatus('connecting', `Reconnecting... (${{reconnectAttempts}}/${{maxReconnectAttempts}})`);
                        setTimeout(connectWebSocket, 5000 * reconnectAttempts);
                    }} else {{
                        debugLog('Max reconnection attempts reached');
                        updateConnectionStatus('disconnected', 'Connection failed');
                    }}
                }};
                
                ws.onerror = function(error) {{
                    debugLog('WebSocket error', error);
                    updateConnectionStatus('disconnected', 'Connection error');
                }};
                
            }} catch (e) {{
                debugLog('Error creating WebSocket connection', e);
                updateConnectionStatus('disconnected', 'Connection failed');
            }}
        }}
        
        // Notification system
        function showNotification(message, type = 'info') {{
            debugLog('Showing notification', {{message, type}});
            
            const notification = document.createElement('div');
            notification.className = `alert alert-${{type === 'error' ? 'error' : type === 'success' ? 'success' : 'info'}}`;
            notification.textContent = message;
            notification.style.position = 'fixed';
            notification.style.top = '60px';
            notification.style.right = '20px';
            notification.style.zIndex = '1000';
            notification.style.minWidth = '300px';
            notification.style.maxWidth = '400px';
            
            document.body.appendChild(notification);
            
            setTimeout(() => {{
                if (notification.parentNode) {{
                    notification.remove();
                    debugLog('Notification removed');
                }}
            }}, 5000);
        }}
        
        // API helper functions
        async function apiRequest(method, endpoint, data = null, token = null) {{
            debugLog('Making API request', {{method, endpoint, hasData: !!data, hasToken: !!token}});
            
            const url = 'http://localhost:8080' + endpoint;
            const options = {{
                method: method,
                headers: {{
                    'Content-Type': 'application/json',
                }},
            }};
            
            if (token) {{
                options.headers['Authorization'] = 'Bearer ' + token;
                debugLog('Added authorization header');
            }}
            
            if (data) {{
                options.body = JSON.stringify(data);
                debugLog('Added request body', data);
            }}
            
            try {{
                debugLog('Sending request to', url);
                const response = await fetch(url, options);
                debugLog('API response received', {{status: response.status, statusText: response.statusText}});
                
                const result = await response.json();
                debugLog('API response data', result);
                
                return {{
                    status: response.status,
                    data: result,
                    success: response.ok
                }};
            }} catch (error) {{
                debugLog('API request error', error);
                return {{
                    status: 0,
                    data: {{error: 'Network error: ' + error.message}},
                    success: false
                }};
            }}
        }}
        
        // File upload helper
        async function uploadFile(file, token) {{
            debugLog('Uploading file', {{
                name: file.name,
                size: file.size,
                type: file.type
            }});
            
            const formData = new FormData();
            formData.append('file', file);
            
            try {{
                const response = await fetch('http://localhost:8080/files', {{
                    method: 'POST',
                    headers: {{
                        'Authorization': 'Bearer ' + token
                    }},
                    body: formData
                }});
                
                debugLog('File upload response', {{status: response.status}});
                
                const result = await response.json();
                debugLog('File upload result', result);
                
                if (response.ok) {{
                    showNotification('📎 File uploaded successfully!', 'success');
                    return result;
                }} else {{
                    showNotification('❌ ' + (result.error || 'Upload failed'), 'error');
                    return null;
                }}
            }} catch (error) {{
                debugLog('File upload error', error);
                showNotification('❌ Upload error: ' + error.message, 'error');
                return null;
            }}
        }}
        
        // Initialize WebSocket connection on page load
        document.addEventListener('DOMContentLoaded', function() {{
            debugLog('DOM content loaded, initializing WebSocket');
            setTimeout(connectWebSocket, 1000); // Delay to ensure API is ready
        }});
        
        // Check authentication on page load
        document.addEventListener('DOMContentLoaded', function() {{
            const token = localStorage.getItem('authToken');
            if (!token && !window.location.pathname.includes('/login') && !window.location.pathname.includes('/register')) {{
                debugLog('No auth token found, redirecting to login');
                window.location.href = '/login';
            }}
        }});
        
        // Auto-logout on token expiry
        function checkTokenExpiry() {{
            const token = localStorage.getItem('authToken');
            if (token) {{
                // Simple token validation - try a lightweight API call
                fetch('http://localhost:8080/health', {{
                    headers: {{
                        'Authorization': 'Bearer ' + token
                    }}
                }}).catch(() => {{
                    debugLog('Token validation failed, clearing storage');
                    localStorage.removeItem('authToken');
                    localStorage.removeItem('userData');
                    if (!window.location.pathname.includes('/login')) {{
                        window.location.href = '/login';
                    }}
                }});
            }}
        }}
        
        // Check token every 5 minutes
        setInterval(checkTokenExpiry, 5 * 60 * 1000);
        
        // Custom scripts for specific pages
        {extra_scripts}
    </script>
</body>
</html>
        """
    
    @staticmethod
    def login_page(error_message: str = "") -> str:
        """Login page template"""
        logger.debug(f"Rendering login page with error: {error_message}")
        
        error_html = ""
        if error_message:
            error_html = f'<div class="alert alert-error">❌ {error_message}</div>'
        
        content = f"""
        <div class="card" style="max-width: 500px; margin: 50px auto;">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">👋 Welcome Back!</h1>
            
            {error_html}
            
            <form id="loginForm" method="POST">
                <div class="form-group">
                    <label for="username">👤 Username</label>
                    <input type="text" id="username" name="username" class="form-control" required
                           placeholder="Enter your username">
                </div>
                
                <div class="form-group">
                    <label for="password">🔒 Password</label>
                    <input type="password" id="password" name="password" class="form-control" required
                           placeholder="Enter your password">
                </div>
                
                <button type="submit" class="btn" style="width: 100%; margin-bottom: 15px;">
                    🚀 Login
                </button>
            </form>
            
            <div style="text-align: center;">
                <p>Don't have an account? <a href="/register" style="color: #667eea; font-weight: 600;">Register here</a></p>
            </div>
        </div>
        """
        
        scripts = """
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            debugLog('Login form submitted');
            
            const formData = new FormData(this);
            const data = {};
            for (let [key, value] of formData.entries()) {
                data[key] = value;
            }
            
            debugLog('Login data prepared', data);
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄 Logging in...';
            submitBtn.disabled = true;
            
            const response = await apiRequest('POST', '/auth/login', data);
            
            // Restore button
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
            
            if (response.success) {
                debugLog('Login successful', response.data);
                localStorage.setItem('authToken', response.data.token);
                localStorage.setItem('userData', JSON.stringify(response.data.user));
                showNotification('✅ Login successful! Welcome back!', 'success');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1000);
            } else {
                debugLog('Login failed', response.data);
                showNotification('❌ ' + (response.data.error || 'Login failed'), 'error');
            }
        });
        """
        
        return HTMLTemplates.base_template("Login", content, extra_scripts=scripts)
    
    @staticmethod
    def register_page(error_message: str = "") -> str:
        """Registration page template"""
        logger.debug(f"Rendering register page with error: {error_message}")
        
        error_html = ""
        if error_message:
            error_html = f'<div class="alert alert-error">❌ {error_message}</div>'
        
        content = f"""
        <div class="card" style="max-width: 500px; margin: 50px auto;">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">🎉 Join Our Community!</h1>
            
            {error_html}
            
            <form id="registerForm" method="POST">
                <div class="form-group">
                    <label for="username">👤 Username</label>
                    <input type="text" id="username" name="username" class="form-control" required
                           placeholder="Choose a unique username" pattern="[a-zA-Z0-9_]{{3,30}}">
                    <small style="color: #666;">3-30 characters, letters, numbers, and underscores only</small>
                </div>
                
                <div class="form-group">
                    <label for="email">📧 Email</label>
                    <input type="email" id="email" name="email" class="form-control" required
                           placeholder="your.email@example.com">
                </div>
                
                <div class="form-group">
                    <label for="password">🔒 Password</label>
                    <input type="password" id="password" name="password" class="form-control" required
                           placeholder="Create a strong password" minlength="6">
                    <small style="color: #666;">At least 6 characters</small>
                </div>
                
                <button type="submit" class="btn" style="width: 100%; margin-bottom: 15px;">
                    ✨ Create Account
                </button>
            </form>
            
            <div style="text-align: center;">
                <p>Already have an account? <a href="/login" style="color: #667eea; font-weight: 600;">Login here</a></p>
            </div>
        </div>
        """
        
        scripts = """
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            debugLog('Register form submitted');
            
            const formData = new FormData(this);
            const data = {};
            for (let [key, value] of formData.entries()) {
                data[key] = value;
            }
            
            debugLog('Registration data prepared', data);
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄 Creating account...';
            submitBtn.disabled = true;
            
            const response = await apiRequest('POST', '/auth/register', data);
            
            // Restore button
            submitBtn.textContent = originalText;
            submitBtn.disabled = false;
            
            if (response.success) {
                debugLog('Registration successful', response.data);
                localStorage.setItem('authToken', response.data.token);
                localStorage.setItem('userData', JSON.stringify(response.data.user));
                showNotification('🎉 Registration successful! Welcome to the platform!', 'success');
                setTimeout(() => {
                    window.location.href = '/';
                }, 1000);
            } else {
                debugLog('Registration failed', response.data);
                showNotification('❌ ' + (response.data.error || 'Registration failed'), 'error');
            }
        });
        """
        
        return HTMLTemplates.base_template("Register", content, extra_scripts=scripts)
    
    @staticmethod
    def home_page(posts: List[Dict]) -> str:
        """Home page template"""
        logger.debug(f"Rendering home page with {len(posts)} posts")
        
        posts_html = ""
        if posts:
            for post in posts:
                tags_html = ""
                if post.get('tags'):
                    tags_html = " ".join([f'<span class="tag">#{tag}</span>' for tag in post['tags']])
                
                # Format date
                created_at = post.get('created_at', '')
                if created_at:
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        formatted_date = dt.strftime('%B %d, %Y at %I:%M %p')
                    except:
                        formatted_date = created_at[:19].replace('T', ' ')
                else:
                    formatted_date = 'Unknown date'
                
                posts_html += f"""
                <article class="post">
                    <div class="post-header">
                        <h2 class="post-title">
                            <a href="/posts/{post['id']}" style="text-decoration: none; color: inherit;">
                                {post['title']}
                            </a>
                        </h2>
                        <div class="post-meta">
                            👤 {post.get('author', 'Unknown')} • 📅 {formatted_date} • 👁️ {post.get('view_count', 0)} views
                        </div>
                    </div>
                    
                    <div class="post-content">
                        {post['content'][:300]}{'...' if len(post['content']) > 300 else ''}
                    </div>
                    
                    {f'<div class="post-tags">{tags_html}</div>' if tags_html else ''}
                    
                    <div style="margin-top: 15px;">
                        <a href="/posts/{post['id']}" class="btn">📖 Read More</a>
                    </div>
                </article>
                """
        else:
            posts_html = '''
            <div class="loading">
                <h2>🌟 No posts yet!</h2>
                <p>Be the first to share something amazing with the community.</p>
                <a href="/create-post" class="btn">✨ Create the first post!</a>
            </div>
            '''
        
        content = f"""
        <div class="card">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">
                🌟 Latest Posts
            </h1>
            
            <div style="text-align: center; margin-bottom: 30px;">
                <a href="/create-post" class="btn">✨ Create New Post</a>
                <a href="/search" class="btn btn-secondary">🔍 Search Posts</a>
            </div>
            
            {posts_html}
        </div>
        """
        
        scripts = """
        // Load posts on page load
        document.addEventListener('DOMContentLoaded', async function() {
            debugLog('Loading posts for home page');
            
            const token = localStorage.getItem('authToken');
            if (!token) {
                debugLog('No auth token, redirecting to login');
                window.location.href = '/login';
                return;
            }
            
            debugLog('Auth token found, user is logged in');
        });
        """
        
        return HTMLTemplates.base_template("Home", content, extra_scripts=scripts)
    
    @staticmethod
    def create_post_page() -> str:
        """Create post page template"""
        logger.debug("Rendering create post page")
        
        content = """
        <div class="card">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">
                ✍️ Create New Post
            </h1>
            
            <form id="createPostForm" method="POST">
                <div class="form-group">
                    <label for="title">📝 Title</label>
                    <input type="text" id="title" name="title" class="form-control" required 
                           placeholder="Enter an engaging title..." maxlength="200">
                </div>
                
                <div class="form-group">
                    <label for="category">📂 Category</label>
                    <select id="category" name="category" class="form-control">
                        <option value="general">📄 General</option>
                        <option value="technology">💻 Technology</option>
                        <option value="programming">👨‍💻 Programming</option>
                        <option value="lifestyle">🌱 Lifestyle</option>
                        <option value="education">🎓 Education</option>
                        <option value="entertainment">🎬 Entertainment</option>
                        <option value="news">📰 News</option>
                        <option value="science">🔬 Science</option>
                        <option value="health">🏥 Health</option>
                        <option value="travel">✈️ Travel</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="tags">🏷️ Tags (comma-separated)</label>
                    <input type="text" id="tags" name="tags" class="form-control" 
                           placeholder="e.g., javascript, tutorial, web development">
                    <small style="color: #666;">Use commas to separate tags</small>
                </div>
                
                <div class="form-group">
                    <label for="content">📄 Content</label>
                    <textarea id="content" name="content" class="form-control" required 
                              placeholder="Write your amazing content here..." style="min-height: 200px;"></textarea>
                    <small style="color: #666;">Markdown is supported</small>
                </div>
                
                <div class="form-group">
                    <label for="fileUpload">📎 Attach File (optional)</label>
                    <input type="file" id="fileUpload" class="form-control" accept=".txt,.pdf,.doc,.docx,.jpg,.jpeg,.png,.gif,.zip">
                    <small style="color: #666;">Max file size: 50MB</small>
                </div>
                
                <div style="text-align: center;">
                    <button type="submit" class="btn">🚀 Publish Post</button>
                    <a href="/" class="btn btn-secondary">❌ Cancel</a>
                </div>
            </form>
        </div>
        """
        
        scripts = """
        let uploadedFileId = null;
        
        document.getElementById('fileUpload').addEventListener('change', async function(e) {
            const file = e.target.files[0];
            if (!file) return;
            
            const token = localStorage.getItem('authToken');
            if (!token) {
                showNotification('❌ Please login first', 'error');
                return;
            }
            
            debugLog('File selected for upload', {
                name: file.name,
                size: file.size,
                type: file.type
            });
            
            const result = await uploadFile(file, token);
            if (result) {
                uploadedFileId = result.file.id;
                showNotification(`✅ File "${file.name}" uploaded successfully!`, 'success');
            }
        });
        
        document.getElementById('createPostForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            debugLog('Create post form submitted');
            
            const formData = new FormData(this);
            const data = {
                title: formData.get('title'),
                category: formData.get('category'),
                content: formData.get('content'),
                tags: formData.get('tags') ? formData.get('tags').split(',').map(tag => tag.trim()).filter(tag => tag) : []
            };
            
            debugLog('Post data prepared', data);
            
            const token = localStorage.getItem('authToken');
            if (!token) {
                debugLog('No auth token available');
                showNotification('❌ Please login first', 'error');
                window.location.href = '/login';
                return;
            }
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄 Publishing...';
            submitBtn.disabled = true;
            
            const response = await apiRequest('POST', '/posts', data, token);
            
            if (response.success) {
                debugLog('Post created successfully', response.data);
                showNotification('🎉 Post published successfully!', 'success');
                setTimeout(() => {
                    window.location.href = '/posts/' + response.data.post.id;
                }, 1000);
            } else {
                debugLog('Post creation failed', response.data);
                showNotification('❌ ' + (response.data.error || 'Failed to create post'), 'error');
                
                // Restore button
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            }
        });
        """
        
        return HTMLTemplates.base_template("Create Post", content, extra_scripts=scripts)
    
    @staticmethod
    def post_detail_page(post: Dict, comments: List[Dict]) -> str:
        """Post detail page template"""
        logger.debug(f"Rendering post detail page for post: {post.get('id')}")
        
        # Format post tags
        tags_html = ""
        if post.get('tags'):
            tags_html = " ".join([f'<span class="tag">#{tag}</span>' for tag in post['tags']])
        
        # Format date
        created_at = post.get('created_at', '')
        if created_at:
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                formatted_date = dt.strftime('%B %d, %Y at %I:%M %p')
            except:
                formatted_date = created_at[:19].replace('T', ' ')
        else:
            formatted_date = 'Unknown date'
        
        # Format comments
        comments_html = ""
        if comments:
            for comment in comments:
                comment_date = comment.get('created_at', '')
                if comment_date:
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(comment_date.replace('Z', '+00:00'))
                        comment_formatted_date = dt.strftime('%b %d, %Y at %I:%M %p')
                    except:
                        comment_formatted_date = comment_date[:19].replace('T', ' ')
                else:
                    comment_formatted_date = 'Unknown date'
                
                comments_html += f"""
                <div class="comment">
                    <div class="comment-header">
                        👤 {comment.get('author', 'Unknown')} • 📅 {comment_formatted_date}
                    </div>
                    <div class="comment-content">
                        {comment['content']}
                    </div>
                </div>
                """
        else:
            comments_html = '<p style="color: #666; text-align: center; padding: 20px;">💬 No comments yet. Be the first to share your thoughts!</p>'
        
        content = f"""
        <div class="card">
            <article class="post">
                <h1 class="post-title">{post['title']}</h1>
                
                <div class="post-meta" style="margin-bottom: 20px; font-size: 16px;">
                    👤 {post.get('author', 'Unknown')} • 
                    📅 {formatted_date} • 
                    📂 {post.get('category', 'General')} •
                    👁️ {post.get('view_count', 0)} views
                </div>
                
                {f'<div class="post-tags" style="margin-bottom: 20px;">{tags_html}</div>' if tags_html else ''}
                
                <div class="post-content" style="white-space: pre-wrap; line-height: 1.8; font-size: 16px;">
                    {post['content']}
                </div>
            </article>
        </div>
        
        <div class="card comments">
            <h3 style="margin-bottom: 20px;">💬 Comments ({len(comments)})</h3>
            
            <form id="commentForm" style="margin-bottom: 30px;">
                <div class="form-group">
                    <label for="comment">💭 Add your comment</label>
                    <textarea id="comment" name="content" class="form-control" required 
                              placeholder="Share your thoughts about this post..." style="min-height: 100px;"></textarea>
                </div>
                <button type="submit" class="btn">💬 Post Comment</button>
            </form>
            
            <div id="commentsContainer">
                {comments_html}
            </div>
        </div>
        """
        
        scripts = f"""
        const postId = '{post['id']}';
        
        document.getElementById('commentForm').addEventListener('submit', async function(e) {{
            e.preventDefault();
            debugLog('Comment form submitted for post', postId);
            
            const formData = new FormData(this);
            const data = {{
                post_id: postId,
                content: formData.get('content')
            }};
            
            debugLog('Comment data prepared', data);
            
            const token = localStorage.getItem('authToken');
            if (!token) {{
                debugLog('No auth token available');
                showNotification('❌ Please login first', 'error');
                window.location.href = '/login';
                return;
            }}
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄 Posting...';
            submitBtn.disabled = true;
            
            const response = await apiRequest('POST', '/comments', data, token);
            
            if (response.success) {{
                debugLog('Comment created successfully', response.data);
                showNotification('✅ Comment posted successfully!', 'success');
                this.reset();
                setTimeout(() => {{
                    window.location.reload();
                }}, 1000);
            }} else {{
                debugLog('Comment creation failed', response.data);
                showNotification('❌ ' + (response.data.error || 'Failed to post comment'), 'error');
                
                // Restore button
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            }}
        }});
        """
        
        return HTMLTemplates.base_template(f"Post: {post['title']}", content, extra_scripts=scripts)
    
    @staticmethod
    def profile_page(user: Dict) -> str:
        """Profile page template"""
        logger.debug(f"Rendering profile page for user: {user.get('username')}")
        
        content = f"""
        <div class="card">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">
                👤 User Profile
            </h1>
            
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 30px;">
                <div>
                    <h3 style="color: #667eea; margin-bottom: 20px;">📋 Profile Information</h3>
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 10px;">
                        <p><strong>👤 Username:</strong> {user.get('username', 'N/A')}</p>
                        <p><strong>📧 Email:</strong> {user.get('email', 'N/A')}</p>
                        <p><strong>🏷️ Role:</strong> {user.get('role', 'user')}</p>
                        <p><strong>📅 Member since:</strong> {user.get('created_at', '')[:10]}</p>
                        <p><strong>📝 Description:</strong> {user.get('description', 'No description provided')}</p>
                        <p><strong>😊 Mood:</strong> {user.get('mood', 'Not specified')}</p>
                    </div>
                </div>
                
                <div>
                    <h3 style="color: #667eea; margin-bottom: 20px;">✏️ Update Profile</h3>
                    <form id="profileForm">
                        <div class="form-group">
                            <label for="description">📝 Description</label>
                            <textarea id="description" name="description" class="form-control" 
                                      placeholder="Tell us about yourself...">{user.get('description', '')}</textarea>
                        </div>
                        
                        <div class="form-group">
                            <label for="mood">😊 Current Mood</label>
                            <input type="text" id="mood" name="mood" class="form-control" 
                                   value="{user.get('mood', '')}" placeholder="How are you feeling?">
                        </div>
                        
                        <div class="form-group">
                            <label for="avatar_url">🖼️ Avatar URL</label>
                            <input type="url" id="avatar_url" name="avatar_url" class="form-control" 
                                   value="{user.get('avatar_url', '')}" placeholder="https://example.com/avatar.jpg">
                        </div>
                        
                        <button type="submit" class="btn">💾 Update Profile</button>
                    </form>
                </div>
            </div>
        </div>
        """
        
        scripts = """
        document.getElementById('profileForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            debugLog('Profile update form submitted');
            
            const formData = new FormData(this);
            const data = {};
            for (let [key, value] of formData.entries()) {
                data[key] = value;
            }
            
            debugLog('Profile update data prepared', data);
            
            const token = localStorage.getItem('authToken');
            if (!token) {
                debugLog('No auth token available');
                showNotification('❌ Please login first', 'error');
                window.location.href = '/login';
                return;
            }
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄 Updating...';
            submitBtn.disabled = true;
            
            const response = await apiRequest('PUT', '/users/profile', data, token);
            
            if (response.success) {
                debugLog('Profile updated successfully', response.data);
                showNotification('✅ Profile updated successfully!', 'success');
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                debugLog('Profile update failed', response.data);
                showNotification('❌ ' + (response.data.error || 'Failed to update profile'), 'error');
                
                // Restore button
                submitBtn.textContent = originalText;
                submitBtn.disabled = false;
            }
        });
        """
        
        return HTMLTemplates.base_template("Profile", content, extra_scripts=scripts)
    
    @staticmethod
    def search_page(query: str = "", results: List[Dict] = None) -> str:
        """Search page template"""
        logger.debug(f"Rendering search page with query: {query}")
        
        results_html = ""
        if results is not None:
            if results:
                for post in results:
                    tags_html = ""
                    if post.get('tags'):
                        tags_html = " ".join([f'<span class="tag">#{tag}</span>' for tag in post['tags']])
                    
                    # Format date
                    created_at = post.get('created_at', '')
                    if created_at:
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                            formatted_date = dt.strftime('%B %d, %Y')
                        except:
                            formatted_date = created_at[:10]
                    else:
                        formatted_date = 'Unknown date'
                    
                    results_html += f"""
                    <article class="post">
                        <h3><a href="/posts/{post['id']}" style="text-decoration: none; color: #667eea;">{post['title']}</a></h3>
                        <div class="post-meta">
                            👤 {post.get('author', 'Unknown')} • 📅 {formatted_date} • 📂 {post.get('category', 'General')}
                        </div>
                        <div class="post-content">
                            {post['content'][:200]}{'...' if len(post['content']) > 200 else ''}
                        </div>
                        {f'<div class="post-tags">{tags_html}</div>' if tags_html else ''}
                    </article>
                    """
            else:
                results_html = f'''
                <div class="loading">
                    <h2>🔍 No results found</h2>
                    <p>No posts found for "{query}". Try different keywords or check your spelling.</p>
                </div>
                '''
        
        content = f"""
        <div class="card">
            <h1 style="text-align: center; margin-bottom: 30px; color: #667eea;">
                🔍 Search Posts
            </h1>
            
            <form id="searchForm" class="search-box">
                <input type="text" id="searchInput" name="q" class="search-input" 
                       value="{query}" placeholder="Search posts, comments, tags..." required>
                <button type="submit" class="search-btn">🔍</button>
            </form>
            
            {f'<div id="searchResults"><h3 style="color: #667eea;">Search Results for "{query}":</h3>{results_html}</div>' if results_html else ''}
        </div>
        """
        
        scripts = """
        document.getElementById('searchForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            debugLog('Search form submitted');
            
            const query = document.getElementById('searchInput').value.trim();
            if (!query) {
                debugLog('Empty search query');
                showNotification('❌ Please enter a search query', 'error');
                return;
            }
            
            debugLog('Searching for', query);
            
            const token = localStorage.getItem('authToken');
            if (!token) {
                debugLog('No auth token available');
                showNotification('❌ Please login first', 'error');
                window.location.href = '/login';
                return;
            }
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.textContent;
            submitBtn.textContent = '🔄';
            submitBtn.disabled = true;
            
            window.location.href = '/search?q=' + encodeURIComponent(query);
        });
        """
        
        return HTMLTemplates.base_template("Search", content, extra_scripts=scripts)

# =============================================================================
# REQUEST HANDLERS
# =============================================================================

class WebClientHandlers:
    """Web client request handlers"""
    
    def __init__(self, session_manager: SessionManager, api_client: APIClient):
        self.session_manager = session_manager
        self.api_client = api_client
        logger.debug("WebClientHandlers initialized")
    
    def get_session_id(self, request) -> Optional[str]:
        """Extract session ID from request"""
        session_id = request.cookies.get('session_id')
        logger.debug(f"Extracted session ID: {session_id}")
        return session_id
    
    async def home(self, request):
        """Home page handler"""
        logger.info("Handling home page request")
        
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if not session:
            logger.debug("No session, redirecting to login")
            return web.HTTPFound('/login')
        
        try:
            # Fetch recent posts
            logger.debug("Fetching recent posts from API")
            response = await self.api_client.auth_request(
                'GET', '/posts?limit=10', session['user']['token']
            )
            
            if response['status'] == 200:
                posts = response['data'].get('posts', [])
                logger.debug(f"Retrieved {len(posts)} posts")
            else:
                logger.error(f"Failed to fetch posts: {response['data']}")
                posts = []
            
            html = HTMLTemplates.home_page(posts)
            return web.Response(text=html, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Error in home handler: {e}")
            return web.Response(text="Internal Server Error", status=500)
    
    async def login_get(self, request):
        """Login page GET handler"""
        logger.info("Handling login GET request")
        
        # Check if already logged in
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if session:
            logger.debug("User already logged in, redirecting to home")
            return web.HTTPFound('/')
        
        error_message = request.query.get('error', '')
        html = HTMLTemplates.login_page(error_message)
        return web.Response(text=html, content_type='text/html')
    
    async def login_post(self, request):
        """Login page POST handler"""
        logger.info("Handling login POST request")
        
        try:
            data = await request.post()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            logger.debug(f"Login attempt for username: {username}")
            
            if not username or not password:
                logger.debug("Missing username or password")
                return web.HTTPFound('/login?error=Username and password required')
            
            # Call API login
            response = await self.api_client.request(
                'POST', '/auth/login',
                json={'username': username, 'password': password}
            )
            
            logger.debug(f"API login response status: {response['status']}")
            
            if response['status'] == 200:
                user_data = response['data']
                logger.info(f"Login successful for user: {username}")
                
                # Create session
                session_id = self.session_manager.create_session(user_data)
                
                # Set cookie and redirect
                response_obj = web.HTTPFound('/')
                response_obj.set_cookie('session_id', session_id, max_age=Config.SESSION_TIMEOUT)
                return response_obj
            else:
                error_msg = response['data'].get('error', 'Login failed')
                logger.debug(f"Login failed: {error_msg}")
                return web.HTTPFound(f'/login?error={quote(error_msg)}')
                
        except Exception as e:
            logger.error(f"Error in login handler: {e}")
            return web.HTTPFound('/login?error=An error occurred')
    
    async def register_get(self, request):
        """Register page GET handler"""
        logger.info("Handling register GET request")
        
        # Check if already logged in
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if session:
            logger.debug("User already logged in, redirecting to home")
            return web.HTTPFound('/')
        
        error_message = request.query.get('error', '')
        html = HTMLTemplates.register_page(error_message)
        return web.Response(text=html, content_type='text/html')
    
    async def register_post(self, request):
        """Register page POST handler"""
        logger.info("Handling register POST request")
        
        try:
            data = await request.post()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            
            logger.debug(f"Registration attempt for username: {username}, email: {email}")
            
            if not username or not email or not password:
                logger.debug("Missing required fields")
                return web.HTTPFound('/register?error=All fields are required')
            
            # Call API register
            response = await self.api_client.request(
                'POST', '/auth/register',
                json={'username': username, 'email': email, 'password': password}
            )
            
            logger.debug(f"API register response status: {response['status']}")
            
            if response['status'] == 200:
                user_data = response['data']
                logger.info(f"Registration successful for user: {username}")
                
                # Create session
                session_id = self.session_manager.create_session(user_data)
                
                # Set cookie and redirect
                response_obj = web.HTTPFound('/')
                response_obj.set_cookie('session_id', session_id, max_age=Config.SESSION_TIMEOUT)
                return response_obj
            else:
                error_msg = response['data'].get('error', 'Registration failed')
                logger.debug(f"Registration failed: {error_msg}")
                return web.HTTPFound(f'/register?error={quote(error_msg)}')
                
        except Exception as e:
            logger.error(f"Error in register handler: {e}")
            return web.HTTPFound('/register?error=An error occurred')
    
    async def logout(self, request):
        """Logout handler"""
        logger.info("Handling logout request")
        
        session_id = self.get_session_id(request)
        if session_id:
            self.session_manager.destroy_session(session_id)
            logger.debug(f"Destroyed session: {session_id}")
        
        response = web.HTTPFound('/login')
        response.del_cookie('session_id')
        logger.debug("Cleared session cookie")
        return response
    
    async def create_post_get(self, request):
        """Create post page GET handler"""
        logger.info("Handling create post GET request")
        
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if not session:
            logger.debug("No session, redirecting to login")
            return web.HTTPFound('/login')
        
        html = HTMLTemplates.create_post_page()
        return web.Response(text=html, content_type='text/html')
    
    async def post_detail(self, request):
        """Post detail page handler"""
        post_id = request.match_info['post_id']
        logger.info(f"Handling post detail request for post: {post_id}")
        
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if not session:
            logger.debug("No session, redirecting to login")
            return web.HTTPFound('/login')
        
        try:
            # Fetch post
            logger.debug(f"Fetching post {post_id} from API")
            response = await self.api_client.auth_request(
                'GET', f'/posts/{post_id}', session['user']['token']
            )
            
            if response['status'] == 404:
                logger.debug(f"Post {post_id} not found")
                return web.Response(text="Post not found", status=404)
            elif response['status'] != 200:
                logger.error(f"Failed to fetch post: {response['data']}")
                return web.Response(text="Error loading post", status=500)
            
            post = response['data']['post']
            comments = post.get('comments', [])
            
            logger.debug(f"Retrieved post: {post['title']} with {len(comments)} comments")
            
            html = HTMLTemplates.post_detail_page(post, comments)
            return web.Response(text=html, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Error in post detail handler: {e}")
            return web.Response(text="Internal Server Error", status=500)
    
    async def profile(self, request):
        """Profile page handler"""
        logger.info("Handling profile request")
        
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if not session:
            logger.debug("No session, redirecting to login")
            return web.HTTPFound('/login')
        
        try:
            # Fetch current user profile
            logger.debug("Fetching user profile from API")
            response = await self.api_client.auth_request(
                'GET', '/users/profile', session['user']['token']
            )
            
            if response['status'] == 200:
                user = response['data']['user']
                logger.debug(f"Retrieved profile for user: {user['username']}")
            else:
                logger.error(f"Failed to fetch profile: {response['data']}")
                user = session['user']['user']  # Fallback to session data
            
            html = HTMLTemplates.profile_page(user)
            return web.Response(text=html, content_type='text/html')
            
        except Exception as e:
            logger.error(f"Error in profile handler: {e}")
            return web.Response(text="Internal Server Error", status=500)
    
    async def search_get(self, request):
        """Search page GET handler"""
        logger.info("Handling search GET request")
        
        session_id = self.get_session_id(request)
        session = self.session_manager.get_session(session_id)
        
        if not session:
            logger.debug("No session, redirecting to login")
            return web.HTTPFound('/login')
        
        query = request.query.get('q', '').strip()
        results = None
        
        if query:
            try:
                logger.debug(f"Searching for: {query}")
                response = await self.api_client.auth_request(
                    'GET', f'/search?q={quote(query)}', session['user']['token']
                )
                
                if response['status'] == 200:
                    results = response['data'].get('results', [])
                    logger.debug(f"Search returned {len(results)} results")
                else:
                    logger.error(f"Search failed: {response['data']}")
                    results = []
                    
            except Exception as e:
                logger.error(f"Error in search: {e}")
                results = []
        
        html = HTMLTemplates.search_page(query, results)
        return web.Response(text=html, content_type='text/html')

# =============================================================================
# SESSION CLEANUP TASK
# =============================================================================

async def cleanup_sessions_task(session_manager: SessionManager):
    """Background task to cleanup expired sessions"""
    logger.info("Starting session cleanup task")
    
    while True:
        try:
            await asyncio.sleep(300)  # Run every 5 minutes
            logger.debug("Running session cleanup")
            session_manager.cleanup_expired_sessions()
        except Exception as e:
            logger.error(f"Error in session cleanup task: {e}")

# =============================================================================
# APPLICATION SETUP
# =============================================================================

def create_web_client_app():
    """Create and configure the web client application"""
    logger.info("Creating web client application")
    
    # Initialize components
    session_manager = SessionManager()
    
    # Create handlers - we'll initialize API client in startup
    handlers = None
    
    async def init_api_client(app):
        """Initialize API client on startup"""
        nonlocal handlers
        logger.info("Initializing API client")
        
        api_client = APIClient(Config.API_BASE_URL)
        await api_client.__aenter__()
        
        app['api_client'] = api_client
        handlers = WebClientHandlers(session_manager, api_client)
        
        # Add handlers to app for cleanup
        app['handlers'] = handlers
        app['session_manager'] = session_manager
        
        # Start background tasks
        app['cleanup_task'] = asyncio.create_task(cleanup_sessions_task(session_manager))
        
        logger.info("API client initialized successfully")
    
    async def cleanup_api_client(app):
        """Cleanup API client on shutdown"""
        logger.info("Cleaning up API client")
        
        # Cancel background tasks
        if 'cleanup_task' in app:
            app['cleanup_task'].cancel()
            try:
                await app['cleanup_task']
            except asyncio.CancelledError:
                pass
        
        # Close API client
        if 'api_client' in app:
            await app['api_client'].__aexit__(None, None, None)
        
        logger.info("API client cleanup completed")
    
    # Create application
    app = web.Application()
    
    # Set up startup and cleanup
    app.on_startup.append(init_api_client)
    app.on_cleanup.append(cleanup_api_client)
    
    # Add routes - we need to use lambdas to access handlers after initialization
    app.router.add_get('/', lambda req: handlers.home(req))
    app.router.add_get('/login', lambda req: handlers.login_get(req))
    app.router.add_post('/login', lambda req: handlers.login_post(req))
    app.router.add_get('/register', lambda req: handlers.register_get(req))
    app.router.add_post('/register', lambda req: handlers.register_post(req))
    app.router.add_get('/logout', lambda req: handlers.logout(req))
    app.router.add_get('/create-post', lambda req: handlers.create_post_get(req))
    app.router.add_get('/posts/{post_id}', lambda req: handlers.post_detail(req))
    app.router.add_get('/profile', lambda req: handlers.profile(req))
    app.router.add_get('/search', lambda req: handlers.search_get(req))
    
    # Redirect /posts to home for now
    app.router.add_get('/posts', lambda req: web.HTTPFound('/'))
    
    logger.info("Web client application created successfully")
    return app

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point"""
    logger.info("Starting Web Client for Blogging API")
    
    # Log configuration
    Config.log_config()
    
    # SSL configuration (optional)
    ssl_context = None
    port = Config.PORT
    
    cert_file = Path('webclient_cert.pem')
    key_file = Path('webclient_key.pem')
    
    if cert_file.exists() and key_file.exists():
        logger.info("SSL certificates found, enabling HTTPS")
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(cert_file, key_file)
        port = 443
    else:
        logger.info("SSL certificates not found, using HTTP")
    
    # Create and run application
    try:
        app = create_web_client_app()
        
        logger.info(f"Starting web client on {Config.HOST}:{port}")
        logger.info(f"API backend: {Config.API_BASE_URL}")
        logger.info("🚀 Web client ready! Open your browser and navigate to:")
        if port == 80:
            logger.info(f"  http://{Config.HOST}/")
        else:
            logger.info(f"  http://{Config.HOST}:{port}/")
        logger.info("🎯 Features available:")
        logger.info("  • User registration and login")
        logger.info("  • Create and view posts") 
        logger.info("  • Comment on posts")
        logger.info("  • Search functionality")
        logger.info("  • Real-time updates via WebSocket")
        logger.info("  • File uploads")
        logger.info("  • User profiles")
        
        web.run_app(
            app,
            host=Config.HOST,
            port=port,
            ssl_context=ssl_context,
            access_log=logger
        )
    except KeyboardInterrupt:
        logger.info("Web client stopped by user")
    except Exception as e:
        logger.error(f"Web client error: {e}")
        raise

if __name__ == '__main__':
    main()
