#!/usr/bin/env python3
"""
Comprehensive test client for the Enhanced File Sharing API
Tests integrity, correctness, and edge cases for all endpoints including file upload/sharing
"""

import asyncio
import aiohttp
import json
import time
import random
import string
import os
import tempfile
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class TestResult:
    """Test result data structure"""
    name: str
    passed: bool
    message: str
    duration: float
    details: Optional[Dict] = None


class TestReporter:
    """Test reporting and statistics"""
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.start_time = time.time()
    
    def add_result(self, result: TestResult):
        self.results.append(result)
        status = "✅ PASS" if result.passed else "❌ FAIL"
        print(f"{status} {result.name} ({result.duration:.2f}s)")
        if not result.passed:
            print(f"      Error: {result.message}")
        if result.details:
            print(f"      Details: {result.details}")
    
    def print_summary(self):
        total_time = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        
        print("\n" + "="*60)
        print("TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {len(self.results)}")
        print(f"Passed: {passed} ✅")
        print(f"Failed: {failed} ❌")
        print(f"Success Rate: {(passed/len(self.results)*100):.1f}%" if self.results else "0%")
        print(f"Total Time: {total_time:.2f}s")
        
        if failed > 0:
            print(f"\nFAILED TESTS:")
            for result in self.results:
                if not result.passed:
                    print(f"  - {result.name}: {result.message}")
        
        print("="*60)


class APITestClient:
    """Test client for API validation"""
    
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.session = None
        self.token = None
        self.reporter = TestReporter()
        
        # Test data
        self.test_users = []
        self.test_posts = []
        self.test_files = []  # Store uploaded test files
        self.temp_files = []  # Track temporary files for cleanup
    
    async def __aenter__(self):
        connector = aiohttp.TCPConnector(limit=100)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except Exception as e:
                print(f"Warning: Failed to clean up temp file {temp_file}: {e}")
        
        if self.session:
            await self.session.close()
    
    def _get_headers(self, include_content_type=True):
        headers = {}
        if include_content_type:
            headers['Content-Type'] = 'application/json'
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        return headers
    
    async def _request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                       expect_status: int = 200, expect_error: bool = False,
                       return_raw: bool = False) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{endpoint}"
        
        # Only include Content-Type header when sending JSON data
        headers = self._get_headers(include_content_type=data is not None)
        
        kwargs = {'headers': headers}
        if data:
            kwargs['json'] = data
        
        try:
            async with self.session.request(method, url, **kwargs) as response:
                if return_raw:
                    # Return raw response for file downloads
                    content = await response.read()
                    return {
                        'status': response.status,
                        'data': content,
                        'headers': dict(response.headers)
                    }
                else:
                    try:
                        result = await response.json()
                    except (aiohttp.ContentTypeError, json.JSONDecodeError):
                        result = await response.text()
                    
                    return {
                        'status': response.status,
                        'data': result,
                        'headers': dict(response.headers)
                    }
        except Exception as e:
            return {
                'status': 0,
                'data': f"Request failed: {str(e)}",
                'headers': {}
            }
    
    async def _upload_file(self, endpoint: str, files: List[tuple], 
                          additional_data: Optional[Dict] = None) -> Dict[str, Any]:
        """Upload files using multipart/form-data"""
        url = f"{self.base_url}{endpoint}"
        
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        data = aiohttp.FormData()
        
        # Add additional form data if provided
        if additional_data:
            for key, value in additional_data.items():
                data.add_field(key, str(value))
        
        # Add files - read content into memory to avoid file handle issues
        for field_name, file_path, filename in files:
            try:
                with open(file_path, 'rb') as f:
                    file_content = f.read()
                data.add_field(field_name, file_content, filename=filename)
            except Exception as e:
                return {
                    'status': 0,
                    'data': f"Failed to read file {file_path}: {str(e)}",
                    'headers': {}
                }
        
        try:
            async with self.session.post(url, data=data, headers=headers) as response:
                try:
                    result = await response.json()
                except (aiohttp.ContentTypeError, json.JSONDecodeError):
                    result = await response.text()
                
                return {
                    'status': response.status,
                    'data': result,
                    'headers': dict(response.headers)
                }
        except Exception as e:
            return {
                'status': 0,
                'data': f"Upload failed: {str(e)}",
                'headers': {}
            }
    
    async def _run_test(self, test_name: str, test_func, *args, **kwargs):
        """Run a single test with timing and error handling"""
        start_time = time.time()
        try:
            await test_func(*args, **kwargs)
            duration = time.time() - start_time
            self.reporter.add_result(TestResult(
                name=test_name,
                passed=True,
                message="Success",
                duration=duration
            ))
        except Exception as e:
            duration = time.time() - start_time
            self.reporter.add_result(TestResult(
                name=test_name,
                passed=False,
                message=str(e),
                duration=duration
            ))
    
    def _generate_test_user(self) -> Dict[str, str]:
        """Generate random test user data"""
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return {
            'username': f'testuser_{suffix}',
            'email': f'test_{suffix}@example.com',
            'password': 'testpass123'
        }
    
    def _generate_test_post(self) -> Dict[str, Any]:
        """Generate random test post data"""
        titles = [
            "Test Post About Technology",
            "My Experience with APIs",
            "Understanding Async Programming",
            "Database Design Patterns",
            "Web Development Best Practices"
        ]
        
        return {
            'title': random.choice(titles) + f" {random.randint(1, 10000)}",
            'content': f"This is test content generated at {datetime.now()}. " * 5,
            'tags': random.sample(['tech', 'api', 'test', 'python', 'web', 'async'], k=3),
            'is_published': random.choice([True, False])
        }
    
    def _create_test_file(self, filename: str, content: str = None, size: int = None) -> str:
        """Create a temporary test file"""
        temp_dir = tempfile.gettempdir()
        temp_path = os.path.join(temp_dir, f"test_{random.randint(1000, 9999)}_{filename}")
        
        try:
            if content:
                # Create text file with consistent encoding
                with open(temp_path, 'wb') as f:
                    # Always use UTF-8 bytes to ensure consistent encoding
                    f.write(content.encode('utf-8'))
            elif size:
                # Create binary file of specified size
                with open(temp_path, 'wb') as f:
                    f.write(b'0' * size)
            else:
                # Default test file - create as binary for consistency
                default_content = f"This is a test file for upload testing.\nCreated at: {datetime.now()}\n"
                with open(temp_path, 'wb') as f:
                    f.write(default_content.encode('utf-8'))
            
            self.temp_files.append(temp_path)
            return temp_path
        except Exception as e:
            raise Exception(f"Failed to create test file {filename}: {e}")
    
    # =============================================================================
    # Health and Basic Tests
    # =============================================================================
    
    async def test_health_check(self):
        """Test health check endpoint"""
        result = await self._request('GET', '/api/health')
        
        if result['status'] == 0:
            raise Exception(f"Failed to connect: {result['data']}")
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        if isinstance(result['data'], str):
            raise Exception(f"Expected JSON response, got text: {result['data']}")
        
        if 'status' not in result['data'] or result['data']['status'] != 'healthy':
            raise Exception("Health check response invalid")
    
    async def test_root_endpoint(self):
        """Test root endpoint"""
        result = await self._request('GET', '/')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['name', 'version', 'description', 'endpoints']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in root response")
        
        # Check for file features
        if 'file_features' not in result['data']:
            raise Exception("Missing file_features in root response")
    
    async def test_status_endpoint(self):
        """Test status endpoint"""
        result = await self._request('GET', '/api/status')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['status', 'collections', 'timestamp', 'file_storage']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in status response")
        
        # Check file storage stats
        file_storage = result['data']['file_storage']
        storage_fields = ['total_files', 'total_size_bytes', 'total_size_mb']
        for field in storage_fields:
            if field not in file_storage:
                raise Exception(f"Missing field '{field}' in file_storage stats")
    
    # =============================================================================
    # Authentication Tests
    # =============================================================================
    
    async def test_user_registration(self):
        """Test user registration"""
        user_data = self._generate_test_user()
        self.test_users.append(user_data)
        
        result = await self._request('POST', '/api/auth/register', user_data)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}. Response: {result['data']}")
        
        required_fields = ['message', 'user_id', 'username', 'token']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in registration response")
        
        # Store token for subsequent tests
        self.token = result['data']['token']
    
    async def test_user_registration_duplicate(self):
        """Test duplicate user registration"""
        if not self.test_users:
            raise Exception("No test users available for duplicate test")
        
        # Try to register same user again
        user_data = self.test_users[0]
        result = await self._request('POST', '/api/auth/register', user_data)
        
        if result['status'] != 409:
            raise Exception(f"Expected status 409 for duplicate user, got {result['status']}")
    
    async def test_user_registration_validation(self):
        """Test user registration validation"""
        # Test missing fields
        result = await self._request('POST', '/api/auth/register', {'username': 'test'})
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for missing fields, got {result['status']}")
        
        # Test invalid email
        result = await self._request('POST', '/api/auth/register', {
            'username': 'test_invalid_email',
            'email': 'invalid-email',
            'password': 'test123'
        })
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for invalid email, got {result['status']}")
        
        # Test short password
        result = await self._request('POST', '/api/auth/register', {
            'username': 'test_short_pass',
            'email': 'test_short@example.com',
            'password': '123'
        })
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for short password, got {result['status']}")
    
    async def test_user_login(self):
        """Test user login"""
        if not self.test_users:
            raise Exception("No test users available for login test")
        
        user_data = self.test_users[0]
        login_data = {
            'username': user_data['username'],
            'password': user_data['password']
        }
        
        result = await self._request('POST', '/api/auth/login', login_data)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}. Response: {result['data']}")
        
        required_fields = ['message', 'user_id', 'username', 'token']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in login response")
        
        # Update token
        self.token = result['data']['token']
    
    async def test_user_login_invalid(self):
        """Test invalid user login"""
        result = await self._request('POST', '/api/auth/login', {
            'username': 'nonexistent_user_123',
            'password': 'wrongpass'
        })
        
        if result['status'] != 401:
            raise Exception(f"Expected status 401 for invalid login, got {result['status']}")
    
    async def test_user_profile(self):
        """Test user profile retrieval"""
        if not self.token:
            raise Exception("No authentication token available")
        
        result = await self._request('GET', '/api/auth/profile')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['username', 'email', 'created_at']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in profile response")
        
        # Ensure sensitive data is not returned
        if 'password_hash' in result['data']:
            raise Exception("Password hash should not be returned in profile")
    
    async def test_unauthorized_access(self):
        """Test unauthorized access to protected endpoints"""
        # Save current token
        original_token = self.token
        self.token = None
        
        try:
            result = await self._request('GET', '/api/auth/profile')
            if result['status'] != 401:
                raise Exception(f"Expected status 401 for unauthorized access, got {result['status']}")
        finally:
            # Restore token
            self.token = original_token
    
    async def test_invalid_token(self):
        """Test invalid token handling"""
        # Save current token
        original_token = self.token
        self.token = "invalid.token.here"
        
        try:
            result = await self._request('GET', '/api/auth/profile')
            if result['status'] != 401:
                raise Exception(f"Expected status 401 for invalid token, got {result['status']}")
        finally:
            # Restore token
            self.token = original_token
    
    # =============================================================================
    # File Upload and Management Tests
    # =============================================================================
    
    async def test_file_upload_single(self):
        """Test uploading a single file"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Create test file
        test_content = "This is a test file for upload.\nLine 2 of content."
        test_file = self._create_test_file("test_upload.txt", test_content)
        
        files = [('file', test_file, 'test_upload.txt')]
        result = await self._upload_file('/api/files/upload', files)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}. Response: {result['data']}")
        
        required_fields = ['message', 'files']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in upload response")
        
        if not result['data']['files']:
            raise Exception("No files returned in upload response")
        
        # Store file info for subsequent tests
        file_info = result['data']['files'][0]
        file_info['_test_content'] = test_content
        self.test_files.append(file_info)
    
    async def test_file_upload_multiple(self):
        """Test uploading multiple files"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Create multiple test files
        file1 = self._create_test_file("test_multi_1.txt", "Content of file 1")
        file2 = self._create_test_file("test_multi_2.txt", "Content of file 2")
        
        files = [
            ('files', file1, 'test_multi_1.txt'),
            ('files', file2, 'test_multi_2.txt')
        ]
        
        result = await self._upload_file('/api/files/upload', files)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}")
        
        if len(result['data']['files']) != 2:
            raise Exception(f"Expected 2 files uploaded, got {len(result['data']['files'])}")
    
    async def test_file_upload_no_files(self):
        """Test upload request with no files"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Send empty form data
        url = f"{self.base_url}/api/files/upload"
        headers = {'Authorization': f'Bearer {self.token}'}
        
        data = aiohttp.FormData()
        data.add_field('dummy', 'value')
        
        async with self.session.post(url, data=data, headers=headers) as response:
            if response.status != 400:
                raise Exception(f"Expected status 400 for no files, got {response.status}")
    
    async def test_file_upload_unauthorized(self):
        """Test file upload without authentication"""
        test_file = self._create_test_file("unauthorized_test.txt", "test")
        
        url = f"{self.base_url}/api/files/upload"
        data = aiohttp.FormData()
        
        # Read file content to avoid handle issues
        with open(test_file, 'rb') as f:
            file_content = f.read()
        data.add_field('file', file_content, filename='test.txt')
        
        try:
            async with self.session.post(url, data=data) as response:
                if response.status != 401:
                    raise Exception(f"Expected status 401 for unauthorized upload, got {response.status}")
        except Exception as e:
            if "Expected status 401" in str(e):
                raise e
            # For other errors (like network issues), still check if we got the expected 401
            raise Exception(f"Unauthorized upload test failed: {e}")
    
    async def test_list_user_files(self):
        """Test listing user's files"""
        if not self.token:
            raise Exception("No authentication token available")
        
        result = await self._request('GET', '/api/files')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['files', 'count']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in files list response")
        
        if not isinstance(result['data']['files'], list):
            raise Exception("Files field should be a list")
    
    async def test_get_file_info(self):
        """Test getting file metadata"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        file_id = self.test_files[0]['file_id']
        result = await self._request('GET', f'/api/files/{file_id}')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['original_filename', 'file_size', 'mime_type', 'uploaded_at']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in file info response")
    
    async def test_get_nonexistent_file_info(self):
        """Test getting info for non-existent file"""
        if not self.token:
            raise Exception("No authentication token available")
        
        result = await self._request('GET', '/api/files/nonexistent-file-id-12345')
        
        if result['status'] != 404:
            raise Exception(f"Expected status 404 for non-existent file, got {result['status']}")
    
    async def test_download_file(self):
        """Test downloading a file"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        file_id = self.test_files[0]['file_id']
        result = await self._request('GET', f'/api/files/{file_id}/download', return_raw=True)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Check content type header
        if 'Content-Type' not in result['headers']:
            raise Exception("Missing Content-Type header in download response")
        
        # Verify content if we have the original
        if '_test_content' in self.test_files[0]:
            expected_content = self.test_files[0]['_test_content'].encode('utf-8')
            downloaded_content = result['data']
            
            if downloaded_content != expected_content:
                # For debugging, show the actual differences
                print(f"Expected: {expected_content}")
                print(f"Downloaded: {downloaded_content}")
                raise Exception(f"Downloaded content doesn't match uploaded content. Expected {len(expected_content)} bytes, got {len(downloaded_content)} bytes")
    
    async def test_update_file_metadata(self):
        """Test updating file metadata"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        file_id = self.test_files[0]['file_id']
        update_data = {
            'description': 'Updated test file description',
            'tags': ['test', 'updated', 'metadata'],
            'is_public': True
        }
        
        result = await self._request('PUT', f'/api/files/{file_id}', update_data)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        if 'message' not in result['data']:
            raise Exception("Missing message field in update response")
    
    async def test_file_sharing_create(self):
        """Test creating a file share link"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        file_id = self.test_files[0]['file_id']
        result = await self._request('POST', f'/api/files/{file_id}/share')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['message', 'share_token', 'share_url']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in share response")
        
        # Store share token for subsequent tests
        self.test_files[0]['share_token'] = result['data']['share_token']
    
    async def test_file_sharing_download(self):
        """Test downloading a file via share token"""
        if not self.test_files or 'share_token' not in self.test_files[0]:
            raise Exception("No test files with share tokens available")
        
        share_token = self.test_files[0]['share_token']
        result = await self._request('GET', f'/api/files/share/{share_token}', return_raw=True)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Verify content if we have the original
        if '_test_content' in self.test_files[0]:
            expected_content = self.test_files[0]['_test_content'].encode('utf-8')
            downloaded_content = result['data']
            
            if downloaded_content != expected_content:
                # For debugging, show the actual differences
                print(f"Expected: {expected_content}")
                print(f"Downloaded: {downloaded_content}")
                raise Exception(f"Shared download content doesn't match original. Expected {len(expected_content)} bytes, got {len(downloaded_content)} bytes")
    
    async def test_file_sharing_invalid_token(self):
        """Test downloading with invalid share token"""
        result = await self._request('GET', '/api/files/share/invalid-token-12345', return_raw=True)
        
        if result['status'] != 404:
            raise Exception(f"Expected status 404 for invalid share token, got {result['status']}")
    
    async def test_file_sharing_revoke(self):
        """Test revoking file sharing"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        file_id = self.test_files[0]['file_id']
        result = await self._request('DELETE', f'/api/files/{file_id}/share')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Test that the share token no longer works
        if 'share_token' in self.test_files[0]:
            share_token = self.test_files[0]['share_token']
            result = await self._request('GET', f'/api/files/share/{share_token}', return_raw=True)
            if result['status'] != 404:
                raise Exception("Share token should be invalid after revocation")
    
    async def test_delete_file(self):
        """Test deleting a file"""
        if not self.token or not self.test_files:
            raise Exception("No authentication token or test files available")
        
        # Use the last uploaded file for deletion
        file_id = self.test_files[0]['file_id']
        result = await self._request('DELETE', f'/api/files/{file_id}')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Verify file is actually deleted
        result = await self._request('GET', f'/api/files/{file_id}')
        if result['status'] != 404:
            raise Exception("File should be deleted and return 404")
    
    # =============================================================================
    # Posts/Content Tests (Updated for File Attachments)
    # =============================================================================
    
    async def test_create_post(self):
        """Test post creation"""
        if not self.token:
            raise Exception("No authentication token available")
        
        post_data = self._generate_test_post()
        self.test_posts.append(post_data)
        
        result = await self._request('POST', '/api/posts', post_data)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}. Response: {result['data']}")
        
        required_fields = ['message', 'post_id', 'post']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in create post response")
        
        # Store post ID for subsequent tests
        post_data['_id'] = result['data']['post_id']
    
    async def test_create_post_with_files(self):
        """Test creating a post with file attachments"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # First upload a file
        test_file = self._create_test_file("post_attachment.txt", "File attached to post")
        files = [('file', test_file, 'post_attachment.txt')]
        upload_result = await self._upload_file('/api/files/upload', files)
        
        if upload_result['status'] != 201:
            raise Exception("Failed to upload file for post attachment test")
        
        file_id = upload_result['data']['files'][0]['file_id']
        
        # Create post with file attachment
        post_data = self._generate_test_post()
        post_data['attached_files'] = [file_id]
        
        result = await self._request('POST', '/api/posts', post_data)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}")
        
        # Verify attached files are included
        if 'attached_files' not in result['data']['post']:
            raise Exception("attached_files field missing from post")
        
        if file_id not in result['data']['post']['attached_files']:
            raise Exception("File ID not found in attached_files")
    
    async def test_create_post_validation(self):
        """Test post creation validation"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Test missing required fields
        result = await self._request('POST', '/api/posts', {'title': 'Test'})
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for missing content, got {result['status']}")
        
        result = await self._request('POST', '/api/posts', {'content': 'Test content'})
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for missing title, got {result['status']}")
    
    async def test_get_posts(self):
        """Test getting posts list"""
        result = await self._request('GET', '/api/posts')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['posts', 'count']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in get posts response")
        
        if not isinstance(result['data']['posts'], list):
            raise Exception("Posts field should be a list")
    
    async def test_get_posts_with_filters(self):
        """Test getting posts with filters"""
        # Test with limit
        result = await self._request('GET', '/api/posts?limit=5')
        if result['status'] != 200:
            raise Exception(f"Expected status 200 for filtered posts, got {result['status']}")
        
        # Test with published filter
        result = await self._request('GET', '/api/posts?published=true')
        if result['status'] != 200:
            raise Exception(f"Expected status 200 for published filter, got {result['status']}")
    
    async def test_get_specific_post(self):
        """Test getting a specific post"""
        if not self.test_posts or '_id' not in self.test_posts[0]:
            raise Exception("No test posts available")
        
        post_id = self.test_posts[0]['_id']
        result = await self._request('GET', f'/api/posts/{post_id}')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Check that views were incremented
        if 'views' not in result['data']:
            raise Exception("Views field missing from post response")
    
    async def test_get_nonexistent_post(self):
        """Test getting a non-existent post"""
        result = await self._request('GET', '/api/posts/nonexistent-id-12345')
        
        if result['status'] != 404:
            raise Exception(f"Expected status 404 for non-existent post, got {result['status']}")
    
    async def test_update_post(self):
        """Test updating a post"""
        if not self.token or not self.test_posts or '_id' not in self.test_posts[0]:
            raise Exception("No authentication token or test posts available")
        
        post_id = self.test_posts[0]['_id']
        update_data = {
            'title': 'Updated Test Post Title',
            'content': 'Updated content for the test post'
        }
        
        result = await self._request('PUT', f'/api/posts/{post_id}', update_data)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        if 'message' not in result['data']:
            raise Exception("Missing message field in update response")
    
    async def test_like_post(self):
        """Test liking a post"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Create a fresh post specifically for the like test
        post_data = self._generate_test_post()
        post_data['title'] = 'Post for Like Test'
        
        # Create the post
        create_result = await self._request('POST', '/api/posts', post_data)
        if create_result['status'] != 201:
            raise Exception(f"Failed to create post for like test: {create_result['status']}")
        
        post_id = create_result['data']['post_id']
        
        # Now like the post
        result = await self._request('POST', f'/api/posts/{post_id}/like')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['message', 'likes']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in like response")
        
        # Test duplicate like (should fail)
        duplicate_result = await self._request('POST', f'/api/posts/{post_id}/like')
        if duplicate_result['status'] != 400:
            raise Exception("Duplicate like should return 400")
        
        # Clean up the test post
        await self._request('DELETE', f'/api/posts/{post_id}')
    
    async def test_unlike_post(self):
        """Test unliking a post"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Create a post and like it first
        post_data = self._generate_test_post()
        post_data['title'] = 'Post for Unlike Test'
        
        create_result = await self._request('POST', '/api/posts', post_data)
        if create_result['status'] != 201:
            raise Exception("Failed to create post for unlike test")
        
        post_id = create_result['data']['post_id']
        
        # Like the post first
        like_result = await self._request('POST', f'/api/posts/{post_id}/like')
        if like_result['status'] != 200:
            raise Exception("Failed to like post for unlike test")
        
        # Now unlike it
        result = await self._request('POST', f'/api/posts/{post_id}/unlike')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['message', 'likes']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in unlike response")
        
        # Clean up the test post
        await self._request('DELETE', f'/api/posts/{post_id}')
    
    async def test_delete_post(self):
        """Test deleting a post"""
        if not self.token or not self.test_posts or '_id' not in self.test_posts[0]:
            raise Exception("No authentication token or test posts available")
        
        post_id = self.test_posts[0]['_id']
        result = await self._request('DELETE', f'/api/posts/{post_id}')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        # Verify post is actually deleted
        result = await self._request('GET', f'/api/posts/{post_id}')
        if result['status'] != 404:
            raise Exception("Post should be deleted and return 404")
    
    # =============================================================================
    # Data Management Tests
    # =============================================================================
    
    async def test_list_collections(self):
        """Test listing collections"""
        if not self.token:
            raise Exception("No authentication token available")
        
        result = await self._request('GET', '/api/collections')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        if 'collections' not in result['data']:
            raise Exception("Missing collections field in response")
        
        if not isinstance(result['data']['collections'], list):
            raise Exception("Collections field should be a list")
        
        # Check that 'files' collection is included
        if 'files' not in result['data']['collections']:
            raise Exception("Files collection should be present")
    
    async def test_collection_stats(self):
        """Test getting collection statistics"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Test files collection stats
        result = await self._request('GET', '/api/collections/files/stats')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['collection', 'count', 'keys', 'total_keys']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in collection stats response")
    
    # =============================================================================
    # Session Authentication Tests
    # =============================================================================
    
    async def test_session_login(self):
        """Test session-based login"""
        if not self.test_users:
            raise Exception("No test users available for session login test")
        
        user_data = self.test_users[0]
        login_data = {
            'username': user_data['username'],
            'password': user_data['password']
        }
        
        result = await self._request('POST', '/api/auth/session-login', login_data)
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['message', 'session_id', 'user_id', 'username']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in session login response")
    
    # =============================================================================
    # Concurrent Access Tests
    # =============================================================================
    
    async def test_concurrent_requests(self):
        """Test concurrent access to the API"""
        async def make_health_request():
            result = await self._request('GET', '/api/health')
            if result['status'] != 200:
                raise Exception(f"Concurrent request failed with status {result['status']}")
            return result
        
        # Make 20 concurrent requests
        tasks = [make_health_request() for _ in range(20)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check for exceptions
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                raise Exception(f"Concurrent request {i} failed: {result}")
    
    async def test_concurrent_file_uploads(self):
        """Test concurrent file uploads"""
        if not self.token:
            raise Exception("No authentication token available")
        
        async def upload_test_file(index):
            try:
                test_file = self._create_test_file(f"concurrent_{index}.txt", f"Content for concurrent test file {index}")
                files = [('file', test_file, f'concurrent_{index}.txt')]
                result = await self._upload_file('/api/files/upload', files)
                if result['status'] != 201:
                    raise Exception(f"Upload failed with status {result['status']}: {result['data']}")
                return result['data']['files'][0]['file_id']
            except Exception as e:
                raise Exception(f"Concurrent upload {index} failed: {e}")
        
        # Upload 5 files concurrently
        tasks = [upload_test_file(i) for i in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check for exceptions and collect successful uploads
        successful_uploads = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                # If any upload fails, clean up successful ones and raise error
                for file_id in successful_uploads:
                    try:
                        await self._request('DELETE', f'/api/files/{file_id}')
                    except:
                        pass
                raise Exception(f"Concurrent upload {i} failed: {result}")
            else:
                successful_uploads.append(result)
        
        # Clean up all uploaded files
        cleanup_tasks = []
        for file_id in successful_uploads:
            cleanup_tasks.append(self._request('DELETE', f'/api/files/{file_id}'))
        
        await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    
    # =============================================================================
    # Edge Cases and Error Handling Tests
    # =============================================================================
    
    async def test_malformed_json(self):
        """Test handling of malformed JSON"""
        headers = {'Content-Type': 'application/json'}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        try:
            async with self.session.post(
                f"{self.base_url}/api/auth/register",
                data="{invalid json}",
                headers=headers
            ) as response:
                if response.status != 400:
                    raise Exception(f"Expected status 400 for malformed JSON, got {response.status}")
        except Exception as e:
            if "Expected status 400" in str(e):
                raise e
    
    async def test_cors_headers(self):
        """Test CORS headers are present"""
        result = await self._request('OPTIONS', '/api/health')
        
        cors_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]
        
        for header in cors_headers:
            if header not in result['headers']:
                raise Exception(f"Missing CORS header: {header}")
    
    async def test_large_payload(self):
        """Test handling of large payloads"""
        if not self.token:
            raise Exception("No authentication token available")
        
        large_content = "A" * 10000  # 10KB content
        post_data = {
            'title': 'Large Payload Test',
            'content': large_content,
            'tags': ['large', 'test']
        }
        
        result = await self._request('POST', '/api/posts', post_data)
        
        if result['status'] != 201:
            raise Exception(f"Large payload test failed with status {result['status']}")
        
        # Clean up
        if 'post_id' in result['data']:
            await self._request('DELETE', f'/api/posts/{result["data"]["post_id"]}')
    
    async def test_large_file_upload(self):
        """Test uploading a larger file"""
        if not self.token:
            raise Exception("No authentication token available")
        
        # Create 1MB test file
        try:
            large_file = self._create_test_file("large_test.dat", size=1024*1024)
            files = [('file', large_file, 'large_test.dat')]
            
            result = await self._upload_file('/api/files/upload', files)
            
            if result['status'] != 201:
                raise Exception(f"Large file upload failed with status {result['status']}. Response: {result['data']}")
            
            # Clean up
            if result['data']['files']:
                file_id = result['data']['files'][0]['file_id']
                await self._request('DELETE', f'/api/files/{file_id}')
        except Exception as e:
            if "Large file upload failed" in str(e):
                raise e
            raise Exception(f"Large file upload test error: {e}")
    
    # =============================================================================
    # Main Test Runner
    # =============================================================================
    
    async def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting Comprehensive API Test Suite with File Upload")
        print("="*70)
        
        # Health and Basic Tests
        print("\n📊 Health and Basic Tests")
        await self._run_test("Health Check", self.test_health_check)
        await self._run_test("Root Endpoint", self.test_root_endpoint)
        await self._run_test("Status Endpoint", self.test_status_endpoint)
        await self._run_test("CORS Headers", self.test_cors_headers)
        
        # Authentication Tests
        print("\n🔐 Authentication Tests")
        await self._run_test("User Registration", self.test_user_registration)
        await self._run_test("Registration Validation", self.test_user_registration_validation)
        await self._run_test("Duplicate Registration", self.test_user_registration_duplicate)
        await self._run_test("User Login", self.test_user_login)
        await self._run_test("Invalid Login", self.test_user_login_invalid)
        await self._run_test("User Profile", self.test_user_profile)
        await self._run_test("Unauthorized Access", self.test_unauthorized_access)
        await self._run_test("Invalid Token", self.test_invalid_token)
        await self._run_test("Session Login", self.test_session_login)
        
        # File Upload and Management Tests
        print("\n📁 File Upload and Management Tests")
        await self._run_test("Single File Upload", self.test_file_upload_single)
        await self._run_test("Multiple File Upload", self.test_file_upload_multiple)
        await self._run_test("Upload No Files", self.test_file_upload_no_files)
        await self._run_test("Upload Unauthorized", self.test_file_upload_unauthorized)
        await self._run_test("List User Files", self.test_list_user_files)
        await self._run_test("Get File Info", self.test_get_file_info)
        await self._run_test("Get Nonexistent File", self.test_get_nonexistent_file_info)
        await self._run_test("Download File", self.test_download_file)
        await self._run_test("Update File Metadata", self.test_update_file_metadata)
        
        # File Sharing Tests
        print("\n🔗 File Sharing Tests")
        await self._run_test("Create File Share", self.test_file_sharing_create)
        await self._run_test("Download Shared File", self.test_file_sharing_download)
        await self._run_test("Invalid Share Token", self.test_file_sharing_invalid_token)
        await self._run_test("Revoke File Share", self.test_file_sharing_revoke)
        await self._run_test("Delete File", self.test_delete_file)
        
        # Posts/Content Tests
        print("\n📝 Posts and Content Tests")
        await self._run_test("Create Post", self.test_create_post)
        await self._run_test("Create Post with Files", self.test_create_post_with_files)
        await self._run_test("Post Creation Validation", self.test_create_post_validation)
        await self._run_test("Get Posts", self.test_get_posts)
        await self._run_test("Get Posts with Filters", self.test_get_posts_with_filters)
        await self._run_test("Get Specific Post", self.test_get_specific_post)
        await self._run_test("Get Non-existent Post", self.test_get_nonexistent_post)
        await self._run_test("Update Post", self.test_update_post)
        await self._run_test("Like Post", self.test_like_post)
        await self._run_test("Unlike Post", self.test_unlike_post)
        await self._run_test("Delete Post", self.test_delete_post)
        
        # Data Management Tests
        print("\n🗄️ Data Management Tests")
        await self._run_test("List Collections", self.test_list_collections)
        await self._run_test("Collection Stats", self.test_collection_stats)
        
        # Concurrent Access Tests
        print("\n⚡ Concurrent Access Tests")
        await self._run_test("Concurrent Requests", self.test_concurrent_requests)
        await self._run_test("Concurrent File Uploads", self.test_concurrent_file_uploads)
        
        # Edge Cases and Error Handling
        print("\n🛡️ Edge Cases and Error Handling")
        await self._run_test("Malformed JSON", self.test_malformed_json)
        await self._run_test("Large Payload", self.test_large_payload)
        await self._run_test("Large File Upload", self.test_large_file_upload)
        
        # Print final summary
        self.reporter.print_summary()
        
        return len([r for r in self.reporter.results if not r.passed]) == 0


async def run_performance_test(base_url="http://localhost:8080"):
    """Run performance tests"""
    print("\n🚀 Performance Test with File Operations")
    print("="*50)
    
    connector = aiohttp.TCPConnector(limit=100)
    timeout = aiohttp.ClientTimeout(total=30)
    
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        
        async def make_request():
            start = time.time()
            try:
                async with session.get(f"{base_url}/api/health") as response:
                    await response.json()
                    return time.time() - start
            except Exception as e:
                print(f"Request failed: {e}")
                return -1
        
        # Warm up
        await make_request()
        
        # Test concurrent requests
        num_requests = 100
        start_time = time.time()
        
        tasks = [make_request() for _ in range(num_requests)]
        response_times = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out failed requests
        valid_times = [t for t in response_times if isinstance(t, (int, float)) and t > 0]
        
        total_time = time.time() - start_time
        
        if valid_times:
            avg_response_time = sum(valid_times) / len(valid_times)
            min_response_time = min(valid_times)
            max_response_time = max(valid_times)
            requests_per_second = len(valid_times) / total_time
        else:
            avg_response_time = min_response_time = max_response_time = 0
            requests_per_second = 0
        
        print(f"Requests: {num_requests}")
        print(f"Successful: {len(valid_times)}")
        print(f"Failed: {num_requests - len(valid_times)}")
        print(f"Total Time: {total_time:.2f}s")
        print(f"Requests/sec: {requests_per_second:.2f}")
        print(f"Avg Response Time: {avg_response_time*1000:.2f}ms")
        print(f"Min Response Time: {min_response_time*1000:.2f}ms")
        print(f"Max Response Time: {max_response_time*1000:.2f}ms")


async def main():
    """Main test runner"""
    import sys
    
    base_url = "http://localhost:8080"
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "performance":
            await run_performance_test(base_url)
            return
        elif sys.argv[1] == "help":
            print("Enhanced API Test Client Usage:")
            print("  python test_client.py           - Run all tests (including file tests)")
            print("  python test_client.py performance - Run performance tests")
            print("  python test_client.py help      - Show this help")
            return
        else:
            base_url = sys.argv[1]
    
    async with APITestClient(base_url) as client:
        success = await client.run_all_tests()
        
        if success:
            print("\n🎉 All tests passed! Enhanced API with file upload is working correctly.")
            sys.exit(0)
        else:
            print("\n💥 Some tests failed. Please check the API implementation.")
            sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())
