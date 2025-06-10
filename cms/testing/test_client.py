#!/usr/bin/env python3
"""
Comprehensive test client for the Flat Structured API
Tests integrity, correctness, and edge cases for all endpoints
"""

import asyncio
import aiohttp
import json
import time
import random
import string
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime


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
        print(f"Success Rate: {(passed/len(self.results)*100):.1f}%")
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
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
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
                       expect_status: int = 200, expect_error: bool = False) -> Dict[str, Any]:
        """Make HTTP request with error handling"""
        url = f"{self.base_url}{endpoint}"
        
        # Only include Content-Type header when sending JSON data
        headers = self._get_headers(include_content_type=data is not None)
        
        kwargs = {'headers': headers}
        if data:
            kwargs['json'] = data
        
        async with self.session.request(method, url, **kwargs) as response:
            try:
                result = await response.json()
            except:
                result = await response.text()
            
            return {
                'status': response.status,
                'data': result,
                'headers': dict(response.headers)
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
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
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
            'title': random.choice(titles) + f" {random.randint(1, 1000)}",
            'content': f"This is test content generated at {datetime.now()}. " * 5,
            'tags': random.sample(['tech', 'api', 'test', 'python', 'web', 'async'], k=3),
            'is_published': random.choice([True, False])
        }
    
    # =============================================================================
    # Health and Basic Tests
    # =============================================================================
    
    async def test_health_check(self):
        """Test health check endpoint"""
        result = await self._request('GET', '/api/health')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
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
    
    async def test_status_endpoint(self):
        """Test status endpoint"""
        result = await self._request('GET', '/api/status')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['status', 'collections', 'timestamp']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in status response")
    
    # =============================================================================
    # Authentication Tests
    # =============================================================================
    
    async def test_user_registration(self):
        """Test user registration"""
        user_data = self._generate_test_user()
        self.test_users.append(user_data)
        
        result = await self._request('POST', '/api/auth/register', user_data)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}")
        
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
            'username': 'test',
            'email': 'invalid-email',
            'password': 'test123'
        })
        if result['status'] != 400:
            raise Exception(f"Expected status 400 for invalid email, got {result['status']}")
        
        # Test short password
        result = await self._request('POST', '/api/auth/register', {
            'username': 'test2',
            'email': 'test2@example.com',
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
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['message', 'user_id', 'username', 'token']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in login response")
        
        # Update token
        self.token = result['data']['token']
    
    async def test_user_login_invalid(self):
        """Test invalid user login"""
        result = await self._request('POST', '/api/auth/login', {
            'username': 'nonexistent',
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
    # Posts/Content Tests
    # =============================================================================
    
    async def test_create_post(self):
        """Test post creation"""
        if not self.token:
            raise Exception("No authentication token available")
        
        post_data = self._generate_test_post()
        self.test_posts.append(post_data)
        
        result = await self._request('POST', '/api/posts', post_data)
        
        if result['status'] != 201:
            raise Exception(f"Expected status 201, got {result['status']}")
        
        required_fields = ['message', 'post_id', 'post']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in create post response")
        
        # Store post ID for subsequent tests
        post_data['_id'] = result['data']['post_id']
    
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
        result = await self._request('GET', '/api/posts/nonexistent-id')
        
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
    
    async def test_collection_stats(self):
        """Test getting collection statistics"""
        if not self.token:
            raise Exception("No authentication token available")
        
        result = await self._request('GET', '/api/collections/users/stats')
        
        if result['status'] != 200:
            raise Exception(f"Expected status 200, got {result['status']}")
        
        required_fields = ['collection', 'count', 'keys', 'total_keys']
        for field in required_fields:
            if field not in result['data']:
                raise Exception(f"Missing field '{field}' in collection stats response")
    
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
    
    async def test_concurrent_database_operations(self):
        """Test concurrent database operations"""
        if not self.token:
            raise Exception("No authentication token available")
        
        async def create_test_post(index):
            post_data = {
                'title': f'Concurrent Test Post {index}',
                'content': f'Content for concurrent test post {index}',
                'tags': ['concurrent', 'test']
            }
            result = await self._request('POST', '/api/posts', post_data)
            if result['status'] != 201:
                raise Exception(f"Concurrent post creation {index} failed")
            return result['data']['post_id']
        
        # Create 10 posts concurrently
        tasks = [create_test_post(i) for i in range(10)]
        post_ids = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check for exceptions
        for i, post_id in enumerate(post_ids):
            if isinstance(post_id, Exception):
                raise Exception(f"Concurrent post creation {i} failed: {post_id}")
        
        # Clean up created posts
        cleanup_tasks = []
        for post_id in post_ids:
            if not isinstance(post_id, Exception):
                cleanup_tasks.append(self._request('DELETE', f'/api/posts/{post_id}'))
        
        await asyncio.gather(*cleanup_tasks, return_exceptions=True)
    
    # =============================================================================
    # Edge Cases and Error Handling Tests
    # =============================================================================
    
    async def test_malformed_json(self):
        """Test handling of malformed JSON"""
        headers = {'Content-Type': 'application/json'}
        
        async with self.session.post(
            f"{self.base_url}/api/auth/register",
            data="{invalid json}",
            headers=headers
        ) as response:
            if response.status != 400:
                raise Exception(f"Expected status 400 for malformed JSON, got {response.status}")
    
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
    
    # =============================================================================
    # Main Test Runner
    # =============================================================================
    
    async def run_all_tests(self):
        """Run all test suites"""
        print("🚀 Starting Comprehensive API Test Suite")
        print("="*60)
        
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
        
        # Posts/Content Tests
        print("\n📝 Posts and Content Tests")
        await self._run_test("Create Post", self.test_create_post)
        await self._run_test("Post Creation Validation", self.test_create_post_validation)
        await self._run_test("Get Posts", self.test_get_posts)
        await self._run_test("Get Posts with Filters", self.test_get_posts_with_filters)
        await self._run_test("Get Specific Post", self.test_get_specific_post)
        await self._run_test("Get Non-existent Post", self.test_get_nonexistent_post)
        await self._run_test("Update Post", self.test_update_post)
        await self._run_test("Like Post", self.test_like_post)
        await self._run_test("Delete Post", self.test_delete_post)
        
        # Data Management Tests
        print("\n🗄️ Data Management Tests")
        await self._run_test("List Collections", self.test_list_collections)
        await self._run_test("Collection Stats", self.test_collection_stats)
        
        # Concurrent Access Tests
        print("\n⚡ Concurrent Access Tests")
        await self._run_test("Concurrent Requests", self.test_concurrent_requests)
        await self._run_test("Concurrent Database Operations", self.test_concurrent_database_operations)
        
        # Edge Cases and Error Handling
        print("\n🛡️ Edge Cases and Error Handling")
        await self._run_test("Malformed JSON", self.test_malformed_json)
        await self._run_test("Large Payload", self.test_large_payload)
        
        # Print final summary
        self.reporter.print_summary()
        
        return len([r for r in self.reporter.results if not r.passed]) == 0


async def run_performance_test(base_url="http://localhost:8080"):
    """Run performance tests"""
    print("\n🚀 Performance Test")
    print("="*40)
    
    async with aiohttp.ClientSession() as session:
        
        async def make_request():
            start = time.time()
            async with session.get(f"{base_url}/api/health") as response:
                await response.json()
                return time.time() - start
        
        # Warm up
        await make_request()
        
        # Test concurrent requests
        num_requests = 100
        start_time = time.time()
        
        tasks = [make_request() for _ in range(num_requests)]
        response_times = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        avg_response_time = sum(response_times) / len(response_times)
        min_response_time = min(response_times)
        max_response_time = max(response_times)
        requests_per_second = num_requests / total_time
        
        print(f"Requests: {num_requests}")
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
            print("API Test Client Usage:")
            print("  python test_client.py           - Run all tests")
            print("  python test_client.py performance - Run performance tests")
            print("  python test_client.py help      - Show this help")
            return
        else:
            base_url = sys.argv[1]
    
    async with APITestClient(base_url) as client:
        success = await client.run_all_tests()
        
        if success:
            print("\n🎉 All tests passed! API is working correctly.")
            sys.exit(0)
        else:
            print("\n💥 Some tests failed. Please check the API implementation.")
            sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())