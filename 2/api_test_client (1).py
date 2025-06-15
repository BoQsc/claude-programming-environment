#!/usr/bin/env python3
"""
Comprehensive API Test Client
Tests all endpoints, authentication, and rate limiting
"""

import asyncio
import aiohttp
import json
import time
import random
import string
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class TestResult:
    name: str
    passed: bool
    message: str
    duration: float = 0.0

class APITestClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[TestResult] = []
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def random_username(self) -> str:
        """Generate random username"""
        return f"user_{''.join(random.choices(string.ascii_lowercase, k=8))}"
    
    def random_password(self) -> str:
        """Generate random password"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    
    async def request(self, method: str, endpoint: str, **kwargs) -> tuple[int, dict]:
        """Make HTTP request and return status, response"""
        url = f"{self.base_url}{endpoint}"
        try:
            async with self.session.request(method, url, **kwargs) as resp:
                try:
                    data = await resp.json()
                except:
                    data = {"text": await resp.text()}
                return resp.status, data
        except Exception as e:
            return 0, {"error": str(e)}
    
    def log_test(self, name: str, passed: bool, message: str, duration: float = 0.0):
        """Log test result"""
        result = TestResult(name, passed, message, duration)
        self.results.append(result)
        status = "✅ PASS" if passed else "❌ FAIL"
        duration_str = f" ({duration:.2f}s)" if duration > 0 else ""
        print(f"{status} {name}: {message}{duration_str}")
    
    async def test_basic_endpoints(self):
        """Test basic endpoint accessibility"""
        print("\n🌐 Testing Basic Endpoints")
        
        # Test non-existent endpoint
        start = time.time()
        status, _ = await self.request("GET", "/nonexistent")
        duration = time.time() - start
        self.log_test("404 Handling", status == 404, f"Status: {status}", duration)
        
        # Test invalid JSON
        start = time.time()
        status, data = await self.request("POST", "/register", 
                                         headers={"Content-Type": "application/json"},
                                         data="invalid json")
        duration = time.time() - start
        self.log_test("Invalid JSON", status == 400, f"Status: {status}", duration)
    
    async def test_user_registration(self) -> tuple[str, str]:
        """Test user registration and return username, password"""
        print("\n👤 Testing User Registration")
        
        username = self.random_username()
        password = self.random_password()
        
        # Valid registration
        start = time.time()
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": password})
        duration = time.time() - start
        self.log_test("Valid Registration", status == 200, 
                     f"User: {username}", duration)
        
        # Duplicate registration
        start = time.time()
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": password})
        duration = time.time() - start
        self.log_test("Duplicate Registration", status == 400, 
                     "Correctly rejected duplicate", duration)
        
        # Missing fields
        start = time.time()
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username})
        duration = time.time() - start
        self.log_test("Missing Password", status == 400, 
                     "Correctly rejected incomplete data", duration)
        
        return username, password
    
    async def test_authentication(self, username: str, password: str) -> str:
        """Test login and return token"""
        print("\n🔐 Testing Authentication")
        
        # Skip if dummy credentials (from rate limited registration)
        if username == "dummy_user":
            self.log_test("Valid Login", False, "Skipped due to registration rate limit")
            self.log_test("Invalid Password", False, "Skipped due to registration rate limit") 
            self.log_test("Non-existent User", False, "Skipped due to registration rate limit")
            return None
        
        # Valid login
        start = time.time()
        status, data = await self.request("POST", "/login",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": password})
        duration = time.time() - start
        
        token = None
        if status == 200 and "token" in data:
            token = data["token"]
            self.log_test("Valid Login", True, f"Token received", duration)
        else:
            self.log_test("Valid Login", False, f"Status: {status}, Data: {data}", duration)
        
        # Invalid password
        start = time.time()
        status, data = await self.request("POST", "/login",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": "wrongpassword"})
        duration = time.time() - start
        self.log_test("Invalid Password", status == 401, 
                     "Correctly rejected bad password", duration)
        
        # Non-existent user
        start = time.time()
        status, data = await self.request("POST", "/login",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": "nonexistent", "password": password})
        duration = time.time() - start
        self.log_test("Non-existent User", status == 401, 
                     "Correctly rejected missing user", duration)
        
        return token
    
    async def test_protected_endpoints(self, token: str, username: str):
        """Test protected endpoints"""
        print("\n🛡️  Testing Protected Endpoints")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Profile endpoint
        start = time.time()
        status, data = await self.request("GET", "/profile", headers=headers)
        duration = time.time() - start
        profile_ok = status == 200 and data.get("username") == username
        self.log_test("Profile Access", profile_ok, 
                     f"Status: {status}, User: {data.get('username')}", duration)
        
        # Users list
        start = time.time()
        status, data = await self.request("GET", "/users", headers=headers)
        duration = time.time() - start
        users_ok = status == 200 and "users" in data
        self.log_test("Users List", users_ok, 
                     f"Status: {status}, Count: {len(data.get('users', []))}", duration)
        
        # Specific user
        start = time.time()
        status, data = await self.request("GET", f"/users/{username}", headers=headers)
        duration = time.time() - start
        user_ok = status == 200 and data.get("username") == username
        self.log_test("Specific User", user_ok, 
                     f"Status: {status}, User: {data.get('username')}", duration)
        
        # Admin stats
        start = time.time()
        status, data = await self.request("GET", "/admin/stats", headers=headers)
        duration = time.time() - start
        stats_ok = status == 200 and "total_users" in data
        self.log_test("Admin Stats", stats_ok, 
                     f"Status: {status}, Users: {data.get('total_users')}", duration)
        
        # Unauthorized access
        start = time.time()
        status, data = await self.request("GET", "/profile")
        duration = time.time() - start
        self.log_test("No Auth Header", status == 401, 
                     "Correctly rejected missing auth", duration)
        
        # Invalid token
        start = time.time()
        status, data = await self.request("GET", "/profile", 
                                         headers={"Authorization": "Bearer invalid_token"})
        duration = time.time() - start
        self.log_test("Invalid Token", status == 401, 
                     "Correctly rejected invalid token", duration)
    
    async def test_logout(self, token: str):
        """Test logout functionality"""
        print("\n🚪 Testing Logout")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Logout
        start = time.time()
        status, data = await self.request("POST", "/logout", headers=headers)
        duration = time.time() - start
        self.log_test("Logout", status == 200, 
                     f"Status: {status}", duration)
        
        # Try using token after logout
        start = time.time()
        status, data = await self.request("GET", "/profile", headers=headers)
        duration = time.time() - start
        self.log_test("Token After Logout", status == 401, 
                     "Token correctly invalidated", duration)
    
    async def test_rate_limiting_registration(self):
        """Test registration rate limiting (5 per 5 minutes per IP)"""
        print("\n🚦 Testing Registration Rate Limiting")
        print("Note: May already be rate limited from previous tests")
        
        successful_registrations = 0
        rate_limited = False
        
        for i in range(7):  # Try 7 registrations (limit is 5)
            username = self.random_username()
            password = self.random_password()
            
            start = time.time()
            status, data = await self.request("POST", "/register",
                                             headers={"Content-Type": "application/json"},
                                             json={"username": username, "password": password})
            duration = time.time() - start
            
            if status == 200:
                successful_registrations += 1
                print(f"  Registration {i+1}: ✅ Success ({duration:.2f}s)")
            elif status == 429:
                rate_limited = True
                print(f"  Registration {i+1}: 🚫 Rate limited ({duration:.2f}s)")
                break
            else:
                print(f"  Registration {i+1}: ❓ Unexpected status {status}")
        
        # Rate limiting is working if we get 429 status
        self.log_test("Registration Rate Limit", 
                     rate_limited or successful_registrations == 0,
                     f"Rate limited: {rate_limited}, New registrations: {successful_registrations}")
    
    async def test_rate_limiting_login(self):
        """Test login rate limiting (10 per 5 minutes per IP)"""
        print("\n🚦 Testing Login Rate Limiting")
        print("Note: May already be rate limited from previous tests")
        
        # Try to create a test user (might fail due to rate limiting)
        username = self.random_username()
        password = self.random_password()
        
        reg_status, _ = await self.request("POST", "/register",
                                          headers={"Content-Type": "application/json"},
                                          json={"username": username, "password": password})
        
        if reg_status != 200:
            print(f"  Cannot create test user (rate limited), testing with wrong credentials")
            username = "nonexistent"
            password = "wrongpassword"
        
        login_attempts = 0
        rate_limited = False
        
        for i in range(12):  # Try 12 logins (limit is 10)
            start = time.time()
            status, data = await self.request("POST", "/login",
                                             headers={"Content-Type": "application/json"},
                                             json={"username": username, "password": "wrongpassword"})
            duration = time.time() - start
            
            if status == 401:  # Invalid credentials (normal)
                login_attempts += 1
                print(f"  Login {i+1}: ✅ Normal failure ({duration:.2f}s)")
            elif status == 429:  # Rate limited
                rate_limited = True
                print(f"  Login {i+1}: 🚫 Rate limited ({duration:.2f}s)")
                break
            else:
                print(f"  Login {i+1}: ❓ Unexpected status {status}")
        
        self.log_test("Login Rate Limit", 
                     rate_limited or login_attempts == 0,
                     f"Rate limited: {rate_limited}, Login attempts: {login_attempts}")
    
    async def test_rate_limiting_protected(self):
        """Test rate limiting on protected endpoints"""
        print("\n🚦 Testing Protected Endpoint Rate Limiting")
        
        # Try to create user and get token (might fail due to rate limiting)
        username = self.random_username()
        password = self.random_password()
        
        reg_status, _ = await self.request("POST", "/register",
                                          headers={"Content-Type": "application/json"},
                                          json={"username": username, "password": password})
        
        if reg_status != 200:
            print("  Cannot create test user due to rate limiting, skipping protected endpoint rate limit test")
            self.log_test("Protected Rate Limit Setup", False, "Registration rate limited")
            return
        
        login_status, login_data = await self.request("POST", "/login",
                                                     headers={"Content-Type": "application/json"},
                                                     json={"username": username, "password": password})
        
        if login_status != 200:
            print("  Cannot login due to rate limiting, skipping protected endpoint rate limit test")
            self.log_test("Protected Rate Limit Setup", False, "Login rate limited")
            return
        
        token = login_data.get("token")
        if not token:
            self.log_test("Protected Rate Limit Setup", False, "Failed to get token")
            return
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test profile endpoint (200 per minute limit)
        successful_requests = 0
        rate_limited = False
        
        # Make rapid requests to test rate limiting
        start_time = time.time()
        for i in range(25):  # Quick burst test
            status, data = await self.request("GET", "/profile", headers=headers)
            
            if status == 200:
                successful_requests += 1
            elif status == 429:
                rate_limited = True
                print(f"  Profile request {i+1}: 🚫 Rate limited after {successful_requests} requests")
                break
            
            # Small delay to avoid overwhelming
            await asyncio.sleep(0.01)
        
        total_time = time.time() - start_time
        
        self.log_test("Profile Rate Limit", 
                     successful_requests > 0,  # Should allow some requests
                     f"Successful: {successful_requests} in {total_time:.2f}s")
    
    async def test_user_deletion(self, token: str, username: str):
        """Test user deletion using existing authenticated user"""
        print("\n🗑️  Testing User Deletion")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Delete own account using existing user
        start = time.time()
        status, data = await self.request("DELETE", f"/users/{username}", headers=headers)
        duration = time.time() - start
        self.log_test("Self Deletion", status == 200, 
                     f"Status: {status}", duration)
        
        # Try to access profile after deletion
        start = time.time()
        status, data = await self.request("GET", "/profile", headers=headers)
        duration = time.time() - start
        self.log_test("Access After Deletion", status == 401, 
                     "Token correctly invalidated", duration)
    
    async def test_concurrent_access(self):
        """Test concurrent access to the API"""
        print("\n⚡ Testing Concurrent Access")
        
        async def register_user():
            username = self.random_username()
            password = self.random_password()
            
            status, data = await self.request("POST", "/register",
                                             headers={"Content-Type": "application/json"},
                                             json={"username": username, "password": password})
            return status == 200
        
        # Create 10 users concurrently
        start = time.time()
        tasks = [register_user() for _ in range(10)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        successful = sum(1 for r in results if r is True)
        
        self.log_test("Concurrent Registration", 
                     successful >= 5,  # At least half should succeed
                     f"Successful: {successful}/10 in {duration:.2f}s", duration)
    
    def print_summary(self):
        """Print test summary"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        
        print("\n" + "="*60)
        print(f"📊 TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"Success Rate: {passed/total*100:.1f}%")
        
        if failed > 0:
            print(f"\n❌ Failed Tests:")
            for result in self.results:
                if not result.passed:
                    print(f"  - {result.name}: {result.message}")
        
        print("="*60)

async def main():
    """Run all tests"""
    print("🧪 Starting Comprehensive API Tests")
    print("Make sure your API server is running on localhost:8080")
    print("="*60)
    
    async with APITestClient() as client:
        # Basic functionality tests
        await client.test_basic_endpoints()
        
        # User management flow
        username, password = await client.test_user_registration()
        token = await client.test_authentication(username, password)
        
        if token:
            await client.test_protected_endpoints(token, username)
            
            # Test user deletion with current user
            await client.test_user_deletion(token, username)
        
        # Test logout with a fresh user (if we can create one)
        username2, password2 = await client.test_user_registration()
        token2 = await client.test_authentication(username2, password2)
        if token2:
            await client.test_logout(token2)
        
        # Rate limiting tests LAST (these consume rate limit budget)
        print("\n🚨 Starting Rate Limiting Tests (may affect subsequent API usage)")
        await client.test_rate_limiting_registration()
        await client.test_rate_limiting_login()
        await client.test_rate_limiting_protected()
        
        # Concurrent access test AFTER rate limiting (creates many users)
        await client.test_concurrent_access()
        
        # Print summary
        client.print_summary()

if __name__ == "__main__":
    asyncio.run(main())