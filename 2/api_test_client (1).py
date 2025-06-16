#!/usr/bin/env python3
"""
Comprehensive API Test Client
Tests all endpoints, authentication, and rate limiting with careful resource management
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
    correct: bool
    message: str
    duration: float = 0.0

class APITestClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[TestResult] = []
        
        # Rate limit tracking to avoid exceeding limits during functional tests
        self.registration_count = 0
        self.login_count = 0
        self.deletion_count = 0
        
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
    
    def log_test(self, name: str, correct: bool, message: str, duration: float = 0.0):
        """Log test result"""
        result = TestResult(name, correct, message, duration)
        self.results.append(result)
        status = "✅ CORRECT" if correct else "❌ INCORRECT"
        duration_str = f" ({duration:.2f}s)" if duration > 0 else ""
        print(f"{status} {name}: {message}{duration_str}")
    
    async def safe_register_user(self) -> tuple[str, str, str]:
        """Safely register a user without hitting rate limits"""
        if self.registration_count >= 4:  # Stay under limit of 5
            raise Exception("Registration limit would be exceeded")
        
        username = self.random_username()
        password = self.random_password()
        
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": password})
        
        if status == 200:
            self.registration_count += 1
            # Login to get token
            _, login_data = await self.request("POST", "/login",
                                              headers={"Content-Type": "application/json"},
                                              json={"username": username, "password": password})
            token = login_data.get("token", "")
            return username, password, token
        else:
            raise Exception(f"Registration failed: {status} - {data}")
    
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
        self.log_test("Invalid JSON Handling", status == 400, f"Status: {status}", duration)
    
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
        
        if status == 200:
            self.registration_count += 1
        
        # Duplicate registration
        start = time.time()
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username, "password": password})
        duration = time.time() - start
        self.log_test("Duplicate Registration Rejection", status == 400, 
                     "Correctly rejected duplicate", duration)
        
        # Missing fields
        start = time.time()
        status, data = await self.request("POST", "/register",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": username})
        duration = time.time() - start
        self.log_test("Missing Password Rejection", status == 400, 
                     "Correctly rejected incomplete data", duration)
        
        return username, password
    
    async def test_authentication(self, username: str, password: str) -> str:
        """Test login and return token"""
        print("\n🔐 Testing Authentication")
        
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
        self.log_test("Invalid Password Rejection", status == 401, 
                     "Correctly rejected bad password", duration)
        
        # Non-existent user  
        start = time.time()
        status, data = await self.request("POST", "/login",
                                         headers={"Content-Type": "application/json"},
                                         json={"username": "nonexistent_user_xyz", "password": password})
        duration = time.time() - start
        self.log_test("Non-existent User Rejection", status == 401, 
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
        self.log_test("Users List Access", users_ok, 
                     f"Status: {status}, Count: {len(data.get('users', []))}", duration)
        
        # Specific user
        start = time.time()
        status, data = await self.request("GET", f"/users/{username}", headers=headers)
        duration = time.time() - start
        user_ok = status == 200 and data.get("username") == username
        self.log_test("Specific User Access", user_ok, 
                     f"Status: {status}, User: {data.get('username')}", duration)
        
        # Admin stats
        start = time.time()
        status, data = await self.request("GET", "/admin/stats", headers=headers)
        duration = time.time() - start
        stats_ok = status == 200 and "total_users" in data
        self.log_test("Admin Stats Access", stats_ok, 
                     f"Status: {status}, Users: {data.get('total_users')}", duration)
        
        # Unauthorized access
        start = time.time()
        status, data = await self.request("GET", "/profile")
        duration = time.time() - start
        self.log_test("Missing Auth Rejection", status == 401, 
                     "Correctly rejected missing auth", duration)
        
        # Invalid token
        start = time.time()
        status, data = await self.request("GET", "/profile", 
                                         headers={"Authorization": "Bearer invalid_token_xyz"})
        duration = time.time() - start
        self.log_test("Invalid Token Rejection", status == 401, 
                     "Correctly rejected invalid token", duration)
    
    async def test_logout(self, token: str):
        """Test logout functionality"""
        print("\n🚪 Testing Logout")
        
        headers = {"Authorization": f"Bearer {token}"}
        
        # Logout
        start = time.time()
        status, data = await self.request("POST", "/logout", headers=headers)
        duration = time.time() - start
        self.log_test("Logout Success", status == 200, 
                     f"Status: {status}", duration)
        
        # Try using token after logout
        start = time.time()
        status, data = await self.request("GET", "/profile", headers=headers)
        duration = time.time() - start
        self.log_test("Token Invalidation", status == 401, 
                     "Token correctly invalidated after logout", duration)
    
    async def test_user_deletion(self):
        """Test user deletion with proper setup"""
        print("\n🗑️  Testing User Deletion")
        
        try:
            # Create dedicated test user for deletion
            username, password, token = await self.safe_register_user()
            headers = {"Authorization": f"Bearer {token}"}
            
            # Verify user exists first
            start = time.time()
            status, data = await self.request("GET", f"/users/{username}", headers=headers)
            duration = time.time() - start
            self.log_test("Pre-deletion User Exists", status == 200 and data.get("username") == username,
                         f"User {username} exists before deletion", duration)
            
            # Delete the user
            start = time.time()
            status, data = await self.request("DELETE", f"/users/{username}", headers=headers)
            duration = time.time() - start
            
            deletion_success = status == 200 and "deleted" in data.get("message", "").lower()
            self.log_test("User Deletion", deletion_success, 
                         f"Status: {status}, Message: {data.get('message')}", duration)
            
            if deletion_success:
                self.deletion_count += 1
            
            # Try to access profile after deletion (should fail)
            start = time.time()
            status, data = await self.request("GET", "/profile", headers=headers)
            duration = time.time() - start
            self.log_test("Post-deletion Access Block", status == 401, 
                         "Profile access correctly blocked after deletion", duration)
            
        except Exception as e:
            self.log_test("User Deletion Setup", False, f"Setup failed: {str(e)}")
    
    async def test_concurrent_access(self):
        """Test concurrent access with limited registrations"""
        print("\n⚡ Testing Concurrent Access")
        
        # Only do 2 concurrent registrations to stay under rate limit
        remaining_registrations = 4 - self.registration_count
        if remaining_registrations < 2:
            self.log_test("Concurrent Access", False, 
                         f"Skipped - only {remaining_registrations} registrations remaining")
            return
        
        async def register_user():
            username = self.random_username()
            password = self.random_password()
            
            status, data = await self.request("POST", "/register",
                                             headers={"Content-Type": "application/json"},
                                             json={"username": username, "password": password})
            return status == 200
        
        # Create 2 users concurrently
        start = time.time()
        tasks = [register_user() for _ in range(2)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        duration = time.time() - start
        
        successful = sum(1 for r in results if r is True)
        self.registration_count += successful
        
        self.log_test("Concurrent Registration", 
                     successful >= 1,  # At least one should succeed
                     f"Successful: {successful}/2 in {duration:.2f}s", duration)
    
    async def test_rate_limiting_registration(self):
        """Test registration rate limiting (5 per 5 minutes per IP)"""
        print("\n🚦 Testing Registration Rate Limiting")
        print("Note: This will consume remaining rate limit budget")
        
        successful_registrations = 0
        rate_limited = False
        
        # Try enough registrations to hit the limit (we may have used some already)
        remaining_attempts = 7 - self.registration_count
        
        for i in range(remaining_attempts):
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
        
        total_registrations = self.registration_count + successful_registrations
        
        self.log_test("Registration Rate Limit", 
                     total_registrations <= 5 and rate_limited,
                     f"Total registrations: {total_registrations}, Rate limited: {rate_limited}")
    
    async def test_rate_limiting_login(self):
        """Test login rate limiting (10 per 5 minutes per IP)"""
        print("\n🚦 Testing Login Rate Limiting")
        
        login_attempts = 0
        rate_limited = False
        
        # Use a known bad username to avoid lockout issues
        for i in range(12):  # Try 12 logins (limit is 10)
            start = time.time()
            status, data = await self.request("POST", "/login",
                                             headers={"Content-Type": "application/json"},
                                             json={"username": "baduser", "password": "wrongpassword"})
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
                     login_attempts <= 10 and rate_limited,
                     f"Attempts: {login_attempts}, Rate limited: {rate_limited}")
    
    async def test_rate_limiting_protected(self):
        """Test rate limiting on protected endpoints"""
        print("\n🚦 Testing Protected Endpoint Rate Limiting")
        
        try:
            # Create a fresh user for this test
            username, password, token = await self.safe_register_user()
            headers = {"Authorization": f"Bearer {token}"}
            
            # Test profile endpoint (200 per minute limit)
            successful_requests = 0
            rate_limited = False
            
            # Make rapid requests to test rate limiting
            start_time = time.time()
            for i in range(25):  # Quick burst test
                start = time.time()
                status, data = await self.request("GET", "/profile", headers=headers)
                duration = time.time() - start
                
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
            
        except Exception as e:
            self.log_test("Protected Rate Limit Setup", False, f"Setup failed: {str(e)}")
    
    def print_summary(self):
        """Print test summary"""
        total = len(self.results)
        correct = sum(1 for r in self.results if r.correct)
        incorrect = total - correct
        
        print("\n" + "="*60)
        print(f"📊 TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"✅ Correct: {correct}")
        print(f"❌ Incorrect: {incorrect}")
        print(f"Success Rate: {correct/total*100:.1f}%")
        
        print(f"\n📈 Resource Usage:")
        print(f"  Registrations: {self.registration_count}/5 (rate limit)")
        print(f"  Deletions: {self.deletion_count}/5 (rate limit)")
        
        if incorrect > 0:
            print(f"\n❌ Incorrect Behaviors:")
            for result in self.results:
                if not result.correct:
                    print(f"  - {result.name}: {result.message}")
        
        print("="*60)

async def main():
    """Run all tests in the correct order"""
    print("🧪 Starting Comprehensive API Tests")
    print("Make sure your API server is running on localhost:8080")
    print("="*60)
    
    async with APITestClient() as client:
        # Core functionality tests (careful with rate limits)
        await client.test_basic_endpoints()
        
        # User management flow (uses 1 registration)
        username, password = await client.test_user_registration()
        token = await client.test_authentication(username, password)
        
        if token:
            await client.test_protected_endpoints(token, username)
            await client.test_logout(token)
        
        # Additional functional tests (uses 1 more registration + 1 deletion)
        await client.test_user_deletion()
        
        # Concurrent test (uses 2 more registrations, total = 4)
        await client.test_concurrent_access()
        
        print("\n" + "="*60)
        print("🚨 RATE LIMITING TESTS - Will consume remaining rate limits")
        print("="*60)
        
        # Rate limiting tests (will exhaust limits - must be last!)
        await client.test_rate_limiting_registration()
        await client.test_rate_limiting_login()
        await client.test_rate_limiting_protected()
        
        # Print summary
        client.print_summary()

if __name__ == "__main__":
    asyncio.run(main())