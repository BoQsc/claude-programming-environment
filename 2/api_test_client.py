#!/usr/bin/env python3
"""
Comprehensive API Test Client
Tests all endpoints, authentication, and rate limiting
Usage: python test_client.py
"""

import urllib.request
import urllib.parse
import json
import time
import threading
from typing import Dict, Optional, List

class APIClient:
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url
        self.token: Optional[str] = None
        
    def request(self, method: str, path: str, data: dict = None, headers: dict = None) -> tuple[int, dict]:
        """Make HTTP request and return (status_code, response_data)"""
        url = f"{self.base_url}{path}"
        
        # Prepare headers
        req_headers = {'Content-Type': 'application/json'}
        if headers:
            req_headers.update(headers)
        if self.token:
            req_headers['Authorization'] = f'Bearer {self.token}'
            
        # Prepare data
        req_data = None
        if data:
            req_data = json.dumps(data).encode('utf-8')
            
        try:
            req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
            with urllib.request.urlopen(req) as response:
                response_data = json.loads(response.read().decode('utf-8'))
                return response.status, response_data
        except urllib.error.HTTPError as e:
            try:
                error_data = json.loads(e.read().decode('utf-8'))
                return e.code, error_data
            except:
                return e.code, {'error': str(e)}
        except Exception as e:
            return 0, {'error': str(e)}
    
    def register(self, username: str, password: str) -> tuple[int, dict]:
        return self.request('POST', '/register', {'username': username, 'password': password})
    
    def login(self, username: str, password: str) -> tuple[int, dict]:
        status, data = self.request('POST', '/login', {'username': username, 'password': password})
        if status == 200 and 'token' in data:
            self.token = data['token']
        return status, data
    
    def logout(self) -> tuple[int, dict]:
        return self.request('POST', '/logout')
    
    def get_profile(self) -> tuple[int, dict]:
        return self.request('GET', '/profile')
    
    def get_users(self) -> tuple[int, dict]:
        return self.request('GET', '/users')
    
    def get_user(self, username: str) -> tuple[int, dict]:
        return self.request('GET', f'/users/{username}')
    
    def delete_user(self, username: str) -> tuple[int, dict]:
        return self.request('DELETE', f'/users/{username}')

class TestResults:
    def __init__(self):
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        self.failures: List[str] = []
    
    def assert_status(self, expected: int, actual: int, test_name: str):
        self.tests_run += 1
        if expected == actual:
            self.tests_passed += 1
            print(f"✅ {test_name}")
        else:
            self.tests_failed += 1
            error = f"❌ {test_name} - Expected {expected}, got {actual}"
            print(error)
            self.failures.append(error)
    
    def assert_contains(self, key: str, data: dict, test_name: str):
        self.tests_run += 1
        if key in data:
            self.tests_passed += 1
            print(f"✅ {test_name}")
        else:
            self.tests_failed += 1
            error = f"❌ {test_name} - Key '{key}' not found in response"
            print(error)
            self.failures.append(error)
    
    def print_summary(self):
        print(f"\n{'='*50}")
        print(f"TEST SUMMARY")
        print(f"{'='*50}")
        print(f"Total Tests: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_failed}")
        
        if self.failures:
            print(f"\nFAILURES:")
            for failure in self.failures:
                print(f"  {failure}")
        
        success_rate = (self.tests_passed / self.tests_run * 100) if self.tests_run > 0 else 0
        print(f"\nSuccess Rate: {success_rate:.1f}%")

def test_basic_functionality():
    """Test basic CRUD operations"""
    print(f"\n{'='*50}")
    print("TESTING BASIC FUNCTIONALITY")
    print(f"{'='*50}")
    
    client = APIClient()
    results = TestResults()
    
    # Test registration
    status, data = client.register("testuser", "password123")
    results.assert_status(200, status, "User registration")
    results.assert_contains("message", data, "Registration success message")
    
    # Test duplicate registration
    status, data = client.register("testuser", "password123")
    results.assert_status(400, status, "Duplicate user registration blocked")
    
    # Test login
    status, data = client.login("testuser", "password123")
    results.assert_status(200, status, "User login")
    results.assert_contains("token", data, "Login returns token")
    
    # Test invalid login
    client2 = APIClient()
    status, data = client2.login("testuser", "wrongpassword")
    results.assert_status(401, status, "Invalid login blocked")
    
    # Test protected endpoint access
    status, data = client.get_profile()
    results.assert_status(200, status, "Profile access with token")
    results.assert_contains("username", data, "Profile contains username")
    
    # Test unauthorized access
    status, data = client2.get_profile()
    results.assert_status(401, status, "Profile access without token blocked")
    
    # Test user listing
    status, data = client.get_users()
    results.assert_status(200, status, "User listing")
    results.assert_contains("users", data, "User list contains users array")
    
    # Test specific user lookup
    status, data = client.get_user("testuser")
    results.assert_status(200, status, "Specific user lookup")
    
    # Test nonexistent user lookup
    status, data = client.get_user("nonexistent")
    results.assert_status(404, status, "Nonexistent user returns 404")
    
    # Test logout
    status, data = client.logout()
    results.assert_status(200, status, "User logout")
    
    return results

def test_rate_limiting():
    """Test rate limiting on all endpoints"""
    print(f"\n{'='*50}")
    print("TESTING RATE LIMITING")
    print(f"{'='*50}")
    
    results = TestResults()
    
    # Test registration rate limiting (5 per 5 minutes)
    print("\n🔄 Testing registration rate limiting (5 per 5 minutes)...")
    clients = []
    for i in range(7):  # Try 7 registrations, should block after 5
        client = APIClient()
        clients.append(client)
        status, data = client.register(f"ratetest{i}", "password123")
        print(f"  Registration {i+1}: Status {status}")
        
        if i < 5:
            results.assert_status(200, status, f"Registration {i+1} allowed")
        else:
            results.assert_status(429, status, f"Registration {i+1} rate limited")
            if status == 429:
                results.assert_contains("retry_after", data, f"Rate limit response includes retry_after")
    
    # Test login rate limiting (10 per 5 minutes)
    print("\n🔄 Testing login rate limiting (10 per 5 minutes)...")
    client = APIClient()
    # First register a user to test login
    client.register("logintest", "password123")
    
    for i in range(12):  # Try 12 logins, should block after 10
        status, data = client.login("logintest", "wrongpassword")  # Use wrong password to avoid token issues
        print(f"  Login attempt {i+1}: Status {status}")
        
        if i < 10:
            results.assert_status(401, status, f"Login {i+1} processed (invalid creds)")
        else:
            results.assert_status(429, status, f"Login {i+1} rate limited")
    
    # Test authenticated endpoint rate limiting
    print("\n🔄 Testing profile rate limiting (200 per minute)...")
    auth_client = APIClient()
    auth_client.register("profiletest", "password123")
    auth_client.login("profiletest", "password123")
    
    # Test a bunch of profile requests (won't hit 200 limit, just verify it works)
    success_count = 0
    for i in range(10):
        status, data = auth_client.get_profile()
        if status == 200:
            success_count += 1
    
    results.assert_status(10, success_count, "Profile requests under rate limit succeed")
    
    return results

def test_concurrent_requests():
    """Test concurrent access and rate limiting"""
    print(f"\n{'='*50}")
    print("TESTING CONCURRENT REQUESTS")
    print(f"{'='*50}")
    
    results = TestResults()
    
    def make_registration_requests(thread_id: int, results_list: list):
        """Make registration requests from a thread"""
        client = APIClient()
        thread_results = []
        for i in range(3):  # Each thread tries 3 registrations
            status, data = client.register(f"concurrent{thread_id}_{i}", "password123")
            thread_results.append(status)
            time.sleep(0.1)  # Small delay
        results_list.append(thread_results)
    
    print("🧵 Starting 5 concurrent threads, each making 3 registration requests...")
    threads = []
    thread_results = []
    
    for i in range(5):
        thread = threading.Thread(target=make_registration_requests, args=(i, thread_results))
        threads.append(thread)
        thread.start()
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    # Analyze results
    all_status_codes = []
    for thread_result in thread_results:
        all_status_codes.extend(thread_result)
    
    success_count = all_status_codes.count(200)
    rate_limited_count = all_status_codes.count(429)
    
    print(f"  Successful registrations: {success_count}")
    print(f"  Rate limited responses: {rate_limited_count}")
    print(f"  Total requests: {len(all_status_codes)}")
    
    # Should have some rate limiting due to IP-based limits
    results.tests_run += 1
    if rate_limited_count > 0:
        results.tests_passed += 1
        print("✅ Concurrent rate limiting working")
    else:
        results.tests_failed += 1
        print("❌ Expected some rate limiting in concurrent test")
        results.failures.append("No rate limiting observed in concurrent test")
    
    return results

def test_edge_cases():
    """Test edge cases and error conditions"""
    print(f"\n{'='*50}")
    print("TESTING EDGE CASES")
    print(f"{'='*50}")
    
    client = APIClient()
    results = TestResults()
    
    # Test malformed JSON
    try:
        req = urllib.request.Request(
            "http://localhost:8080/register",
            data=b"invalid json",
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        with urllib.request.urlopen(req) as response:
            status = response.status
    except urllib.error.HTTPError as e:
        status = e.code
    
    results.assert_status(400, status, "Malformed JSON rejected")
    
    # Test missing fields
    status, data = client.request('POST', '/register', {'username': 'test'})  # Missing password
    results.assert_status(400, status, "Missing required fields rejected")
    
    # Test empty credentials
    status, data = client.register("", "")
    results.assert_status(200, status, "Empty credentials handled")  # Might be allowed depending on validation
    
    # Test very long requests
    long_username = "a" * 1000
    status, data = client.register(long_username, "password")
    # Should either work or return 400, but not crash
    results.tests_run += 1
    if status in [200, 400]:
        results.tests_passed += 1
        print("✅ Long username handled gracefully")
    else:
        results.tests_failed += 1
        print(f"❌ Unexpected status {status} for long username")
        results.failures.append(f"Long username test returned {status}")
    
    return results

def main():
    print("🚀 API TEST CLIENT")
    print("Testing comprehensive API functionality and rate limiting")
    print("Make sure your API server is running on http://localhost:8080")
    
    input("\nPress Enter to start testing...")
    
    # Run all test suites
    all_results = []
    
    try:
        all_results.append(test_basic_functionality())
        all_results.append(test_rate_limiting())
        all_results.append(test_concurrent_requests())
        all_results.append(test_edge_cases())
        
        # Combine all results
        total_results = TestResults()
        for result in all_results:
            total_results.tests_run += result.tests_run
            total_results.tests_passed += result.tests_passed
            total_results.tests_failed += result.tests_failed
            total_results.failures.extend(result.failures)
        
        total_results.print_summary()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Testing interrupted by user")
    except Exception as e:
        print(f"\n\n💥 Testing failed with error: {e}")
        print("Make sure your API server is running!")

if __name__ == "__main__":
    main()