#!/usr/bin/env python3
"""
Comprehensive test client for the authentication API.
Tests all endpoints, edge cases, and verifies consistency.

Usage: python test_client.py
"""

import asyncio
import aiohttp
import json
import time
from typing import Dict, Any, Optional

BASE_URL = "http://localhost:8080"

class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []
    
    def add_test(self, name: str, passed: bool, details: str = ""):
        self.tests.append({
            'name': name,
            'passed': passed,
            'details': details
        })
        if passed:
            self.passed += 1
        else:
            self.failed += 1
    
    def print_summary(self):
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"📊 Total:  {self.passed + self.failed}")
        print(f"🎯 Success Rate: {(self.passed/(self.passed+self.failed)*100):.1f}%" if self.passed + self.failed > 0 else "No tests run")
        
        if self.failed > 0:
            print(f"\n❌ FAILED TESTS:")
            for test in self.tests:
                if not test['passed']:
                    print(f"   • {test['name']}: {test['details']}")

class APITestClient:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.session: Optional[aiohttp.ClientSession] = None
        self.result = TestResult()
        
        # Test data
        self.test_users = {
            'alice': {'username': 'alice', 'password': 'secret123'},
            'bob': {'username': 'bob', 'password': 'password456'},
            'charlie': {'username': 'charlie', 'password': 'test789'}
        }
        self.tokens = {}
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    def assert_test(self, name: str, condition: bool, details: str = ""):
        """Assert a test condition and record result"""
        self.result.add_test(name, condition, details)
        status = "✅" if condition else "❌"
        print(f"{status} {name}")
        if not condition and details:
            print(f"   Details: {details}")
    
    async def request(self, method: str, endpoint: str, data: dict = None, token: str = None, expect_status: int = None):
        """Make HTTP request and return response"""
        url = f"{self.base_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if token:
            headers['Authorization'] = f'Bearer {token}'
        
        try:
            async with self.session.request(method, url, headers=headers, json=data) as resp:
                response_data = {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'data': None
                }
                
                try:
                    response_data['data'] = await resp.json()
                except:
                    response_data['data'] = await resp.text()
                
                if expect_status and resp.status != expect_status:
                    print(f"⚠️  Expected status {expect_status}, got {resp.status} for {method} {endpoint}")
                
                return response_data
        except Exception as e:
            print(f"❌ Request failed: {method} {endpoint} - {e}")
            return {'status': 0, 'data': str(e), 'headers': {}}
    
    async def test_cors(self):
        """Test CORS headers"""
        print(f"\n🌐 Testing CORS Support...")
        
        # Test preflight request
        resp = await self.request('OPTIONS', '/profile')
        
        self.assert_test(
            "CORS - OPTIONS request works",
            resp['status'] in [200, 204],
            f"Got status {resp['status']}"
        )
        
        required_headers = [
            'Access-Control-Allow-Origin',
            'Access-Control-Allow-Methods',
            'Access-Control-Allow-Headers'
        ]
        
        for header in required_headers:
            self.assert_test(
                f"CORS - {header} present",
                header in resp['headers'],
                f"Missing header: {header}"
            )
    
    async def test_registration(self):
        """Test user registration"""
        print(f"\n👤 Testing User Registration...")
        
        # Valid registration
        for username, user_data in self.test_users.items():
            resp = await self.request('POST', '/register', user_data)
            self.assert_test(
                f"Register user '{username}'",
                resp['status'] == 200 and 'User created' in str(resp['data']),
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
        
        # Duplicate registration
        resp = await self.request('POST', '/register', self.test_users['alice'])
        self.assert_test(
            "Register duplicate user fails",
            resp['status'] == 400 and 'exists' in str(resp['data']).lower(),
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Invalid input - short username
        resp = await self.request('POST', '/register', {'username': 'ab', 'password': 'secret123'})
        self.assert_test(
            "Register with short username fails",
            resp['status'] == 400,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Invalid input - short password
        resp = await self.request('POST', '/register', {'username': 'validuser', 'password': '123'})
        self.assert_test(
            "Register with short password fails",
            resp['status'] == 400,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Invalid JSON
        try:
            async with self.session.post(f"{self.base_url}/register", data="invalid json") as resp:
                status = resp.status
        except:
            status = 400
        
        self.assert_test(
            "Register with invalid JSON fails",
            status == 400,
            f"Status: {status}"
        )
    
    async def test_username_check(self):
        """Test username availability check"""
        print(f"\n🔍 Testing Username Availability...")
        
        # Check existing user
        resp = await self.request('GET', '/checkusername?username=alice')
        available = True  # default assumption
        if isinstance(resp['data'], dict):
            available = resp['data'].get('available', True)
        
        self.assert_test(
            "Check existing username shows unavailable",
            resp['status'] == 200 and available == False,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Check available username
        resp = await self.request('GET', '/checkusername?username=newuser123')
        available = False  # default assumption
        if isinstance(resp['data'], dict):
            available = resp['data'].get('available', False)
        
        self.assert_test(
            "Check available username shows available",
            resp['status'] == 200 and available == True,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Missing username parameter
        resp = await self.request('GET', '/checkusername')
        self.assert_test(
            "Check username without parameter fails",
            resp['status'] == 400,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
    
    async def test_login(self):
        """Test user login"""
        print(f"\n🔐 Testing User Login...")
        
        # Valid login
        for username, user_data in self.test_users.items():
            resp = await self.request('POST', '/login', user_data)
            has_token = False
            expires_in = None
            
            if isinstance(resp['data'], dict):
                has_token = 'token' in resp['data']
                expires_in = resp['data'].get('expires_in')
                if has_token:
                    self.tokens[username] = resp['data']['token']
            
            self.assert_test(
                f"Login user '{username}'",
                resp['status'] == 200 and has_token,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            if has_token:
                # Verify token expiry is set
                self.assert_test(
                    f"Login returns expires_in for '{username}'",
                    expires_in == 3600,
                    f"expires_in: {expires_in}"
                )
        
        # Invalid credentials
        resp = await self.request('POST', '/login', {'username': 'alice', 'password': 'wrongpassword'})
        self.assert_test(
            "Login with wrong password fails",
            resp['status'] == 401,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Non-existent user
        resp = await self.request('POST', '/login', {'username': 'nonexistent', 'password': 'password'})
        self.assert_test(
            "Login with non-existent user fails",
            resp['status'] == 401,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Invalid JSON
        try:
            async with self.session.post(f"{self.base_url}/login", data="invalid") as resp:
                status = resp.status
        except:
            status = 400
        
        self.assert_test(
            "Login with invalid JSON fails",
            status == 400,
            f"Status: {status}"
        )
    
    async def test_authentication(self):
        """Test authentication with tokens"""
        print(f"\n🔑 Testing Authentication...")
        
        # Valid token
        alice_token = self.tokens.get('alice')
        if alice_token:
            resp = await self.request('GET', '/profile', token=alice_token)
            username = None
            if isinstance(resp['data'], dict):
                username = resp['data'].get('username')
            
            self.assert_test(
                "Access profile with valid token",
                resp['status'] == 200 and username == 'alice',
                f"Status: {resp['status']}, Username: {username}, Response: {resp['data']}"
            )
        
        # Invalid token
        resp = await self.request('GET', '/profile', token='invalid_token_123')
        self.assert_test(
            "Access profile with invalid token fails",
            resp['status'] == 401,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # No token
        resp = await self.request('GET', '/profile')
        self.assert_test(
            "Access profile without token fails",
            resp['status'] == 401,
            f"Status: {resp['status']}, Response: {resp['data']}"
        )
        
        # Malformed Authorization header
        headers = {'Authorization': 'InvalidFormat token123'}
        try:
            async with self.session.get(f"{self.base_url}/profile", headers=headers) as resp:
                status = resp.status
        except:
            status = 401
        
        self.assert_test(
            "Access with malformed auth header fails",
            status == 401,
            f"Status: {status}"
        )
    
    async def test_profile(self):
        """Test profile endpoint"""
        print(f"\n👤 Testing Profile Access...")
        
        alice_token = self.tokens.get('alice')
        if alice_token:
            resp = await self.request('GET', '/profile', token=alice_token)
            
            if resp['status'] == 200 and isinstance(resp['data'], dict):
                profile = resp['data']
                self.assert_test(
                    "Profile contains username",
                    profile.get('username') == 'alice',
                    f"Username: {profile.get('username')}"
                )
                
                self.assert_test(
                    "Profile contains created_at",
                    'created_at' in profile and isinstance(profile['created_at'], (int, float)),
                    f"created_at: {profile.get('created_at')}"
                )
                
                self.assert_test(
                    "Profile contains last_login",
                    'last_login' in profile,
                    f"last_login: {profile.get('last_login')}"
                )
            else:
                self.assert_test(
                    "Profile request failed",
                    False,
                    f"Status: {resp['status']}, Response: {resp['data']}"
                )
    
    async def test_users_list(self):
        """Test users listing"""
        print(f"\n📋 Testing Users List...")
        
        alice_token = self.tokens.get('alice')
        if alice_token:
            resp = await self.request('GET', '/users', token=alice_token)
            
            has_users = False
            users = []
            usernames = []
            
            if isinstance(resp['data'], dict) and 'users' in resp['data']:
                has_users = True
                users = resp['data']['users']
                usernames = [u.get('username') if isinstance(u, dict) else str(u) for u in users]
            
            self.assert_test(
                "Get users list works",
                resp['status'] == 200 and has_users,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            if has_users:
                self.assert_test(
                    "Users list contains all registered users",
                    all(name in usernames for name in self.test_users.keys()),
                    f"Expected: {list(self.test_users.keys())}, Got: {usernames}"
                )
                
                self.assert_test(
                    "Users list has correct count",
                    len(users) == len(self.test_users),
                    f"Expected: {len(self.test_users)}, Got: {len(users)}"
                )
    
    async def test_user_details(self):
        """Test individual user details"""
        print(f"\n🔍 Testing User Details...")
        
        alice_token = self.tokens.get('alice')
        if alice_token:
            # Get existing user
            resp = await self.request('GET', '/users/bob', token=alice_token)
            username = None
            if isinstance(resp['data'], dict):
                username = resp['data'].get('username')
                
            self.assert_test(
                "Get existing user details",
                resp['status'] == 200 and username == 'bob',
                f"Status: {resp['status']}, Username: {username}, Response: {resp['data']}"
            )
            
            # Get non-existent user
            resp = await self.request('GET', '/users/nonexistent', token=alice_token)
            self.assert_test(
                "Get non-existent user fails",
                resp['status'] == 404,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
    
    async def test_password_change(self):
        """Test password change functionality"""
        print(f"\n🔒 Testing Password Change...")
        
        charlie_token = self.tokens.get('charlie')
        if charlie_token:
            # Valid password change
            change_data = {
                'current_password': 'test789',
                'new_password': 'newpassword123'
            }
            resp = await self.request('PUT', '/changepassword', change_data, token=charlie_token)
            self.assert_test(
                "Change password with valid current password",
                resp['status'] == 200,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            # Verify old password no longer works
            login_resp = await self.request('POST', '/login', {'username': 'charlie', 'password': 'test789'})
            self.assert_test(
                "Old password no longer works after change",
                login_resp['status'] == 401,
                f"Status: {login_resp['status']}"
            )
            
            # Verify new password works
            login_resp = await self.request('POST', '/login', {'username': 'charlie', 'password': 'newpassword123'})
            has_token = False
            if isinstance(login_resp['data'], dict) and 'token' in login_resp['data']:
                has_token = True
                self.tokens['charlie'] = login_resp['data']['token']
                
            self.assert_test(
                "New password works after change",
                login_resp['status'] == 200 and has_token,
                f"Status: {login_resp['status']}"
            )
            
            # Wrong current password
            wrong_change_data = {
                'current_password': 'wrongpassword',
                'new_password': 'anothernewpass'
            }
            resp = await self.request('PUT', '/changepassword', wrong_change_data, token=self.tokens['charlie'])
            self.assert_test(
                "Change password with wrong current password fails",
                resp['status'] == 400,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            # New password too short
            short_change_data = {
                'current_password': 'newpassword123',
                'new_password': '123'
            }
            resp = await self.request('PUT', '/changepassword', short_change_data, token=self.tokens['charlie'])
            self.assert_test(
                "Change password with short new password fails",
                resp['status'] == 400,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
    
    async def test_logout(self):
        """Test logout functionality"""
        print(f"\n🚪 Testing Logout...")
        
        # Login bob to get a fresh token for testing
        login_resp = await self.request('POST', '/login', self.test_users['bob'])
        if login_resp['status'] == 200 and isinstance(login_resp['data'], dict):
            bob_token = login_resp['data']['token']
            
            # Verify token works before logout
            resp = await self.request('GET', '/profile', token=bob_token)
            self.assert_test(
                "Token works before logout",
                resp['status'] == 200,
                f"Status: {resp['status']}"
            )
            
            # Logout
            resp = await self.request('POST', '/logout', token=bob_token)
            self.assert_test(
                "Logout request succeeds",
                resp['status'] == 200,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            # Verify token no longer works after logout
            resp = await self.request('GET', '/profile', token=bob_token)
            self.assert_test(
                "Token invalidated after logout",
                resp['status'] == 401,
                f"Status: {resp['status']}"
            )
        
        # Logout without token (should still succeed)
        resp = await self.request('POST', '/logout')
        self.assert_test(
            "Logout without token succeeds",
            resp['status'] == 200,
            f"Status: {resp['status']}"
        )
    
    async def test_user_deletion(self):
        """Test user deletion and verify consistency"""
        print(f"\n🗑️  Testing User Deletion...")
        
        # Create a test user for deletion
        delete_user = {'username': 'deleteme', 'password': 'delete123'}
        await self.request('POST', '/register', delete_user)
        
        login_resp = await self.request('POST', '/login', delete_user)
        if login_resp['status'] == 200 and isinstance(login_resp['data'], dict):
            delete_token = login_resp['data']['token']
            
            # Try to delete another user (should fail)
            resp = await self.request('DELETE', '/users/alice', token=delete_token)
            self.assert_test(
                "Cannot delete other users",
                resp['status'] == 403,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            # Delete own account
            resp = await self.request('DELETE', '/users/deleteme', token=delete_token)
            self.assert_test(
                "Can delete own account",
                resp['status'] == 200,
                f"Status: {resp['status']}, Response: {resp['data']}"
            )
            
            # Verify user is actually deleted - token should no longer work
            resp = await self.request('GET', '/profile', token=delete_token)
            self.assert_test(
                "Token invalidated after account deletion",
                resp['status'] == 401,
                f"Status: {resp['status']}"
            )
            
            # Verify user cannot login anymore
            resp = await self.request('POST', '/login', delete_user)
            self.assert_test(
                "Cannot login with deleted account",
                resp['status'] == 401,
                f"Status: {resp['status']}"
            )
            
            # Verify user not in users list
            alice_token = self.tokens.get('alice')
            if alice_token:
                resp = await self.request('GET', '/users', token=alice_token)
                if resp['status'] == 200 and isinstance(resp['data'], dict) and 'users' in resp['data']:
                    users = resp['data']['users']
                    usernames = [u.get('username') if isinstance(u, dict) else str(u) for u in users]
                    self.assert_test(
                        "Deleted user not in users list",
                        'deleteme' not in usernames,
                        f"Found 'deleteme' in: {usernames}"
                    )
                else:
                    self.assert_test(
                        "Could not get users list to verify deletion",
                        False,
                        f"Users list request failed: {resp['status']}, {resp['data']}"
                    )
            
            # Try to delete non-existent user
            resp = await self.request('DELETE', '/users/deleteme', token=alice_token)
            self.assert_test(
                "Delete non-existent user fails",
                resp['status'] == 404,
                f"Status: {resp['status']}"
            )
    
    async def test_edge_cases(self):
        """Test various edge cases"""
        print(f"\n🧪 Testing Edge Cases...")
        
        # Very long username/password
        long_data = {
            'username': 'a' * 1000,
            'password': 'b' * 1000
        }
        resp = await self.request('POST', '/register', long_data)
        self.assert_test(
            "Handle very long input gracefully",
            resp['status'] in [200, 400],  # Either accept or reject, but don't crash
            f"Status: {resp['status']}"
        )
        
        # Empty strings
        empty_data = {'username': '', 'password': ''}
        resp = await self.request('POST', '/register', empty_data)
        self.assert_test(
            "Reject empty username/password",
            resp['status'] == 400,
            f"Status: {resp['status']}"
        )
        
        # Special characters in username
        special_data = {'username': 'user@#$%', 'password': 'password123'}
        resp = await self.request('POST', '/register', special_data)
        self.assert_test(
            "Handle special characters in username",
            resp['status'] in [200, 400],  # Either accept or reject
            f"Status: {resp['status']}"
        )
        
        # Missing fields
        incomplete_data = {'username': 'incomplete'}
        resp = await self.request('POST', '/register', incomplete_data)
        self.assert_test(
            "Reject incomplete registration data",
            resp['status'] == 400,
            f"Status: {resp['status']}"
        )
    
    async def test_consistency(self):
        """Test data consistency across operations"""
        print(f"\n🔄 Testing Data Consistency...")
        
        # Create user, verify it appears everywhere it should
        consistency_user = {'username': 'consistent', 'password': 'test123'}
        await self.request('POST', '/register', consistency_user)
        
        # Check username availability
        resp = await self.request('GET', '/checkusername?username=consistent')
        available = False
        if isinstance(resp['data'], dict):
            available = resp['data'].get('available', True)
        self.assert_test(
            "Registered user shows as unavailable",
            available == False,
            f"Available: {available}, Response: {resp['data']}"
        )
        
        # Login and check profile
        login_resp = await self.request('POST', '/login', consistency_user)
        if login_resp['status'] == 200 and isinstance(login_resp['data'], dict):
            token = login_resp['data']['token']
            
            profile_resp = await self.request('GET', '/profile', token=token)
            profile_username = None
            if isinstance(profile_resp['data'], dict):
                profile_username = profile_resp['data'].get('username')
            
            self.assert_test(
                "Profile username matches registration",
                profile_username == 'consistent',
                f"Profile username: {profile_username}, Response: {profile_resp['data']}"
            )
            
            # Check in users list
            alice_token = self.tokens.get('alice')
            if alice_token:
                users_resp = await self.request('GET', '/users', token=alice_token)
                if users_resp['status'] == 200 and isinstance(users_resp['data'], dict):
                    users_data = users_resp['data'].get('users', [])
                    usernames = [u.get('username') if isinstance(u, dict) else str(u) for u in users_data]
                    self.assert_test(
                        "New user appears in users list",
                        'consistent' in usernames,
                        f"Usernames: {usernames}"
                    )
    
    async def run_all_tests(self):
        """Run comprehensive test suite"""
        print(f"🚀 Starting Comprehensive API Tests")
        print(f"🎯 Target: {self.base_url}")
        print(f"⏰ Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        try:
            # Test server connectivity
            resp = await self.request('GET', '/users')
            if resp['status'] == 0:
                print(f"❌ Cannot connect to server at {self.base_url}")
                print(f"   Make sure the server is running!")
                return
            
            # Run all test suites
            test_suites = [
                self.test_cors,
                self.test_registration,
                self.test_username_check,
                self.test_login,
                self.test_authentication,
                self.test_profile,
                self.test_users_list,
                self.test_user_details,
                self.test_password_change,
                self.test_logout,
                self.test_user_deletion,
                self.test_edge_cases,
                self.test_consistency,
            ]
            
            for test_suite in test_suites:
                try:
                    await test_suite()
                except Exception as e:
                    print(f"❌ Test suite {test_suite.__name__} crashed: {e}")
                    self.result.add_test(f"{test_suite.__name__} (crashed)", False, str(e))
                
                # Small delay between test suites
                await asyncio.sleep(0.1)
            
        except KeyboardInterrupt:
            print(f"\n⚠️  Tests interrupted by user")
        except Exception as e:
            print(f"❌ Test execution failed: {e}")
        
        finally:
            self.result.print_summary()

async def main():
    """Main test runner"""
    print("🧪 Comprehensive API Test Suite")
    print("=" * 60)
    
    async with APITestClient() as client:
        await client.run_all_tests()

if __name__ == "__main__":
    asyncio.run(main())