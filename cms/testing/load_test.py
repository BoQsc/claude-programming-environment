#!/usr/bin/env python3
"""
Load testing and stress testing for the Flat Structured API
Tests the API under various load conditions to validate ~100 concurrent user capacity
"""

import asyncio
import aiohttp
import time
import random
import statistics
from typing import List, Dict, Any
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class LoadTestResult:
    """Load test result metrics"""
    total_requests: int
    successful_requests: int
    failed_requests: int
    total_time: float
    requests_per_second: float
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    error_rate: float


class LoadTester:
    """Load testing framework"""
    
    def __init__(self, base_url="http://localhost:8080"):
        self.base_url = base_url
        self.results: List[float] = []
        self.errors: List[str] = []
        
    async def make_request(self, session: aiohttp.ClientSession, method: str, 
                          endpoint: str, data: Dict = None, headers: Dict = None) -> float:
        """Make a single request and return response time"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{endpoint}"
            kwargs = {}
            if data:
                kwargs['json'] = data
            if headers:
                kwargs['headers'] = headers
            
            async with session.request(method, url, **kwargs) as response:
                await response.read()  # Consume response body
                
                if response.status >= 400:
                    self.errors.append(f"HTTP {response.status} for {method} {endpoint}")
                    return -1  # Mark as error
                
                return time.time() - start_time
                
        except Exception as e:
            self.errors.append(f"Exception for {method} {endpoint}: {str(e)}")
            return -1  # Mark as error
    
    async def run_load_test(self, concurrent_users: int, duration_seconds: int, 
                           test_scenarios: List[Dict]) -> LoadTestResult:
        """Run load test with specified parameters"""
        
        print(f"🚀 Starting load test: {concurrent_users} users for {duration_seconds}s")
        
        self.results = []
        self.errors = []
        
        async def user_simulation(user_id: int):
            """Simulate a single user's behavior"""
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=100)
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                
                end_time = time.time() + duration_seconds
                
                while time.time() < end_time:
                    # Choose random scenario
                    scenario = random.choice(test_scenarios)
                    
                    response_time = await self.make_request(
                        session, 
                        scenario['method'], 
                        scenario['endpoint'],
                        scenario.get('data'),
                        scenario.get('headers')
                    )
                    
                    if response_time >= 0:
                        self.results.append(response_time)
                    
                    # Random delay between requests (0.1 to 2 seconds)
                    await asyncio.sleep(random.uniform(0.1, 2.0))
        
        # Start load test
        start_time = time.time()
        
        # Create user simulation tasks
        tasks = [user_simulation(i) for i in range(concurrent_users)]
        
        # Wait for all users to complete
        await asyncio.gather(*tasks, return_exceptions=True)
        
        total_time = time.time() - start_time
        
        # Calculate metrics
        successful_requests = len(self.results)
        failed_requests = len(self.errors)
        total_requests = successful_requests + failed_requests
        
        if successful_requests > 0:
            avg_response_time = statistics.mean(self.results)
            min_response_time = min(self.results)
            max_response_time = max(self.results)
            median_response_time = statistics.median(self.results)
            
            sorted_results = sorted(self.results)
            p95_index = int(0.95 * len(sorted_results))
            p99_index = int(0.99 * len(sorted_results))
            p95_response_time = sorted_results[p95_index] if p95_index < len(sorted_results) else max_response_time
            p99_response_time = sorted_results[p99_index] if p99_index < len(sorted_results) else max_response_time
        else:
            avg_response_time = min_response_time = max_response_time = 0
            median_response_time = p95_response_time = p99_response_time = 0
        
        requests_per_second = total_requests / total_time if total_time > 0 else 0
        error_rate = (failed_requests / total_requests * 100) if total_requests > 0 else 0
        
        return LoadTestResult(
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            total_time=total_time,
            requests_per_second=requests_per_second,
            avg_response_time=avg_response_time,
            min_response_time=min_response_time,
            max_response_time=max_response_time,
            median_response_time=median_response_time,
            p95_response_time=p95_response_time,
            p99_response_time=p99_response_time,
            error_rate=error_rate
        )
    
    def print_results(self, result: LoadTestResult, test_name: str):
        """Print load test results"""
        print(f"\n📊 {test_name} Results")
        print("=" * 50)
        print(f"Total Requests:      {result.total_requests}")
        print(f"Successful:          {result.successful_requests}")
        print(f"Failed:              {result.failed_requests}")
        print(f"Error Rate:          {result.error_rate:.2f}%")
        print(f"Total Time:          {result.total_time:.2f}s")
        print(f"Requests/sec:        {result.requests_per_second:.2f}")
        print(f"Avg Response Time:   {result.avg_response_time*1000:.2f}ms")
        print(f"Min Response Time:   {result.min_response_time*1000:.2f}ms")
        print(f"Max Response Time:   {result.max_response_time*1000:.2f}ms")
        print(f"Median Response:     {result.median_response_time*1000:.2f}ms")
        print(f"95th Percentile:     {result.p95_response_time*1000:.2f}ms")
        print(f"99th Percentile:     {result.p99_response_time*1000:.2f}ms")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)} total):")
            for error in self.errors[:10]:  # Show first 10 errors
                print(f"   {error}")
            if len(self.errors) > 10:
                print(f"   ... and {len(self.errors) - 10} more errors")


async def test_basic_load():
    """Test basic load - health check endpoints"""
    
    tester = LoadTester()
    
    scenarios = [
        {'method': 'GET', 'endpoint': '/api/health'},
        {'method': 'GET', 'endpoint': '/api/status'},
        {'method': 'GET', 'endpoint': '/'},
    ]
    
    # Test with increasing load
    for concurrent_users in [10, 25, 50, 100]:
        result = await tester.run_load_test(
            concurrent_users=concurrent_users,
            duration_seconds=30,
            test_scenarios=scenarios
        )
        
        tester.print_results(result, f"Basic Load Test - {concurrent_users} Users")
        
        # Check if performance is acceptable
        if result.error_rate > 5.0:
            print(f"⚠️  Warning: High error rate ({result.error_rate:.2f}%) with {concurrent_users} users")
        if result.avg_response_time > 1.0:
            print(f"⚠️  Warning: High response time ({result.avg_response_time*1000:.2f}ms) with {concurrent_users} users")


async def test_authentication_load():
    """Test authentication endpoints under load"""
    
    tester = LoadTester()
    
    # Generate test users for registration
    scenarios = []
    for i in range(100):
        scenarios.append({
            'method': 'POST',
            'endpoint': '/api/auth/register',
            'data': {
                'username': f'loadtest_user_{i}_{random.randint(1000, 9999)}',
                'email': f'loadtest_{i}_{random.randint(1000, 9999)}@example.com',
                'password': 'loadtest123'
            }
        })
    
    result = await tester.run_load_test(
        concurrent_users=50,
        duration_seconds=60,
        test_scenarios=scenarios
    )
    
    tester.print_results(result, "Authentication Load Test")


async def test_database_operations_load():
    """Test database-heavy operations under load"""
    
    tester = LoadTester()
    
    # First, create a test user and get a token
    async with aiohttp.ClientSession() as session:
        # Register a test user
        user_data = {
            'username': f'loadtest_dbuser_{random.randint(1000, 9999)}',
            'email': f'loadtest_db_{random.randint(1000, 9999)}@example.com',
            'password': 'loadtest123'
        }
        
        async with session.post(f"{tester.base_url}/api/auth/register", json=user_data) as response:
            if response.status == 201:
                result_data = await response.json()
                token = result_data.get('token')
            else:
                print("Failed to create test user for database load test")
                return
    
    headers = {'Authorization': f'Bearer {token}'}
    
    scenarios = [
        # Create posts
        {
            'method': 'POST',
            'endpoint': '/api/posts',
            'headers': headers,
            'data': {
                'title': f'Load Test Post {random.randint(1000, 9999)}',
                'content': 'This is a load test post content. ' * 10,
                'tags': ['loadtest', 'performance']
            }
        },
        # Get posts
        {
            'method': 'GET',
            'endpoint': '/api/posts',
            'headers': headers
        },
        # Get collections
        {
            'method': 'GET',
            'endpoint': '/api/collections',
            'headers': headers
        }
    ]
    
    result = await tester.run_load_test(
        concurrent_users=75,
        duration_seconds=45,
        test_scenarios=scenarios
    )
    
    tester.print_results(result, "Database Operations Load Test")


async def test_mixed_workload():
    """Test mixed workload simulating real usage"""
    
    tester = LoadTester()
    
    # Create some test users and tokens first
    tokens = []
    async with aiohttp.ClientSession() as session:
        for i in range(10):
            user_data = {
                'username': f'mixedtest_user_{i}_{random.randint(1000, 9999)}',
                'email': f'mixedtest_{i}_{random.randint(1000, 9999)}@example.com',
                'password': 'mixedtest123'
            }
            
            async with session.post(f"{tester.base_url}/api/auth/register", json=user_data) as response:
                if response.status == 201:
                    result_data = await response.json()
                    tokens.append(result_data.get('token'))
    
    # Mixed scenarios simulating real usage patterns
    scenarios = []
    
    # Anonymous users (20% of traffic)
    scenarios.extend([
        {'method': 'GET', 'endpoint': '/api/health'},
        {'method': 'GET', 'endpoint': '/'},
        {'method': 'GET', 'endpoint': '/api/posts'},
    ] * 2)
    
    # Authenticated users (80% of traffic)
    for token in tokens:
        headers = {'Authorization': f'Bearer {token}'}
        scenarios.extend([
            # Read operations (60%)
            {'method': 'GET', 'endpoint': '/api/posts', 'headers': headers},
            {'method': 'GET', 'endpoint': '/api/auth/profile', 'headers': headers},
            {'method': 'GET', 'endpoint': '/api/posts', 'headers': headers},
            
            # Write operations (20%)
            {
                'method': 'POST',
                'endpoint': '/api/posts',
                'headers': headers,
                'data': {
                    'title': f'Mixed Workload Post {random.randint(1000, 9999)}',
                    'content': 'Mixed workload test content. ' * 5,
                    'tags': ['mixed', 'workload', 'test']
                }
            },
        ])
    
    result = await tester.run_load_test(
        concurrent_users=100,  # Target 100 concurrent users
        duration_seconds=120,   # 2 minute test
        test_scenarios=scenarios
    )
    
    tester.print_results(result, "Mixed Workload Test - 100 Concurrent Users")
    
    # Evaluate results against requirements
    print("\n🎯 Performance Evaluation")
    print("=" * 30)
    
    if result.error_rate < 1.0:
        print("✅ Error rate: EXCELLENT (< 1%)")
    elif result.error_rate < 5.0:
        print("✅ Error rate: GOOD (< 5%)")
    else:
        print("❌ Error rate: POOR (> 5%)")
    
    if result.avg_response_time < 0.1:
        print("✅ Response time: EXCELLENT (< 100ms)")
    elif result.avg_response_time < 0.5:
        print("✅ Response time: GOOD (< 500ms)")
    elif result.avg_response_time < 1.0:
        print("⚠️  Response time: ACCEPTABLE (< 1s)")
    else:
        print("❌ Response time: POOR (> 1s)")
    
    if result.requests_per_second > 500:
        print("✅ Throughput: EXCELLENT (> 500 req/s)")
    elif result.requests_per_second > 200:
        print("✅ Throughput: GOOD (> 200 req/s)")
    elif result.requests_per_second > 100:
        print("⚠️  Throughput: ACCEPTABLE (> 100 req/s)")
    else:
        print("❌ Throughput: POOR (< 100 req/s)")


async def test_stress_limits():
    """Test API under extreme stress to find breaking points"""
    
    print("\n🔥 Stress Testing - Finding Breaking Points")
    print("=" * 50)
    
    tester = LoadTester()
    
    scenarios = [
        {'method': 'GET', 'endpoint': '/api/health'},
        {'method': 'GET', 'endpoint': '/api/status'},
    ]
    
    # Gradually increase load until breaking point
    for concurrent_users in [200, 300, 500, 750, 1000]:
        print(f"\n🧪 Testing with {concurrent_users} concurrent users...")
        
        result = await tester.run_load_test(
            concurrent_users=concurrent_users,
            duration_seconds=30,
            test_scenarios=scenarios
        )
        
        print(f"   Requests/sec: {result.requests_per_second:.2f}")
        print(f"   Error rate: {result.error_rate:.2f}%")
        print(f"   Avg response: {result.avg_response_time*1000:.2f}ms")
        
        # Stop if error rate becomes too high
        if result.error_rate > 20.0:
            print(f"❌ Breaking point reached at {concurrent_users} users (error rate > 20%)")
            break
        elif result.avg_response_time > 5.0:
            print(f"❌ Breaking point reached at {concurrent_users} users (response time > 5s)")
            break


async def main():
    """Main load testing runner"""
    import sys
    
    if len(sys.argv) > 1:
        test_type = sys.argv[1]
        
        if test_type == "basic":
            await test_basic_load()
        elif test_type == "auth":
            await test_authentication_load()
        elif test_type == "database":
            await test_database_operations_load()
        elif test_type == "mixed":
            await test_mixed_workload()
        elif test_type == "stress":
            await test_stress_limits()
        elif test_type == "all":
            await test_basic_load()
            await test_authentication_load()
            await test_database_operations_load()
            await test_mixed_workload()
        elif test_type == "help":
            print("Load Testing Usage:")
            print("  python load_test.py basic     - Basic load test")
            print("  python load_test.py auth      - Authentication load test")
            print("  python load_test.py database  - Database operations test")
            print("  python load_test.py mixed     - Mixed workload (realistic)")
            print("  python load_test.py stress    - Stress test to breaking point")
            print("  python load_test.py all       - Run all tests except stress")
            return
        else:
            print(f"Unknown test type: {test_type}")
            print("Use 'python load_test.py help' for available options")
            return
    else:
        # Default: run mixed workload test
        await test_mixed_workload()


if __name__ == '__main__':
    asyncio.run(main())