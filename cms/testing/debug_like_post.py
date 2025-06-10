#!/usr/bin/env python3
"""
Debug script to test the Like Post endpoint specifically
"""

import asyncio
import aiohttp
import json


async def debug_like_post():
    """Debug the like post functionality step by step"""
    
    base_url = "http://localhost:8080"
    
    async with aiohttp.ClientSession() as session:
        
        print("🔍 Debugging Like Post Endpoint")
        print("=" * 50)
        
        # Step 1: Register a user
        print("\n1. Registering a test user...")
        user_data = {
            'username': 'debug_user_like',
            'email': 'debug_like@example.com',
            'password': 'debug123'
        }
        
        async with session.post(f"{base_url}/api/auth/register", json=user_data) as response:
            if response.status == 201:
                reg_data = await response.json()
                token = reg_data['token']
                print(f"   ✅ User registered, token: {token[:20]}...")
            else:
                print(f"   ❌ Registration failed: {response.status}")
                text = await response.text()
                print(f"   Response: {text}")
                return
        
        # Step 2: Create a post
        print("\n2. Creating a test post...")
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        post_data = {
            'title': 'Debug Post for Like Test',
            'content': 'This is a test post for debugging the like functionality.',
            'tags': ['debug', 'test']
        }
        
        async with session.post(f"{base_url}/api/posts", json=post_data, headers=headers) as response:
            if response.status == 201:
                create_data = await response.json()
                post_id = create_data['post_id']
                print(f"   ✅ Post created with ID: {post_id}")
            else:
                print(f"   ❌ Post creation failed: {response.status}")
                text = await response.text()
                print(f"   Response: {text}")
                return
        
        # Step 3: Test like endpoint
        print(f"\n3. Testing like endpoint for post {post_id}...")
        like_url = f"{base_url}/api/posts/{post_id}/like"
        print(f"   URL: {like_url}")
        
        # For like endpoint, only send Authorization header (no Content-Type)
        like_headers = {'Authorization': f'Bearer {token}'}
        print(f"   Headers: {like_headers}")
        
        async with session.post(like_url, headers=like_headers) as response:
            print(f"   Status: {response.status}")
            print(f"   Response Headers: {dict(response.headers)}")
            
            try:
                data = await response.json()
                print(f"   Response JSON: {data}")
            except:
                text = await response.text()
                print(f"   Raw Response: {text}")
            
            if response.status == 200:
                print("   ✅ Like endpoint works!")
            else:
                print(f"   ❌ Like endpoint failed with status {response.status}")
        
        # Step 4: Verify the post was liked
        print(f"\n4. Checking if likes were incremented...")
        async with session.get(f"{base_url}/api/posts/{post_id}", headers=headers) as response:
            if response.status == 200:
                post_data = await response.json()
                likes = post_data.get('likes', 0)
                print(f"   Post now has {likes} likes")
            else:
                print(f"   Failed to get post: {response.status}")


async def test_like_directly():
    """Test like endpoint with minimal setup"""
    print("\n" + "=" * 50)
    print("🧪 Direct Like Test")
    print("=" * 50)
    
    base_url = "http://localhost:8080"
    
    async with aiohttp.ClientSession() as session:
        # Try to like a non-existent post (should get 404, not 400)
        print("\n1. Testing like on non-existent post...")
        
        # First register and get token
        user_data = {
            'username': 'direct_test_user',
            'email': 'direct@example.com',
            'password': 'direct123'
        }
        
        async with session.post(f"{base_url}/api/auth/register", json=user_data) as response:
            if response.status == 201:
                reg_data = await response.json()
                token = reg_data['token']
            else:
                print("Failed to register user for direct test")
                return
        
        headers = {'Authorization': f'Bearer {token}'}
        
        # Test like on fake post ID
        async with session.post(f"{base_url}/api/posts/fake-post-id/like", headers=headers) as response:
            print(f"   Status for fake post: {response.status}")
            text = await response.text()
            print(f"   Response: {text}")
        
        # Test like without auth
        print("\n2. Testing like without authentication...")
        async with session.post(f"{base_url}/api/posts/fake-post-id/like") as response:
            print(f"   Status without auth: {response.status}")
            text = await response.text()
            print(f"   Response: {text}")


async def main():
    """Main debug function"""
    await debug_like_post()
    await test_like_directly()


if __name__ == '__main__':
    asyncio.run(main())