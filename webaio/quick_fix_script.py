#!/usr/bin/env python3
"""
Quick Fix Script for Blogging API WebSocket Issues
Run this to automatically fix the WebSocket problems
"""

import re
import os
import shutil
from pathlib import Path

def fix_blogging_api():
    """Fix the WebSocket issues in blogging_api.py"""
    
    api_file = Path('blogging_api.py')
    
    if not api_file.exists():
        print("❌ blogging_api.py not found!")
        print("Make sure you're in the correct directory.")
        return False
    
    print("🔧 Fixing blogging_api.py WebSocket issues...")
    
    # Create backup
    backup_file = api_file.with_suffix('.py.backup')
    shutil.copy2(api_file, backup_file)
    print(f"📋 Created backup: {backup_file}")
    
    # Read the file
    content = api_file.read_text(encoding='utf-8')
    
    # Fix 1: Update imports
    print("🔄 Fixing imports...")
    old_import = r'from aiohttp import web, ClientError'
    new_import = 'from aiohttp import web, ClientError, WSMsgType'
    
    if 'WSMsgType' not in content:
        content = re.sub(old_import, new_import, content)
        print("   ✅ Added WSMsgType import")
    else:
        print("   ✅ WSMsgType import already present")
    
    # Fix 2: Replace websocket_handler function
    print("🔄 Fixing WebSocket handler...")
    
    # Find the websocket_handler function
    websocket_pattern = r'async def websocket_handler\(request\):.*?return ws'
    
    new_websocket_handler = '''async def websocket_handler(request):
    """WebSocket handler for live updates"""
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    ws_manager = request.app['ws_manager']
    ws_manager.add_connection(ws)
    
    logger.info("WebSocket connection established")
    
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                    logger.debug(f"WebSocket message: {data}")
                    
                    # Handle different message types
                    if data.get('type') == 'ping':
                        await ws.send_str(json.dumps({'type': 'pong'}))
                        logger.debug("Sent pong response")
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON in WebSocket message: {e}")
                    await ws.send_str(json.dumps({'type': 'error', 'message': 'Invalid JSON'}))
                    
            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
                break
            elif msg.type == WSMsgType.CLOSE:
                logger.info("WebSocket closed by client")
                break
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        ws_manager.remove_connection(ws)
        logger.info("WebSocket connection closed")
    
    return ws'''
    
    # Replace the function
    content = re.sub(websocket_pattern, new_websocket_handler, content, flags=re.DOTALL)
    print("   ✅ Updated WebSocket handler function")
    
    # Fix 3: Fix any remaining web.MsgType references
    print("🔄 Fixing message type references...")
    content = content.replace('web.MsgType', 'WSMsgType')
    content = content.replace('aiohttp.WSMsgType', 'WSMsgType')
    print("   ✅ Updated message type references")
    
    # Write the fixed content back
    api_file.write_text(content, encoding='utf-8')
    
    print("✅ All fixes applied successfully!")
    print("\n📝 Changes made:")
    print("   • Added WSMsgType import")
    print("   • Fixed WebSocket handler function")
    print("   • Updated message type references")
    print(f"   • Backup saved as: {backup_file}")
    
    print("\n🚀 Now restart your blogging API:")
    print("   python blogging_api.py")
    
    return True

def test_fix():
    """Test if the fix was applied correctly"""
    api_file = Path('blogging_api.py')
    
    if not api_file.exists():
        print("❌ blogging_api.py not found!")
        return False
    
    content = api_file.read_text(encoding='utf-8')
    
    checks = [
        ('WSMsgType import', 'WSMsgType' in content and 'from aiohttp' in content),
        ('WebSocket handler updated', 'msg.type == WSMsgType.TEXT' in content),
        ('No web.MsgType references', 'web.MsgType' not in content),
    ]
    
    print("🧪 Testing fixes:")
    all_passed = True
    
    for check_name, condition in checks:
        if condition:
            print(f"   ✅ {check_name}")
        else:
            print(f"   ❌ {check_name}")
            all_passed = False
    
    if all_passed:
        print("\n🎉 All fixes verified successfully!")
    else:
        print("\n⚠️  Some fixes may not have been applied correctly.")
    
    return all_passed

if __name__ == '__main__':
    print("🔧 Blogging API WebSocket Fix Script")
    print("=" * 40)
    
    try:
        if fix_blogging_api():
            print("\n" + "=" * 40)
            test_fix()
            
            print("\n📋 Next Steps:")
            print("1. Restart your blogging API: python blogging_api.py")
            print("2. Restart your web client: python webclient.py")
            print("3. Open http://localhost/ in your browser")
            print("4. WebSocket should now work properly!")
            
    except Exception as e:
        print(f"\n❌ Error during fix: {e}")
        print("You may need to apply the fixes manually.")
        
    print("\n🎯 If you need to restore the original file:")
    print("   Copy blogging_api.py.backup back to blogging_api.py")
