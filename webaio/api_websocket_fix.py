# Fix for blogging_api.py WebSocket handler
# Replace the websocket_handler function with this corrected version

from aiohttp import web, ClientError, WSMsgType
import json
import logging

logger = logging.getLogger(__name__)

async def websocket_handler(request):
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
    
    return ws

# Also need to update the imports at the top of blogging_api.py:
# Change this line:
# from aiohttp import web, ClientError
# To this:
# from aiohttp import web, ClientError, WSMsgType