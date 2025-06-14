from aiohttp import web

async def get_hello(request):
    return web.Response(text="Hello from GET /hello")
async def post_hello(request):
    return web.Response(text="Created hello")
async def get_api_users(request):
    return web.json_response({"users": ["alice", "bob", "charlie"]})
async def get_users_id(request):
    user_id = request.match_info['id']
    return web.json_response({"user_id": user_id, "message": f"User {user_id} details"})
async def delete_users_id(request):
    user_id = request.match_info['id']
    return web.Response(text=f"Deleted user {user_id}")
async def get_users_id_posts_post_id(request):
    user_id = request.match_info['id']
    post_id = request.match_info['post_id']
    return web.json_response({"user_id": user_id, "post_id": post_id, "message": f"Post {post_id} from user {user_id}"})
async def get_api_users_id_profile(request):
    user_id = request.match_info['id']
    return web.json_response({"profile": f"Profile of user {user_id}"})

import os, sys, time, threading, hashlib

def watch_file():
    original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    while True: 
        time.sleep(2)
        current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        if current_hash != original_hash:
            os.execv(sys.executable, ['python'] + sys.argv)
threading.Thread(target=watch_file, daemon=True).start()

import re, inspect
app = web.Application()
for name, handler in list(globals().items()):
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route_parts = name[len(method)+1:].split('_')
            source = inspect.getsource(handler)
            params = re.findall(r"request\.match_info\['(\w+)'\]", source)
            
            for param in params:
                param_parts = param.split('_')
                for i in range(len(route_parts) - len(param_parts) + 1):
                    if route_parts[i:i+len(param_parts)] == param_parts:
                        route_parts[i:i+len(param_parts)] = [f'{{{param}}}']
                        break
            
            route = '/' + '/'.join(route_parts)
            app.router.add_route(method.upper(), route, handler)
            break
web.run_app(app)