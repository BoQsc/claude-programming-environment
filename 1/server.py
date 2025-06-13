import os, sys, time, threading, hashlib


from aiohttp import web
async def get_hello(request):
    return web.Response(text="Hello from GET /hello")
async def post_hello(request):
    return web.Response(text="Created hello")
async def get_test(request):
    return web.Response(text="Hello from GET /test")
async def get_api_users(request):
    return web.json_response({"users": ["alice", "bob"]})
async def delete_users(request):
    return web.Response(text="Deleted users")
    
    
    
    
def watch_file():
    original_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    while True: 
        time.sleep(2)
        current_hash = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
        if current_hash != original_hash:
            os.execv(sys.executable, ['python'] + sys.argv)

threading.Thread(target=watch_file, daemon=True).start()
app = web.Application()
for name, handler in list(globals().items()):
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route = name[len(method)+1:]
            app.router.add_route(method.upper(), f"/{route}", handler)
            break
web.run_app(app)