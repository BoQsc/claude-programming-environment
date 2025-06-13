from aiohttp import web

async def get_hello(request):
    return web.Response(text="Hello from GET /hello")

async def post_hello(request):
    return web.Response(text="Created hello")

async def get_test(request):
    return web.Response(text="Hello from GET /test")

async def delete_users(request):
    return web.Response(text="Deleted users")

app = web.Application()
for name, handler in list(globals().items()):
    for method in ['get', 'post', 'put', 'delete', 'patch']:
        if name.startswith(f"{method}_"):
            route = name[len(method)+1:]  # Remove "method_" prefix
            app.router.add_route(method.upper(), f"/{route}", handler)
            break

web.run_app(app)