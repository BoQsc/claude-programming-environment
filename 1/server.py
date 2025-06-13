from aiohttp import web



async def zzz(request):
    return web.Response(text="Hello from /zzz")

async def route_hello(request):
    return web.Response(text="Hello from /hello")

async def route_test(request):
    return web.Response(text="Hello from /test")



app = web.Application()
for name, handler in list(globals().items()):
    if (route := name.removeprefix("route_")) != name:
        app.router.add_get(f"/{route}", handler)

web.run_app(app)
