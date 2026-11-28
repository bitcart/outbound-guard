import asyncio
import contextlib
import errno
import ipaddress
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from typing import Any

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

PUBLIC_IP = "8.8.8.8"
LOCAL_NAMES = {"localhost", "localhost."}


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    external: list[Any] = []
    getaddrinfo = socket.getaddrinfo
    connect, connect_ex = socket.socket.connect, socket.socket.connect_ex

    def local_getaddrinfo(host: Any, port: Any, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0) -> Any:  # noqa: A002
        if host not in LOCAL_NAMES:
            flags |= socket.AI_NUMERICHOST
        return getaddrinfo(host, port, family, type, proto, flags)

    def is_external(sock: socket.socket, address: Any) -> bool:
        return sock.family in (socket.AF_INET, socket.AF_INET6) and not ipaddress.ip_address(address[0]).is_loopback

    def local_connect(self: socket.socket, address: Any) -> None:
        if is_external(self, address):
            external.append(address)
            raise ConnectionRefusedError("external connections are not allowed in tests")
        connect(self, address)

    def local_connect_ex(self: socket.socket, address: Any) -> int:
        if is_external(self, address):
            external.append(address)
            return errno.ECONNREFUSED
        return connect_ex(self, address)

    monkeypatch.setattr(socket, "getaddrinfo", local_getaddrinfo)
    monkeypatch.setattr(socket.socket, "connect", local_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", local_connect_ex)
    yield
    assert external == []


class FakeServer:
    def __init__(self) -> None:
        self.requests: list[str] = []
        self.peers: set[Any] = set()
        self.redirect_to = ""
        self.app = web.Application()
        self.app.router.add_route("*", "/redirect", self.redirect)
        self.app.router.add_route("*", "/large", self.large)
        self.app.router.add_route("*", "/sized", self.sized)
        self.app.router.add_route("*", "/stalled", self.stalled)
        self.app.router.add_route("*", "/slow", self.slow)
        self.app.router.add_route("*", "/{path:.*}", self.ok)

    async def ok(self, request: web.Request) -> web.Response:
        self.requests.append(f"{request.method} {request.path}")
        self.peers.add(request.transport.get_extra_info("peername") if request.transport else None)
        return web.json_response({"ok": True})

    async def redirect(self, request: web.Request) -> web.Response:
        self.requests.append(f"{request.method} {request.path}")
        raise web.HTTPTemporaryRedirect(self.redirect_to)

    async def large(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        response.enable_compression(web.ContentCoding.gzip)
        await response.prepare(request)
        with contextlib.suppress(OSError):
            for _ in range(64):
                await response.write(b"0" * 1024)
        return response

    async def sized(self, request: web.Request) -> web.Response:
        return web.Response(body=b"0" * int(request.query["size"]))

    async def stalled(self, request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse()
        response.content_length = int(request.query["size"])
        await response.prepare(request)
        await response.write(b"0")
        await asyncio.sleep(5)
        return response

    async def slow(self, request: web.Request) -> web.Response:
        await asyncio.sleep(5)
        return web.Response()


type ServerFactory = Callable[[], Awaitable[tuple[FakeServer, int]]]


@pytest.fixture
async def start_server() -> AsyncIterator[ServerFactory]:
    async with contextlib.AsyncExitStack() as stack:

        async def start() -> tuple[FakeServer, int]:
            fake = FakeServer()
            server = await stack.enter_async_context(TestServer(fake.app, host="127.0.0.1"))
            assert server.port
            return fake, server.port

        yield start
