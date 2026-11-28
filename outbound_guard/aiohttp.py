import asyncio
import functools
from collections.abc import Sequence
from typing import Any

from aiohttp import (
    ClientConnectorError,
    ClientPayloadError,
    ClientRequest,
    ClientResponse,
    ClientSession,
    ClientTimeout,
    TCPConnector,
)
from aiohttp.abc import ResolveResult
from aiohttp.connector import Connection
from aiohttp.tracing import Trace

from outbound_guard.addresses import is_public_address
from outbound_guard.destinations import is_ip_address
from outbound_guard.guard import ConnectionCheck, OutboundDenied, OutboundGuard

DEFAULT_TIMEOUT = ClientTimeout(total=15)
MAX_RESPONSE_SIZE = 16 * 1024 * 1024


class GuardedConnector(TCPConnector):
    """A TCPConnector that connects only to addresses the guard approves and refuses proxies.

    Connections to addresses that are not public are checked again before each request, so allowlist changes apply to
    reused keep-alive connections too. Other arguments are passed to TCPConnector.
    """

    def __init__(self, guard: OutboundGuard, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.guard = guard

    async def _resolve_host(self, host: str, port: int, traces: Sequence[Trace] | None = None) -> list[ResolveResult]:
        results = await super()._resolve_host(host, port, traces)
        return await ConnectionCheck(self.guard, host, port).filter_approved(results, lambda result: result["host"])

    async def connect(self, req: ClientRequest, traces: list[Trace], timeout: ClientTimeout) -> Connection:
        if req.proxy:
            raise self.guard.deny(req.url.raw_host or "", req.url.port, f"proxy {req.proxy.host}", "proxies are not supported")
        loop = asyncio.get_running_loop()
        deadline = None if timeout.connect is None else loop.time() + timeout.connect
        connection = await super().connect(req, traces, timeout)
        try:
            async with asyncio.timeout_at(deadline):
                await self.check_peer(req, connection)
        except BaseException:
            connection.close()
            raise
        return connection

    async def check_peer(self, req: ClientRequest, connection: Connection) -> None:
        peer = connection.transport.get_extra_info("peername") if connection.transport else None
        address = str(peer[0]) if peer else ""
        if is_ip_address(address) and is_public_address(address):
            return
        try:
            await ConnectionCheck(self.guard, req.url.raw_host or "", req.url.port).approve(address)
        except OutboundDenied as e:
            raise ClientConnectorError(req.connection_key, e) from e


@functools.lru_cache
def limited_response_class(max_size: int) -> type[ClientResponse]:
    """A ClientResponse class whose read(), text() and json() raise ClientPayloadError past max_size bytes."""

    class LimitedResponse(ClientResponse):
        async def read(self) -> bytes:
            if self._body is None:
                try:
                    if (self.content_length or 0) > max_size and not self.content.at_eof():
                        raise ClientPayloadError(f"Response is larger than {max_size} bytes")
                    body = bytearray()
                    async for chunk in self.content.iter_any():
                        body += chunk
                        if len(body) > max_size:
                            raise ClientPayloadError(f"Response is larger than {max_size} bytes")
                    self._body = bytes(body)
                    for trace in self._traces:
                        await trace.send_response_chunk_received(self.method, self.url, self._body)
                except BaseException:
                    self.close()
                    raise
            return await super().read()

    return LimitedResponse


def session(
    guard: OutboundGuard,
    *,
    timeout: ClientTimeout = DEFAULT_TIMEOUT,
    max_response_size: int = MAX_RESPONSE_SIZE,
    **kwargs: Any,
) -> ClientSession:
    """Create an aiohttp session for URLs that users or other servers control.

    Connections go only to addresses the guard approves, otherwise aiohttp.ClientOSError is raised. Proxies are not
    used. Reading a response with read(), text() or json() raises aiohttp.ClientPayloadError past max_response_size
    bytes; iterating response.content directly is not limited. Other arguments are passed to aiohttp.ClientSession,
    except connector, response_class and trust_env.
    """
    return ClientSession(
        connector=GuardedConnector(guard),
        trust_env=False,
        timeout=timeout,
        response_class=limited_response_class(max_response_size),
        **kwargs,
    )
