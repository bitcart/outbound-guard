import functools
from collections.abc import Sequence
from typing import Any

from aiohttp import ClientPayloadError, ClientRequest, ClientResponse, ClientSession, ClientTimeout, TCPConnector
from aiohttp.abc import ResolveResult
from aiohttp.connector import Connection
from aiohttp.tracing import Trace

from outbound_guard.guard import ConnectionCheck, OutboundGuard

DEFAULT_TIMEOUT = ClientTimeout(total=15)
MAX_RESPONSE_SIZE = 16 * 1024 * 1024


class GuardedConnector(TCPConnector):
    """A TCPConnector that connects only to addresses the guard approves and refuses proxies.

    Other arguments are passed to TCPConnector.
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
        return await super().connect(req, traces, timeout)


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
