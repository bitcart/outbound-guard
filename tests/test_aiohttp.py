import asyncio
import errno
import logging
import socket
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest
from aiohttp import ClientSession, ClientTimeout
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.connector import Connection

from outbound_guard import OutboundDenied, OutboundGuard
from outbound_guard.aiohttp import MAX_RESPONSE_SIZE, GuardedConnector, limited_response_class, session
from tests.conftest import PUBLIC_IP, ServerFactory


async def get_json(outbound: OutboundGuard, url: str, **kwargs: Any) -> Any:
    async with session(outbound) as client, client.get(url, **kwargs) as response:
        return await response.json()


class FakeResolver(AbstractResolver):
    def __init__(self, *answers: list[str]) -> None:
        self.answers = list(answers)

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET) -> list[ResolveResult]:
        return [
            ResolveResult(hostname=host, host=address, port=port, family=socket.AF_INET, proto=0, flags=0)
            for address in self.answers.pop(0)
        ]

    async def close(self) -> None:
        pass


def outcome(error: BaseException) -> str:
    if isinstance(error, aiohttp.ClientConnectorError) and isinstance(error.os_error, OutboundDenied):
        return "denied"
    if isinstance(error, aiohttp.InvalidURL):
        return "invalid"
    if isinstance(error, aiohttp.ClientConnectorDNSError):
        return "unresolved"
    return repr(error)


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "localhost",
        "localhost.",
        "LOCALHOST",
        "0.0.0.0",
        "[::1]",
        "[::]",
        "[::ffff:127.0.0.1]",
        "[::127.0.0.1]",
        "[64:ff9b::7f00:1]",
        "0x7f000001",
        "10.0.0.1",
        "169.254.169.254",
        "user:password@127.0.0.1",
        "①②⑦.0.0.1",
    ],
)
async def test_internal_hosts_are_denied(host: str, start_server: ServerFactory) -> None:
    server, port = await start_server()
    with pytest.raises(aiohttp.ClientError) as e:
        await get_json(OutboundGuard(), f"http://{host}:{port}/")
    assert outcome(e.value) == "denied"
    assert server.requests == []


@pytest.mark.parametrize(
    "host,outcomes",
    [
        ("2130706433", {"denied", "invalid"}),
        ("0177.0.0.1", {"denied", "invalid"}),
        ("127.1", {"denied", "invalid"}),
        ("%31%32%37.0.0.1", {"unresolved"}),
    ],
)
async def test_other_spellings_of_internal_hosts_fail(host: str, outcomes: set[str], start_server: ServerFactory) -> None:
    server, port = await start_server()
    with pytest.raises(aiohttp.ClientError) as e:
        await get_json(OutboundGuard(), f"http://{host}:{port}/")
    assert outcome(e.value) in outcomes
    assert server.requests == []


async def test_denials_are_logged(start_server: ServerFactory, caplog: pytest.LogCaptureFixture) -> None:
    _, port = await start_server()
    with caplog.at_level(logging.WARNING, "outbound_guard"), pytest.raises(aiohttp.ClientOSError) as e:
        await get_json(OutboundGuard(denial_hint=". Allow it in settings"), f"http://user:secret@localhost:{port}/")
    assert isinstance(e.value, aiohttp.ClientConnectorError)
    assert isinstance(e.value.os_error, OutboundDenied)
    assert "Allow it in settings" not in str(e.value)
    assert f"localhost:{port}" in caplog.text and "not a public address. Allow it in settings" in caplog.text
    assert "secret" not in caplog.text


async def test_allowed_destination_is_reachable(start_server: ServerFactory) -> None:
    server, port = await start_server()
    other, other_port = await start_server()
    outbound = OutboundGuard([f"127.0.0.1:{port}"])
    assert await get_json(outbound, f"http://127.0.0.1:{port}/direct") == {"ok": True}
    assert await get_json(outbound, f"http://localhost:{port}/by-name") == {"ok": True}
    with pytest.raises(aiohttp.ClientOSError):
        await get_json(outbound, f"http://127.0.0.1:{other_port}/")
    assert server.requests == ["GET /direct", "GET /by-name"]
    assert other.requests == []


async def test_allowlist_changes_apply_to_the_next_connection(start_server: ServerFactory) -> None:
    server, port = await start_server()
    allowed: list[str] = []
    provider = AsyncMock(side_effect=lambda: allowed)
    async with session(OutboundGuard(provider)) as client:
        assert isinstance(client.connector, GuardedConnector) and client.connector.use_dns_cache
        for _ in range(2):
            with pytest.raises(aiohttp.ClientOSError):
                await client.get(f"http://localhost:{port}/")
            allowed.append(f"localhost:{port}")
            async with client.get(f"http://localhost:{port}/", headers={"Connection": "close"}) as response:
                assert response.status == 200
            allowed.clear()
    assert len(server.requests) == 2
    assert provider.call_count == 4


async def test_allowlist_changes_apply_to_reused_connections(start_server: ServerFactory) -> None:
    server, port = await start_server()
    allowed = [f"localhost:{port}"]
    provider = AsyncMock(side_effect=lambda: allowed)
    async with session(OutboundGuard(provider)) as client:
        for path in ("/first", "/reused"):
            async with client.get(f"http://localhost:{port}{path}") as response:
                assert response.status == 200
        assert provider.call_count == 2
        allowed.clear()
        with pytest.raises(aiohttp.ClientConnectorError) as e:
            await client.get(f"http://localhost:{port}/removed")
        assert isinstance(e.value.os_error, OutboundDenied) and e.value.errno == errno.EACCES
        allowed.append(f"localhost:{port}")
        async with client.get(f"http://localhost:{port}/again") as response:
            assert response.status == 200
    assert server.requests == ["GET /first", "GET /reused", "GET /again"]
    assert len(server.peers) == 2


async def test_reused_public_connections_are_not_checked_again(
    start_server: ServerFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, port = await start_server()
    provider = AsyncMock(return_value=["127.0.0.1"])
    monkeypatch.setattr("outbound_guard.aiohttp.is_public_address", lambda address: True)
    async with session(OutboundGuard(provider)) as client:
        for _ in range(3):
            async with client.get(f"http://127.0.0.1:{port}/") as response:
                assert response.status == 200
    assert provider.call_count == 1


async def test_reused_connections_without_a_peer_address_are_denied(
    start_server: ServerFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    server, port = await start_server()
    async with session(OutboundGuard(["127.0.0.1"])) as client:
        async with client.get(f"http://127.0.0.1:{port}/") as response:
            assert response.status == 200
        monkeypatch.setattr(Connection, "transport", property(lambda self: None))
        with pytest.raises(aiohttp.ClientConnectorError, match="not a canonical IP address"):
            await client.get(f"http://127.0.0.1:{port}/")
    assert server.requests == ["GET /"]


async def test_every_redirect_hop_is_checked(start_server: ServerFactory) -> None:
    allowed, allowed_port = await start_server()
    internal, internal_port = await start_server()
    outbound = OutboundGuard([f"127.0.0.1:{allowed_port}"])
    allowed.redirect_to = f"http://127.0.0.1:{allowed_port}/final"
    assert await get_json(outbound, f"http://127.0.0.1:{allowed_port}/redirect") == {"ok": True}
    for host in ("127.0.0.1", "localhost"):
        allowed.redirect_to = f"http://{host}:{internal_port}/final"
        with pytest.raises(aiohttp.ClientOSError):
            await get_json(outbound, f"http://127.0.0.1:{allowed_port}/redirect")
    assert allowed.requests == ["GET /redirect", "GET /final", "GET /redirect", "GET /redirect"]
    assert internal.requests == []


@pytest.fixture
def dialled() -> tuple[list[str], Callable[[Any], socket.socket]]:
    addresses: list[str] = []

    def record(addr_info: Any) -> socket.socket:
        addresses.append(str(addr_info[4][0]))
        raise ConnectionRefusedError("not connecting in tests")

    return addresses, record


@pytest.mark.parametrize("use_dns_cache", [False, True])
async def test_dns_rebinding_is_denied(
    use_dns_cache: bool, start_server: ServerFactory, dialled: tuple[list[str], Callable[[Any], socket.socket]]
) -> None:
    server, port = await start_server()
    addresses, record = dialled
    resolver = FakeResolver([PUBLIC_IP], ["127.0.0.1"], [PUBLIC_IP, "127.0.0.1"])
    connector = GuardedConnector(OutboundGuard(), resolver=resolver, use_dns_cache=use_dns_cache, socket_factory=record)
    async with ClientSession(connector=connector) as client:
        for number in range(3):
            if use_dns_cache:
                connector.clear_dns_cache()
            with pytest.raises(aiohttp.ClientOSError) as e:
                await client.get(f"http://rebind.example.com:{port}/")
            assert isinstance(e.value, aiohttp.ClientConnectorDNSError) == (number == 1)
    assert resolver.answers == []
    assert addresses == [PUBLIC_IP, PUBLIC_IP]
    assert server.requests == []


async def test_cached_answers_are_checked(start_server: ServerFactory) -> None:
    _, port = await start_server()
    resolver = FakeResolver(["127.0.0.1"])
    allowed = [f"cached.example.com:{port}"]
    connector = GuardedConnector(OutboundGuard(AsyncMock(side_effect=lambda: allowed)), resolver=resolver)
    async with ClientSession(connector=connector) as client:
        async with client.get(f"http://cached.example.com:{port}/", headers={"Connection": "close"}) as response:
            assert response.status == 200
        allowed.clear()
        with pytest.raises(aiohttp.ClientOSError):
            await client.get(f"http://cached.example.com:{port}/")
    assert resolver.answers == []


async def test_proxies_are_not_used(
    start_server: ServerFactory, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    server, port = await start_server()
    proxy, proxy_port = await start_server()
    outbound = OutboundGuard(["127.0.0.1"])
    for name in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, f"http://127.0.0.1:{proxy_port}")
    assert await get_json(outbound, f"http://127.0.0.1:{port}/") == {"ok": True}
    with caplog.at_level(logging.WARNING, "outbound_guard"), pytest.raises(OSError, match="proxies are not supported"):
        await get_json(outbound, f"http://127.0.0.1:{port}/", proxy=f"http://user:secret@127.0.0.1:{proxy_port}")
    assert caplog.messages == [
        f"Denied an outbound connection to 127.0.0.1:{port} (proxy 127.0.0.1): proxies are not supported"
    ]
    assert (server.requests, proxy.requests) == (["GET /"], [])
    for argument in ({"trust_env": True}, {"connector": None}, {"response_class": None}):
        with pytest.raises(TypeError):
            session(outbound, **argument)


async def test_response_size_is_limited(start_server: ServerFactory) -> None:
    _, port = await start_server()
    outbound = OutboundGuard(["127.0.0.1"])
    url = f"http://127.0.0.1:{port}/large"
    async with session(outbound, max_response_size=64 * 1024) as client, client.get(url) as response:
        assert response.headers["Content-Encoding"] == "gzip"
        assert len(await response.read()) == 64 * 1024
        assert len(await response.read()) == 64 * 1024
    async with session(outbound, max_response_size=64 * 1024 - 1) as client:
        for read in ("read", "text", "json"):
            async with client.get(url) as response:
                with pytest.raises(aiohttp.ClientPayloadError, match="larger than 65535 bytes"):
                    await getattr(response, read)()
                assert response.closed
    assert MAX_RESPONSE_SIZE == 16 * 1024 * 1024
    assert limited_response_class(1024) is limited_response_class(1024)


async def test_content_length_is_checked_first(start_server: ServerFactory) -> None:
    _, port = await start_server()
    async with session(OutboundGuard(["127.0.0.1"]), max_response_size=1024) as client:
        async with client.get(f"http://127.0.0.1:{port}/sized?size=1024") as response:
            assert len(await response.read()) == 1024
        async with client.get(f"http://127.0.0.1:{port}/stalled?size=1025") as response, asyncio.timeout(1):
            with pytest.raises(aiohttp.ClientPayloadError, match="larger than 1024 bytes"):
                await response.read()
            assert response.closed
        async with client.head(f"http://127.0.0.1:{port}/sized?size=2048") as response:
            assert response.content_length == 2048
            assert await response.read() == b""


async def test_traces_see_the_body(start_server: ServerFactory) -> None:
    _, port = await start_server()
    chunks: list[bytes] = []

    async def on_chunk(_: ClientSession, __: SimpleNamespace, params: aiohttp.TraceResponseChunkReceivedParams) -> None:
        chunks.append(params.chunk)

    trace_config = aiohttp.TraceConfig()
    trace_config.on_response_chunk_received.append(on_chunk)
    async with (
        session(OutboundGuard(["127.0.0.1"]), trace_configs=[trace_config]) as client,
        client.get(f"http://127.0.0.1:{port}/sized?size=10") as response,
    ):
        assert await response.read() == b"0" * 10
    assert chunks == [b"0" * 10]


async def test_timeouts(start_server: ServerFactory) -> None:
    _, port = await start_server()
    outbound = OutboundGuard(["127.0.0.1"])
    async with session(outbound) as client:
        assert client.timeout.total == 15
    with pytest.raises(TimeoutError):
        await get_json(outbound, f"http://127.0.0.1:{port}/slow", timeout=ClientTimeout(total=0.1))
