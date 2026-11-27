import asyncio
import copy
import errno
import logging
import pickle
import socket
import time
from collections.abc import AsyncIterator, Iterable, Iterator
from typing import Any
from unittest.mock import AsyncMock

import pytest

from outbound_guard import ConnectionCheck, OutboundDenied, OutboundGuard
from tests.conftest import PUBLIC_IP


def addr_info(address: str, port: int = 22) -> Any:
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))


@pytest.fixture
async def listener() -> AsyncIterator[int]:
    async with await asyncio.start_server(lambda _, writer: writer.close(), "127.0.0.1", 0) as server:
        yield server.sockets[0].getsockname()[1]


REFUSING_PORT, UNRESPONSIVE_PORT = 7, 9


@pytest.fixture
async def unreachable(monkeypatch: pytest.MonkeyPatch) -> list[socket.socket]:
    attempts = []
    loop = asyncio.get_running_loop()
    sock_connect = loop.sock_connect

    async def connect(sock: socket.socket, address: Any) -> None:
        if address[1] not in (REFUSING_PORT, UNRESPONSIVE_PORT):
            return await sock_connect(sock, address)
        attempts.append(sock)
        if address[1] == REFUSING_PORT:
            raise ConnectionRefusedError
        await asyncio.sleep(60)

    monkeypatch.setattr(loop, "sock_connect", connect)
    return attempts


@pytest.mark.parametrize(
    "entry,host,port,address,expected",
    [
        ("api.internal", "api.internal", 1, "10.0.0.1", True),
        ("api.internal", "API.INTERNAL.", 1, "10.0.0.1", True),
        ("api.internal:8080", "api.internal", 8080, "10.0.0.1", True),
        ("api.internal:8080", "api.internal", 80, "10.0.0.1", False),
        ("api.internal", "evil", 80, "10.0.0.1", False),
        ("10.0.0.1:80", "internal", 80, "10.0.0.1", True),
        ("10.0.0.1:80", "internal", 81, "10.0.0.1", False),
        ("10.0.0.1", "10.0.0.1.example.com", 80, "10.0.0.2", False),
        ("fd00::5", "internal", 80, "fd00:0::5", True),
        ("[fd00::5]:80", "fd00::5", 80, "fd00::5", True),
    ],
)
async def test_allowed_hosts_matching(entry: str, host: str, port: int, address: str, expected: bool) -> None:
    for allowed_hosts in ([entry], AsyncMock(return_value=[entry])):
        check = ConnectionCheck(OutboundGuard(allowed_hosts), host, port)
        assert await check.is_allowed(address) is expected


async def test_public_addresses_need_no_allowlist() -> None:
    provider = AsyncMock(return_value=["internal"])
    outbound = OutboundGuard(provider)
    for port in (443, 8080):
        await ConnectionCheck(outbound, "example.com", port).approve(PUBLIC_IP)
    provider.assert_not_called()


async def test_allowed_hosts_are_loaded_once_per_connection() -> None:
    provider = AsyncMock(return_value=["internal"])
    outbound = OutboundGuard(provider)
    for _ in range(2):
        check = ConnectionCheck(outbound, "internal", 80)
        for address in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
            await check.approve(address)
    assert provider.call_count == 2


def failing_rows() -> Iterator[str]:
    yield "internal"
    raise RuntimeError("database connection lost")


@pytest.mark.parametrize(
    "options",
    [
        {"side_effect": OSError("database is down")},
        {"return_value": ["internal", "user:secret@internal"]},
        {"return_value": None},
        {"return_value": "internal"},
        {"side_effect": lambda: failing_rows()},
    ],
)
async def test_nothing_internal_is_allowed_if_the_allowlist_is_unavailable(
    options: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    outbound = OutboundGuard(AsyncMock(**options))
    with pytest.raises(OutboundDenied):
        await ConnectionCheck(outbound, "internal", 80).approve("10.0.0.1")
    await ConnectionCheck(outbound, "example.com", 443).approve(PUBLIC_IP)
    assert "no internal destinations are allowed" in caplog.text
    assert "secret" not in caplog.text


@pytest.mark.parametrize("allowed_hosts", [["internal", "http://internal"], [None]])
def test_static_allowlist_is_validated(allowed_hosts: Iterable[Any]) -> None:
    with pytest.raises(ValueError):
        OutboundGuard(allowed_hosts)


def test_allowlist_is_not_a_string() -> None:
    with pytest.raises(TypeError):
        OutboundGuard("internal")


async def test_static_allowlist_can_be_any_iterable() -> None:
    outbound = OutboundGuard(host for host in ["internal"])
    for _ in range(2):
        await ConnectionCheck(outbound, "internal", 80).approve("10.0.0.1")


async def test_denials(caplog: pytest.LogCaptureFixture) -> None:
    outbound = OutboundGuard(denial_hint=". Allow it in settings")
    with caplog.at_level(logging.WARNING, "outbound_guard"), pytest.raises(OutboundDenied) as e:
        await ConnectionCheck(outbound, "internal", 80).approve("10.0.0.1")
    assert isinstance(e.value, OSError)
    assert (e.value.errno, e.value.host, e.value.port, e.value.reason) == (
        errno.EACCES,
        "internal",
        80,
        "not a public address",
    )
    assert str(e.value) == "[Errno 13] Connections to internal:80 are not allowed: not a public address"
    assert caplog.messages == [
        "Denied an outbound connection to internal:80 (10.0.0.1): not a public address. Allow it in settings"
    ]


@pytest.mark.parametrize("address", ["127.1", "2130706433", "0x7f000001", "localhost", ""])
async def test_only_canonical_addresses_are_approved(address: str) -> None:
    with pytest.raises(OutboundDenied, match="not a canonical IP address"):
        await ConnectionCheck(OutboundGuard(["localhost", "127.0.0.1"]), address, 80).approve(address)


async def test_filter_approved(caplog: pytest.LogCaptureFixture) -> None:
    check = ConnectionCheck(OutboundGuard(), "mixed.example.com", 22)
    with caplog.at_level(logging.WARNING, "outbound_guard"):
        assert await check.filter_approved(["10.0.0.1", PUBLIC_IP, "127.0.0.1"], str) == [PUBLIC_IP]
        assert await check.filter_approved([], str) == []
        assert caplog.messages == []
        with pytest.raises(OutboundDenied):
            await check.filter_approved(["10.0.0.1", "127.0.0.1"], str)
        with pytest.raises(OutboundDenied, match="not a canonical IP address, not a public address"):
            await check.filter_approved(["127.1", "10.0.0.1", "10.0.0.1"], str)
    assert caplog.messages == [
        "Denied an outbound connection to mixed.example.com:22 (10.0.0.1, 127.0.0.1): not a public address",
        "Denied an outbound connection to mixed.example.com:22 (127.1, 10.0.0.1): "
        "not a canonical IP address, not a public address",
    ]


def test_denials_can_be_pickled() -> None:
    denial = OutboundDenied("internal", 80, "not a public address")
    denial.add_note("while sending a webhook")
    for restored in (pickle.loads(pickle.dumps(denial)), copy.copy(denial)):
        assert (type(restored), restored.args, restored.host, restored.port, restored.reason, restored.__notes__) == (
            OutboundDenied,
            denial.args,
            "internal",
            80,
            "not a public address",
            ["while sending a webhook"],
        )


async def test_resolve_keeps_only_approved_addresses(monkeypatch: pytest.MonkeyPatch) -> None:
    infos = [addr_info("10.0.0.1"), addr_info(PUBLIC_IP)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    assert await OutboundGuard().resolve("mixed.example.com", 22) == infos[1:]
    assert await OutboundGuard(["mixed.example.com"]).resolve("mixed.example.com", 22) == infos
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos[:1])
    with pytest.raises(OutboundDenied):
        await OutboundGuard().resolve("internal.example.com", 22)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "127.1", "2130706433", "::1", "::ffff:127.0.0.1"])
async def test_connect_denies_internal_hosts(host: str, listener: int) -> None:
    with pytest.raises(OutboundDenied):
        await OutboundGuard().connect(host, listener, 5)


@pytest.mark.parametrize(
    "host,entry", [("127.0.0.1", "127.0.0.1"), ("localhost", "localhost"), ("127.1", "127.0.0.1"), ("2130706433", "127.0.0.1")]
)
async def test_connect_to_allowed_hosts(host: str, entry: str, listener: int) -> None:
    with await OutboundGuard([f"{entry}:{listener}"]).connect(host, listener, 5) as sock:
        assert sock.getpeername() == ("127.0.0.1", listener)
        assert sock.gettimeout() is None


async def test_connect_tries_addresses_in_order(
    listener: int, unreachable: list[socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    infos = [addr_info("127.0.0.1", REFUSING_PORT), addr_info("127.0.0.1", listener)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    with await OutboundGuard(["internal"]).connect("internal", listener, 5) as sock:
        assert sock.getpeername() == ("127.0.0.1", listener)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos[:1])
    with pytest.raises(ConnectionRefusedError):
        await OutboundGuard(["internal"]).connect("internal", listener, 5)
    assert len(unreachable) == 2 and all(sock.fileno() == -1 for sock in unreachable)


async def test_unresponsive_address_leaves_time_for_the_next(
    listener: int, unreachable: list[socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    infos = [addr_info("127.0.0.1", UNRESPONSIVE_PORT), addr_info("127.0.0.1", listener)]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    with await OutboundGuard(["internal"]).connect("internal", listener, 1) as sock:
        assert sock.getpeername() == ("127.0.0.1", listener)
    assert len(unreachable) == 1 and unreachable[0].fileno() == -1


async def test_connecting_times_out_across_addresses(
    unreachable: list[socket.socket], monkeypatch: pytest.MonkeyPatch
) -> None:
    infos = [addr_info("127.0.0.1", UNRESPONSIVE_PORT)] * 3
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: infos)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await OutboundGuard(["internal"]).connect("internal", UNRESPONSIVE_PORT, 0.3)
    assert time.monotonic() - started < 2
    assert len(unreachable) == 3 and all(sock.fileno() == -1 for sock in unreachable)


async def test_connect_needs_an_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    with pytest.raises(OSError) as e:
        await OutboundGuard().connect("empty.example.com", 25, 5)
    assert (type(e.value), e.value.errno) == (OSError, errno.EHOSTUNREACH)


async def test_resolving_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: time.sleep(0.5))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        await OutboundGuard().connect("smtp.example.com", 25, 0.05)
    assert time.monotonic() - started < 0.4


async def test_cancelled_connect_closes_the_socket(unreachable: list[socket.socket]) -> None:
    task = asyncio.create_task(OutboundGuard(["127.0.0.1"]).connect("127.0.0.1", UNRESPONSIVE_PORT, 5))
    async with asyncio.timeout(5):
        while not unreachable:
            await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert unreachable[0].fileno() == -1
