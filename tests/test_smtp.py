import asyncio
import ssl
from collections.abc import AsyncIterator

import aiosmtplib
import pytest

from outbound_guard import OutboundDenied, OutboundGuard
from outbound_guard.smtp import connect_smtp


class FakeSMTPServer:
    def __init__(self) -> None:
        self.commands: list[str] = []
        self.connections = 0
        self.port = 0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        writer.write(b"220 ready\r\n")
        while line := (await reader.readline()).decode().strip():
            self.commands.append(line.split()[0].upper())
            match self.commands[-1]:
                case "EHLO":
                    writer.write(b"250-smtp\r\n250 AUTH PLAIN\r\n")
                case "AUTH":
                    writer.write(b"235 ok\r\n")
                case "QUIT":
                    writer.write(b"221 bye\r\n")
                    break
                case _:
                    writer.write(b"250 ok\r\n")
        writer.close()


@pytest.fixture
async def smtp_server() -> AsyncIterator[FakeSMTPServer]:
    fake = FakeSMTPServer()
    async with await asyncio.start_server(fake.handle, "127.0.0.1", 0) as server:
        fake.port = server.sockets[0].getsockname()[1]
        yield fake


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "127.1", "2130706433", "::1"])
async def test_smtp_connects_only_to_approved_addresses(host: str, smtp_server: FakeSMTPServer) -> None:
    with pytest.raises(OutboundDenied):
        await connect_smtp(OutboundGuard(), host, smtp_server.port)
    assert smtp_server.connections == 0


async def test_smtp_to_an_allowed_host(smtp_server: FakeSMTPServer) -> None:
    outbound = OutboundGuard([f"localhost:{smtp_server.port}"])
    async with await connect_smtp(outbound, "localhost", smtp_server.port, username="user", password="password") as client:
        assert client.hostname == "localhost"
        await client.noop()
    assert smtp_server.commands == ["EHLO", "AUTH", "NOOP", "QUIT"]


async def test_smtp_keeps_the_hostname_for_tls() -> None:
    server_names: list[str | None] = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.sni_callback = lambda _, name, __: server_names.append(name)
    async with await asyncio.start_server(lambda _, writer: writer.close(), "127.0.0.1", 0, ssl=context) as server:
        port = server.sockets[0].getsockname()[1]
        with pytest.raises(aiosmtplib.SMTPException):
            await connect_smtp(OutboundGuard(["localhost"]), "localhost", port, use_tls=True, timeout=1)
    assert server_names == ["localhost"]
