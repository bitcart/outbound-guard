import contextlib
import socket
import threading
from collections.abc import Iterator

import paramiko
import pytest

from outbound_guard import OutboundDenied, OutboundGuard
from outbound_guard.ssh import connect_ssh


class Server(paramiko.ServerInterface):
    def check_auth_password(self, username: str, password: str) -> int:
        if (username, password) == ("user", "password"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"


class SSHServer:
    def __init__(self, host_key: paramiko.PKey) -> None:
        self.host_key = host_key
        self.transports: list[paramiko.Transport] = []
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        while not self.stopped.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            transport = paramiko.Transport(connection)
            transport.add_server_key(self.host_key)
            self.transports.append(transport)
            with contextlib.suppress(EOFError, OSError, paramiko.SSHException):
                transport.start_server(server=Server())

    def close(self) -> None:
        self.stopped.set()
        self.thread.join()
        self.listener.close()
        for transport in self.transports:
            transport.close()


@pytest.fixture(scope="session")
def host_key() -> paramiko.PKey:
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def ssh_server(host_key: paramiko.PKey) -> Iterator[SSHServer]:
    server = SSHServer(host_key)
    yield server
    server.close()


def make_client(server: SSHServer, hostname: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.get_host_keys().add(f"[{hostname}]:{server.port}", server.host_key.get_name(), server.host_key)
    return client


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "127.1", "::1"])
async def test_ssh_connects_only_to_approved_addresses(host: str, ssh_server: SSHServer) -> None:
    with make_client(ssh_server, host) as client:
        with pytest.raises(OutboundDenied):
            await connect_ssh(OutboundGuard(), client, host, ssh_server.port)
        assert client.get_transport() is None
    assert ssh_server.transports == []


async def test_ssh_keeps_the_hostname_for_host_keys(ssh_server: SSHServer) -> None:
    outbound = OutboundGuard([f"localhost:{ssh_server.port}"])
    with make_client(ssh_server, "localhost") as client:
        await connect_ssh(outbound, client, "localhost", ssh_server.port, username="user", password="password")
        transport = client.get_transport()
        assert transport is not None and transport.is_authenticated()
        assert transport.getpeername()[0] == "127.0.0.1"
    with (
        make_client(ssh_server, "127.0.0.1") as client,
        pytest.raises(paramiko.SSHException, match="not found in known_hosts"),
    ):
        await connect_ssh(outbound, client, "localhost", ssh_server.port, username="user", password="password")


async def test_failed_ssh_connections_are_closed(ssh_server: SSHServer) -> None:
    outbound = OutboundGuard([f"localhost:{ssh_server.port}"])
    with make_client(ssh_server, "localhost") as client:
        with pytest.raises(paramiko.AuthenticationException):
            await connect_ssh(outbound, client, "localhost", ssh_server.port, username="user", password="wrong")
        assert client.get_transport() is None
