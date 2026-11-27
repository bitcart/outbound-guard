import asyncio
from typing import Any

import paramiko

from outbound_guard.guard import OutboundGuard


async def connect_ssh(
    guard: OutboundGuard, client: paramiko.SSHClient, hostname: str, port: int = 22, *, timeout: float = 10, **kwargs: Any
) -> None:
    """Connect a paramiko.SSHClient to hostname:port through an address the guard approves.

    The hostname is kept for host key checks. timeout limits connecting and the key exchange. Other arguments are
    passed to SSHClient.connect, e.g. username, password, banner_timeout or auth_timeout.
    """
    sock = await guard.connect(hostname, port, timeout)
    try:
        await asyncio.to_thread(client.connect, hostname, port, sock=sock, timeout=timeout, **kwargs)
    except BaseException:
        client.close()
        sock.close()
        raise
