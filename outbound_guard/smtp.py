from typing import Any

import aiosmtplib

from outbound_guard.guard import OutboundGuard


async def connect_smtp(
    guard: OutboundGuard, hostname: str, port: int, *, timeout: float = 10, **kwargs: Any
) -> aiosmtplib.SMTP:
    """Create an aiosmtplib.SMTP client connected to hostname:port through an address the guard approves.

    The hostname is kept for TLS. timeout limits connecting and each SMTP command. Other arguments are passed to
    aiosmtplib.SMTP, e.g. username, password, use_tls or start_tls. The caller closes the client, e.g. with
    `async with await connect_smtp(...) as client:`.
    """
    client = aiosmtplib.SMTP(hostname=hostname, timeout=timeout, **kwargs)
    sock = await guard.connect(hostname, port, timeout)
    try:
        await client.connect(sock=sock)
    except BaseException:
        client.close()
        sock.close()
        raise
    return client
