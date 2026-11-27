import asyncio
import errno
import logging
import socket
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any

from outbound_guard.addresses import is_public_address
from outbound_guard.destinations import Destination, is_ip_address, normalize_host, parse_destination

logger = logging.getLogger("outbound_guard")

NOT_PUBLIC = "not a public address"
NOT_CANONICAL = "not a canonical IP address"

type AllowedHostsProvider = Callable[[], Awaitable[Iterable[str]]]
type AddrInfo = tuple[
    socket.AddressFamily, socket.SocketKind, int, str, tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]
]


class OutboundDenied(OSError):
    """Raised when a destination resolves only to addresses that are neither public nor allowed."""

    def __init__(self, host: str, port: int | None, reason: str) -> None:
        super().__init__(errno.EACCES, f"Connections to {host}:{port} are not allowed: {reason}")
        self.host = host
        self.port = port
        self.reason = reason

    def __reduce__(self) -> tuple[type["OutboundDenied"], tuple[str, int | None, str], dict[str, Any]]:
        return type(self), (self.host, self.port, self.reason), self.__dict__


def parse_allowlist(entries: Iterable[str]) -> frozenset[Destination]:
    if isinstance(entries, str):
        raise TypeError("Expected a collection of hosts, not a string")
    return frozenset(parse_destination(entry) for entry in entries)


def get_address(addr_info: AddrInfo) -> str:
    return str(addr_info[4][0])


class OutboundGuard:
    """Decides which addresses outbound connections may use.

    Public addresses are always allowed. Other addresses are allowed only if the requested host or the address itself,
    with or without the port, is in allowed_hosts: a collection of entries (see parse_destination), or an async
    function returning one, so changes apply to the next connection. If the function fails or returns invalid
    entries, nothing internal is allowed.

    denial_hint is appended to denial log messages (not to exceptions), e.g. to say where the allowlist is configured.
    """

    def __init__(self, allowed_hosts: Iterable[str] | AllowedHostsProvider = (), *, denial_hint: str = "") -> None:
        self._provider: AllowedHostsProvider | None = None
        self._allowed: frozenset[Destination] = frozenset()
        if callable(allowed_hosts):
            self._provider = allowed_hosts
        else:
            self._allowed = parse_allowlist(allowed_hosts)
        self.denial_hint = denial_hint

    async def get_allowed(self) -> frozenset[Destination]:
        if self._provider is None:
            return self._allowed
        try:
            entries = await self._provider()
            if not isinstance(entries, str):
                entries = list(entries)
        except Exception:
            logger.exception("Failed to load allowed hosts, no internal destinations are allowed")
            return frozenset()
        try:
            return parse_allowlist(entries)
        except (TypeError, ValueError):
            logger.error("Allowed hosts are not a collection of valid entries, no internal destinations are allowed")
            return frozenset()

    def deny(self, host: str, port: int | None, address: str, reason: str) -> OutboundDenied:
        logger.warning("Denied an outbound connection to %s:%s (%s): %s%s", host, port, address, reason, self.denial_hint)
        return OutboundDenied(host, port, reason)

    async def resolve(self, host: str, port: int) -> list[AddrInfo]:
        """Resolve host for a TCP connection, keeping only the approved addresses. Raises OutboundDenied if none are."""
        addr_infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
        return await ConnectionCheck(self, host, port).filter_approved(addr_infos, get_address)

    async def connect(self, host: str, port: int, timeout: float) -> socket.socket:
        """Open a TCP connection to host:port through approved addresses only, for protocols other than HTTP.

        Returns a connected blocking socket, which the caller owns. Raises OutboundDenied if no address is approved,
        TimeoutError or another OSError if connecting fails within timeout seconds.
        """
        deadline = asyncio.get_running_loop().time() + timeout
        async with asyncio.timeout_at(deadline):
            return await connect_to_any(await self.resolve(host, port), deadline)


class ConnectionCheck:
    """Approves the addresses of one connection to host:port."""

    def __init__(self, guard: OutboundGuard, host: str, port: int | None) -> None:
        self.guard = guard
        self.host = host
        self.port = port
        self.allowed: frozenset[Destination] | None = None

    async def is_allowed(self, address: str) -> bool:
        if self.allowed is None:
            self.allowed = await self.guard.get_allowed()
        names = {normalize_host(self.host), normalize_host(address)}
        return any(Destination(name, port) in self.allowed for name in names for port in (self.port, None))

    async def denial_reason(self, address: str) -> str | None:
        if not is_ip_address(address):
            return NOT_CANONICAL
        if not is_public_address(address) and not await self.is_allowed(address):
            return NOT_PUBLIC
        return None

    async def approve(self, address: str) -> None:
        if reason := await self.denial_reason(address):
            raise self.guard.deny(self.host, self.port, address, reason)

    async def filter_approved[T](self, results: Iterable[T], get_address: Callable[[T], str]) -> list[T]:
        """Keep the results whose address is approved. Raises OutboundDenied if there were results but none is."""
        approved, denied = [], {}
        for result in results:
            address = get_address(result)
            if reason := await self.denial_reason(address):
                denied[address] = reason
            else:
                approved.append(result)
        if denied and not approved:
            reasons = ", ".join(dict.fromkeys(denied.values()))
            raise self.guard.deny(self.host, self.port, ", ".join(denied), reasons)
        return approved


async def connect_to_any(addr_infos: Sequence[AddrInfo], deadline: float) -> socket.socket:
    loop = asyncio.get_running_loop()
    error = OSError(errno.EHOSTUNREACH, "No addresses to connect to")
    for index, (family, type_, proto, _, sockaddr) in enumerate(addr_infos):
        sock = socket.socket(family, type_, proto)
        try:
            sock.setblocking(False)
            async with asyncio.timeout((deadline - loop.time()) / (len(addr_infos) - index)):
                await loop.sock_connect(sock, sockaddr)
        except OSError as e:
            sock.close()
            error = e
        except BaseException:
            sock.close()
            raise
        else:
            sock.setblocking(True)
            return sock
    raise error
