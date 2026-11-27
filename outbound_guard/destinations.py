import ipaddress
import re
from typing import NamedTuple
from urllib.parse import urlsplit

HOST_PATTERN = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)*")
NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")


class Destination(NamedTuple):
    host: str
    port: int | None


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def is_host_name(host: str) -> bool:
    return bool(HOST_PATTERN.fullmatch(host)) and not NUMERIC_LABEL.fullmatch(host.rsplit(".", 1)[-1])


def normalize_host(host: str) -> str:
    """Canonical form of a host name or IP address."""
    return str(ipaddress.ip_address(host)) if is_ip_address(host) else host.lower().removesuffix(".")


def parse_destination(entry: str) -> Destination:
    """Parse an allowlist entry: host, host:port, IP, IP:port or [IPv6]:port.

    Raises ValueError for anything else, like URLs, CIDR ranges, wildcards, credentials or paths.
    """
    error = ValueError(f"{entry!r} is not a host or host:port")
    if not isinstance(entry, str):
        raise error
    if is_ip_address(entry):
        return Destination(normalize_host(entry), None)
    try:
        url = urlsplit(f"//{entry}")
        port = url.port
    except ValueError:
        raise error from None
    host = normalize_host(url.hostname or "")
    is_valid = is_ip_address(host) or is_host_name(host)
    if not is_valid or url.netloc != entry or url.username is not None or entry.endswith(":"):
        raise error
    return Destination(host, port)
