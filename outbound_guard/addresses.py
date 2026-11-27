import ipaddress


def is_public_address(address: str) -> bool:
    """Whether an IP address is public. Raises ValueError if address is not an IP address."""
    ip = ipaddress.ip_address(address)
    is_site_local = isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or is_site_local)
