import pytest

from outbound_guard import is_public_address

PUBLIC_ADDRESSES = [
    "8.8.8.8",
    "2606:4700::1111",
    "2001:4860:4860::8888",
    "::ffff:8.8.8.8",
    "192.88.99.1",
]
NON_PUBLIC_ADDRESSES = [
    "64:ff9b::808:808",
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "100.64.0.1",
    "100.100.100.200",
    "224.0.0.1",
    "239.255.255.250",
    "ff02::1",
    "ff0e::1",
    "0.0.0.0",
    "0.1.2.3",
    "::",
    "::1",
    "240.0.0.1",
    "255.255.255.255",
    "192.0.0.170",
    "198.18.0.1",
    "fec0::1",
    "fe80::1",
    "fe80::1%1",
    "fc00::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::127.0.0.1",
    "::10.0.0.1",
    "::8.8.8.8",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
    "64:ff9b::a00:1",
    "64:ff9b:1::808:808",
    "2002:7f00:1::",
    "2002:a9fe:a9fe::",
    "2002:808:808::",
    "2001:0:4136:e378:8000:63bf:80ff:fffe",
    "2001:0:808:808::",
    "2001:db8::1",
    "3fff::1",
]


@pytest.mark.parametrize("address", PUBLIC_ADDRESSES)
def test_public_addresses_are_allowed(address: str) -> None:
    assert is_public_address(address)


@pytest.mark.parametrize("address", NON_PUBLIC_ADDRESSES)
def test_other_addresses_are_denied(address: str) -> None:
    assert not is_public_address(address)


@pytest.mark.parametrize("value", ["localhost", "2130706433", "127.1", ""])
def test_only_ip_addresses_are_accepted(value: str) -> None:
    with pytest.raises(ValueError):
        is_public_address(value)
