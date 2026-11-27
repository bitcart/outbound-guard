from typing import Any

import pytest

from outbound_guard import Destination, normalize_host, parse_destination


@pytest.mark.parametrize(
    "entry,host,port",
    [
        ("api.internal", "api.internal", None),
        ("API.Internal.", "api.internal", None),
        ("myapp_api_1:8080", "myapp_api_1", 8080),
        ("1password.com", "1password.com", None),
        ("4f2a9c1e7b3d", "4f2a9c1e7b3d", None),
        ("0xbox.internal", "0xbox.internal", None),
        ("192.168.1.5", "192.168.1.5", None),
        ("192.168.1.5:8080", "192.168.1.5", 8080),
        ("fd00::5", "fd00::5", None),
        ("[fd00::5]", "fd00::5", None),
        ("[FD00:0::5]:80", "fd00::5", 80),
    ],
)
def test_valid_entries(entry: str, host: str, port: int | None) -> None:
    assert parse_destination(entry) == Destination(host, port)


@pytest.mark.parametrize(
    "entry",
    [
        "",
        " api.internal",
        "10.0.0.0/8",
        "http://api.internal",
        "*.lan",
        "api.internal:http",
        "api.internal:",
        "user@api.internal",
        "user:password@api.internal",
        "api.internal:99999",
        "[fd00::5",
        "api.internal/path",
        "api.internal?query",
        "api.internal#fragment",
        ".lan",
        "api..internal",
        "192.168.1",
        "127.1",
        "127.1.",
        "2130706433",
        "0177",
        "0x7f000001",
        "1.0x1",
        "0x",
        None,
        1,
        [],
    ],
)
def test_invalid_entries(entry: Any) -> None:
    with pytest.raises(ValueError, match="is not a host or host:port"):
        parse_destination(entry)


@pytest.mark.parametrize(
    "host,expected",
    [("API.", "api"), ("localhost", "localhost"), ("FD00:0::5", "fd00::5"), ("::ffff:7f00:1", "::ffff:127.0.0.1")],
)
def test_normalize_host(host: str, expected: str) -> None:
    assert normalize_host(host) == expected
