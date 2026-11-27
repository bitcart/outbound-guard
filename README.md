# outbound-guard

[![CI](https://github.com/bitcart/outbound-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/bitcart/outbound-guard/actions/workflows/ci.yml)
[![Codecov](https://img.shields.io/codecov/c/github/bitcart/outbound-guard?style=flat-square)](https://codecov.io/gh/bitcart/outbound-guard)
[![PyPI version](https://img.shields.io/pypi/v/outbound-guard.svg?style=flat-square)](https://pypi.python.org/pypi/outbound-guard/)
[![Docs](https://github.com/bitcart/outbound-guard/actions/workflows/docs.yml/badge.svg)](https://outbound-guard.bitcart.ai)

Keep outbound connections to user-supplied destinations away from internal networks (SSRF protection)

## Overview

Apps that send webhooks, fetch user-supplied URLs or connect to user-configured SMTP and SSH servers can be made to
reach their own internal network: databases, admin panels, cloud metadata endpoints. With outbound-guard, only public
addresses and the internal destinations you allow are reachable:

- DNS tricks and unusual ways of writing IP addresses don't get around it
- with aiohttp, redirects are checked too, proxies are refused, responses are size limited and requests time out by
  default
- the allowlist of internal destinations can be a fixed list or loaded from an async source like a database

The core has no dependencies. Integrations for aiohttp, SMTP (aiosmtplib) and SSH (paramiko) are optional extras.

For API reference see [the docs](https://outbound-guard.bitcart.ai)

## Installation

```bash
pip install "outbound-guard[aiohttp,smtp,ssh]"
```

Pick only the extras you need: `aiohttp`, `smtp`, `ssh`. Python 3.12.4 or newer is required.

## Usage

Create one guard and share it:

```python
from outbound_guard import OutboundGuard

guard = OutboundGuard()  # public addresses only
guard = OutboundGuard(["api.internal:8080", "192.168.1.5"], denial_hint=". Allow it in the outbound settings")
```

### aiohttp

```python
import aiohttp
from outbound_guard.aiohttp import session

async with session(guard) as client, client.post(webhook_url, json=payload) as response:
    data = await response.json()
```

`session()` returns an `aiohttp.ClientSession` with a 15 second total timeout and a 16 MiB response size limit
(`timeout=` and `max_response_size=` change them). Other arguments are passed to `ClientSession`. A denied connection
raises `aiohttp.ClientOSError` with `errno.EACCES`. A response over the limit raises `aiohttp.ClientPayloadError` from
`read()`, `text()` and `json()`; iterating `response.content` directly is not limited.

`GuardedConnector(guard, **kwargs)` and `limited_response_class(max_size)` are available for building sessions yourself.

### SMTP

```python
from outbound_guard.smtp import connect_smtp

async with await connect_smtp(guard, "smtp.example.com", 465, use_tls=True, username=user, password=password) as smtp:
    await smtp.send_message(message)
```

`connect_smtp()` returns a connected `aiosmtplib.SMTP`. Other arguments are passed to `aiosmtplib.SMTP`.

### SSH

```python
import paramiko
from outbound_guard.ssh import connect_ssh

client = paramiko.SSHClient()
client.load_system_host_keys()
await connect_ssh(guard, client, "server.example.com", username=user, password=password)
```

Other arguments are passed to `SSHClient.connect`.

### Other protocols

```python
sock = await guard.connect(host, port, timeout=10)  # a connected blocking socket.socket
addr_infos = await guard.resolve(host, port)  # getaddrinfo results with approved addresses only
```

Both raise `OutboundDenied` (an `OSError` with `errno.EACCES`) if no resolved address is approved.

## Allowlist

Public addresses are always allowed. Anything else is allowed only if it matches an allowlist entry:

- entries are `host`, `host:port`, `IP`, `IP:port` or `[IPv6]:port`, host names are case-insensitive. Anything else,
  like URLs, CIDR ranges or wildcards, is rejected: `parse_destination(entry)` raises `ValueError`, so you can use it to
  validate user input
- a connection to `host:port` that resolves to an internal `address` is allowed if `host` or `address` is in the
  allowlist, either with that port or without a port
- a host name entry trusts DNS for that name: `api.internal` allows whatever `api.internal` resolves to
- allowed destinations stay reachable through redirects

The allowlist is either a collection of entries, validated when the guard is created, or an async function returning
one:

```python
async def allowed_hosts() -> list[str]:
    return (await settings.load()).allowed_hosts


guard = OutboundGuard(allowed_hosts)
```

Changes apply to the next connection. If the function raises or returns an invalid entry, no internal destination is
allowed and the error is logged.

## Logging

Denials are logged as warnings to the `outbound_guard` logger with the host, port, address and reason, followed by
`denial_hint`. The hint is not included in exceptions, so they are safe to show to the users who supplied the
destination. Credentials from URLs are not logged.

## Limitations

- only connections made through the guard are checked. Other clients, libraries and subprocesses aren't, so a network
  level firewall is still a good idea as defense in depth
- the server's own public IP addresses are public: block them at the firewall if services listen on them

## Copyright and License

Copyright (C) 2026 MrNaif2018

Licensed under the [MIT license](LICENSE)
