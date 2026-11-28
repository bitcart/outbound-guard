# Release Notes

## Latest changes

## 0.1.1

Fix allowlist changes not applying to reused keep-alive connections in the aiohttp integration: a session that kept reusing a connection to an internal address could still reach it after the address was removed from the allowlist. Such connections are now checked again before each request

## 0.1.0

Initial release: `OutboundGuard` allows connections to public addresses and to the internal destinations you list, with helpers for raw sockets and optional integrations for aiohttp, SMTP (aiosmtplib) and SSH (paramiko)
