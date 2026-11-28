# Release Notes

## Latest changes

aiohttp: allowlist changes now apply to reused keep-alive connections too. Before, a session that kept using a connection to an internal address could keep reaching it after the address was removed from the allowlist

## 0.1.0

Initial release: `OutboundGuard` allows connections to public addresses and to the internal destinations you list, with helpers for raw sockets and optional integrations for aiohttp, SMTP (aiosmtplib) and SSH (paramiko)
