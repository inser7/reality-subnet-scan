# reality-subnet-scan

Finds a REALITY camouflage site in the same subnet as the VPS.

## Contents

- [Why](#why)
- [Checks](#checks)
- [Usage](#usage)
- [Output](#output)
- [Русская версия](README.ru.md)

## Why

The client connects to the server IP and presents someone else's name in TLS. If that name lives on another network (a `.ru` name on an Estonian address, for example), the mismatch is visible to filters. The scanner walks neighboring addresses and keeps a name only when the certificate name resolves to that same IP.

## Checks

Same handshake checks as [RealiTLScanner](https://github.com/XTLS/RealiTLScanner): TCP 443, TLS 1.3, HTTP/2. The name is also checked in DNS. Dropped names end in `.ru`, `.ir`, `.cn`, or `.su`, or contain `apple`, `icloud`, `microsoft`, `cloudflare`, or `duckdns`. Another server's REALITY certificate (`vk.com`, `github.com`, and the like) is left out of `MATCH` when its A record points elsewhere.

RealiTLScanner has no macOS build. If a tunnel captures the default route, scan from your own interface, not from the VPS.

## Usage

```bash
go run . -addr 203.0.113.0/24 -iface en0 -skip 203.0.113.10
```

Repeat `-addr` and `-skip` for more networks and for your own addresses.

## Output

A `TLS` line means the handshake matched. A `MATCH` line means the name has an A record on that IP and can be used as dest and SNI.
