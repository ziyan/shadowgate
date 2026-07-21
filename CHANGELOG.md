# Changelog

All notable changes to shadowgate will be documented in this file.

The format is based loosely on Keep a Changelog, and versions are recorded using
repository tags.

## Unreleased

## [0.1.3] - 2026-07-21

### Added

- Automatic link reconnection. Each client link now re-dials its transport (with
  exponential backoff) whenever it fails, so a server restart or transient
  network drop self-heals instead of leaving the client stranded until it is
  manually restarted.

### Changed

- Raised the link health timeout to 10s so an occasional burst of packet loss no
  longer causes a needless transport failover; a link whose transport actually
  fails is now marked unhealthy immediately, so real failover is not slowed.

### Fixed

- Split the TCP `EncryptedConnection`'s persisted error into separate send and
  receive fields, removing a data race between the concurrent writer and reader.

## [0.1.2] - 2026-07-21

### Fixed

- Stabilized the client's adaptive transport selection. Round-trip time is now
  an exponential moving average, and the client only switches between two healthy
  links when one is faster by a large margin (2x) rather than 20%. Previously,
  jitter in per-sample RTT made the client flap between TCP and UDP every few
  seconds, which re-pinned the server's return route mid-flow and caused heavy
  packet loss in the server-to-client direction (a health failure still triggers
  an immediate switch).

## [0.1.1] - 2026-07-21

### Added

- `--mtu` flag to set the tun interface MTU. Lower it (e.g. `--mtu 1150`) so a
  full-size tunnel packet plus the UDP transport's per-datagram overhead
  (~54 bytes + padding) stays under the path MTU and does not fragment — without
  it, large downloads over UDP on a constrained path can stall.

## [0.1.0] - 2026-07-21

### Added

- Dual transport, always on: the server listens on TCP and UDP simultaneously on
  one port, and the client opens both. There is no transport flag.
- Adaptive multipath client: it probes each path with keepalives, measures
  round-trip time, sends over the healthy path with the lowest latency, and
  switches automatically — falling back when a path is blocked or fails.
- Obfuscated UDP transport: each IPv4 frame is carried in a single
  `random-nonce || XChaCha20-Poly1305` datagram with no handshake, no plaintext
  header, per-packet replay protection, and randomized length padding
  (`--padding`), so a passive observer sees only high-entropy datagrams of
  varying size.
- TCP now uses a ChaCha20-Poly1305 authenticated record layer (Shadowsocks-AEAD
  style: per-direction random salt, HKDF session keys, counter nonce per record),
  replacing the unauthenticated AES-CTR stream and closing the payload
  malleability gap.
- Transparent forwarding: the server can route traffic **through** a connected
  client to a network behind it (and between clients), and a client relays
  traffic for networks behind it. shadowgate no longer drops frames based on a
  node's own tunnel address — it forwards per the hosts' own routing tables — so
  a server frame for a behind-client network is sent to that client (learned from
  the client's traffic) instead of looping back to the server's tun.
- New packages with tests: `internal/core` (shared router), `internal/obfuscate`
  (UDP codec + replay window), `internal/udp` (UDP listener), `internal/tuntest`
  (in-memory tun), and `internal/e2e` (full client/server end-to-end tests over
  loopback covering both transports and fallback, no root or tun device needed).

### Changed

- Restructured the repository into `command/` (entrypoint) and `internal/`
  packages; the server is now a transport-agnostic router with pluggable TCP and
  UDP transports.
- Compression is now optional and **off by default** (`--compress`); it is
  usually wasted on encrypted traffic and can leak length information.
- TCP sockets set `TCP_NODELAY`.
- Migrated the CLI from `urfave/cli` v1 to v3.
- Upgraded to Go 1.25 and `golang/snappy` v1.0.0.
- Replaced Travis CI with GitHub Actions (lint, test, and build) and added a
  tag-triggered release workflow and Dependabot configuration.

### Fixed

- The routing table and the UDP peer table are size-bounded (per-client and
  overall) so a single client sourcing many (possibly spoofed) addresses cannot
  exhaust server memory; UDP peers are now keyed by socket address (one per
  client) and `Unregister` no longer scans the whole table under the lock. The
  transparent-forwarding trust model is documented in the README.
- TCP record layer derives per-direction keys with role-bound HKDF labels, so an
  on-path attacker can no longer reflect a peer's own records back at it.
- The server's return route to a client now follows whichever transport the
  client is actively using and recovers automatically after a transport fails,
  instead of being pinned to the first transport seen (which black-holed
  server→client traffic on failover). Idle UDP peers are expired after 60s so a
  silently-dead UDP path releases the return route (and to bound memory).
- The client's transport selection is sticky with a latency hysteresis margin, so
  two similar-latency links no longer flap per-packet (which reordered a flow
  across both transports); keepalive round-trip timing no longer under-measures
  links slower than the probe interval.
- `EncryptedConnection` now returns the persisted error instead of a nil error
  once a connection has failed.
- `tun.createInterface` now returns the underlying error instead of silently
  succeeding with an empty interface name when the `TUNSETIFF` ioctl fails.
- IPv4 frame decoding validates the header length so malformed packets can no
  longer panic when their payload or options are accessed.
- Goroutines recover from panics via `deferutil.Recover()` instead of crashing
  the process; the short-write path logs instead of calling `panic`.

### Added

- Unit tests for IPv4 frame encode/decode/split, the encryption handshake, the
  compressed connection, and version reporting.
- `internal/version` with version and commit injected at build time.
- Makefile, `.golangci.yml`, and `mulint.yaml` for reproducible builds and
  linting.
- Multi-stage Dockerfile that builds a static binary on top of Alpine with
  `iproute2`.
