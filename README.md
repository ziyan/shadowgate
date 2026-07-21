# shadowgate

[![CI](https://github.com/ziyan/shadowgate/actions/workflows/ci.yml/badge.svg)](https://github.com/ziyan/shadowgate/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ziyan/shadowgate.svg)](https://pkg.go.dev/github.com/ziyan/shadowgate)
[![Go Report Card](https://goreportcard.com/badge/github.com/ziyan/shadowgate)](https://goreportcard.com/report/github.com/ziyan/shadowgate)

shadowgate is a lightweight, point-to-multipoint encrypted IP tunnel for Linux.
It creates a [TUN](https://www.kernel.org/doc/html/latest/networking/tuntap.html)
interface on both ends and carries IPv4 frames between them, running **both a
TCP and a UDP transport at the same time** and adapting between them.

- **Dual transport, always on** — the server listens on TCP and UDP at once, and
  the client opens both. There is no transport flag to set.
- **Adaptive client** — the client probes each path with keepalives, sends over
  the healthy path with the **lowest latency**, and switches automatically as
  conditions change — falling back to whichever path works if one is blocked or
  fails.
- **Authenticated encryption** — TCP uses a ChaCha20-Poly1305 record layer
  (Shadowsocks-AEAD style: a per-direction random salt, HKDF session keys, and a
  counter nonce per record). UDP uses per-packet XChaCha20-Poly1305. Both derive
  keys from the same password via PBKDF2, and both authenticate every record or
  packet so tampering and wrong passwords are rejected.
- **Obfuscated UDP** — each UDP datagram is `random-nonce || AEAD-ciphertext`
  with no handshake, no plaintext header, and randomized length padding, so a
  passive observer sees only high-entropy datagrams of varying size.
- **Optional compression** — TCP frames can be Snappy-compressed with
  `--compress` (off by default; compression is usually wasted on already-
  encrypted traffic and can leak length information).
- **Small** — a single static binary, no configuration files, no daemon
  dependencies beyond the `ip` command.
- **Multi-client** — a shared router learns client addresses from the traffic it
  sees and routes frames between connected clients (even across transports) as
  well as to its own TUN interface.

> **Note**
> shadowgate is a personal project and has **not** received a formal security
> audit. See [Security](#security) before relying on it.

## How it works

```
        client                                   server
 ┌──────────────────┐                    ┌──────────────────┐
 │       tun0       │                    │       tun0       │
 │   172.18.0.2     │                    │    172.18.0.1    │
 └────────┬─────────┘                    └─────────┬────────┘
          │            TCP (AEAD records)          │
          ├───────────────────────────────────────┤
          │      UDP (obfuscated datagrams)        │
          │  ── adaptively picks the faster path ──│
```

The server owns one address on the tunnel subnet and binds the same port on both
TCP and UDP; a shared router moves frames between the TUN device and whichever
transport a given client uses. Each client opens both transports to the server,
measures their round-trip time with keepalives, and sends tunnel traffic over the
healthiest, lowest-latency path — re-evaluating continuously so a path that
becomes slow, blocked, or dead is abandoned in favour of the other.

## Installation

### From source

Requires Go 1.25 or newer.

```bash
git clone https://github.com/ziyan/shadowgate.git
cd shadowgate
make build      # produces ./shadowgate
```

### With Docker

```bash
docker build -t shadowgate .
```

The container needs `NET_ADMIN` and access to `/dev/net/tun` to create the
interface (see below).

## Usage

shadowgate must run as root (or with `CAP_NET_ADMIN`) because it opens
`/dev/net/tun` and shells out to `ip` to configure the interface.

### Server

```bash
sudo shadowgate server \
  --ip 172.18.0.1/24 \
  --listen :3389 \
  --password "correct horse battery staple"
```

### Client

```bash
sudo shadowgate client \
  --ip 172.18.0.2/24 \
  --connect server.example.com:3389 \
  --password "correct horse battery staple"
```

The server binds both TCP and UDP on the given port, and the client opens both
to `--connect` — no transport selection is needed. Once both ends are up, the two
hosts can reach each other over the tunnel subnet (e.g. `ping 172.18.0.1` from
the client). Raise `--loglevel NOTICE` on the client to see it announce which
transport it is actively using as it adapts.

### Options

Global:

| Flag         | Default | Description                                               |
| ------------ | ------- | --------------------------------------------------------- |
| `--loglevel` | `INFO`  | `DEBUG`, `INFO`, `NOTICE`, `WARNING`, `ERROR`, `CRITICAL` |

`server` / `client`:

| Flag                     | Default (server / client)         | Description                                     |
| ------------------------ | --------------------------------- | ----------------------------------------------- |
| `--ip`                   | `172.18.0.1/24` / `172.18.0.2/24` | Tunnel address in CIDR notation                 |
| `--listen` / `--connect` | `:3389` / `127.0.0.1:3389`        | Address (TCP+UDP) to listen on / connect to     |
| `--password`             | *(empty)*                         | Shared secret used to derive the session keys   |
| `--compress`             | `false`                           | TCP: Snappy-compress the stream                 |
| `--padding`              | `256`                             | UDP: max random padding bytes per datagram      |
| `--ifname`               | *(kernel-assigned)*               | TUN interface name to create                    |
| `--persist`              | `false`                           | Keep the TUN interface after exit               |
| `--timeout`              | `2s`                              | Dial / network operation timeout                |

### The obfuscated UDP datagram

Each UDP datagram is `24-byte random nonce || XChaCha20-Poly1305 ciphertext`; the
encrypted payload includes a sequence number (for replay protection), the IPv4
frame, and `0..--padding` random bytes so datagram sizes vary. There is no
handshake and no plaintext field, so an on-path observer cannot fingerprint the
protocol by content or by a fixed packet size. This defends against **passive**
DPI; it does not attempt to defeat active probing (which would require mimicking
a real protocol such as HTTPS), and a censor doing entropy analysis may still
flag uniformly-random UDP.

### Running in Docker

```bash
docker run --rm -it \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  shadowgate client --connect server.example.com:3389 --password secret
```

## Security

- Confidentiality and integrity rest entirely on the shared `--password`. Use a
  long, high-entropy secret.
- Both transports use authenticated encryption (AEAD): the wrong password, and
  any tampering with a record or datagram, are detected and rejected. There is
  no forward secrecy — the keys are derived from the password alone — so a
  compromised password exposes past captured traffic.
- shadowgate has not undergone a professional security review; it is not a
  substitute for a formally audited VPN such as WireGuard in adversarial
  environments.
- **Transparent forwarding trusts every peer.** Because all peers share one
  password, the server cannot tell them apart: any peer can source frames from,
  and thus advertise a route for, any address (including one another's), and a
  forwarding-enabled client relays whatever it is handed. Run shadowgate only
  among mutually trusted machines, do not rely on tunnel source addresses for
  access control on the server, and constrain a relay client with host firewall
  rules. The routing table is size-bounded so a single peer cannot exhaust
  server memory, but it cannot prevent a trusted peer from hijacking another's
  route.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, coding
conventions, and how to run the linters and tests.

```bash
make build      # build ./shadowgate
make test       # run unit tests
make lint       # golangci-lint (+ mulint if installed)
make coverage   # tests with an HTML coverage report
```

## License

Released under the [MIT License](LICENSE).
