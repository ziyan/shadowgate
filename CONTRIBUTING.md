# Contributing to shadowgate

## Development setup

```bash
git clone https://github.com/ziyan/shadowgate.git
cd shadowgate
make build
make test
```

### Requirements

- Go 1.25+
- golangci-lint
- goimports (for `make format`)
- mulint (optional; internal naming linter — `make lint` skips it when absent)

### Build commands

```bash
make build      # build the ./shadowgate binary
make test       # run unit tests
make coverage   # run tests with an HTML coverage report
make lint       # run golangci-lint and mulint
make format     # run gofmt and goimports
make vendor     # tidy and vendor dependencies
make clean      # remove build artifacts
```

Because shadowgate uses Linux-only TUN syscalls and shells out to `ip`, it only
builds and runs on Linux. Tests that need a real TUN device or the network are
not part of the unit suite; the packages exercised by `make test` (`ipv4`,
`secure`, `compress`, `version`) run anywhere.

## Code conventions

This project uses a modified naming convention that differs from standard Go in
several ways. All contributors must follow these rules; `mulint` enforces most
of them.

### Acronym casing

When the **first alphabetical character is capitalized**, capitalize the entire
acronym:

```go
// Correct
type SessionID string
func GetFTPID() string
var ReferenceURI string

// Wrong
type SessionId string
func GetFtpId() string
```

When the **first alphabetical character is lowercase**, capitalize only the
first letter of the acronym:

```go
// Correct
aesKey := key[:KeySize]
sessionId := "abc"
referenceUri := "https://..."

// Wrong
aesKey := key[:KeySize] // (AESKey)
sessionID := "abc"
referenceURI := "https://..."
```

Project-specific acronyms (IPv4 header fields, crypto primitives, `TUN`) are
registered in `mulint.yaml`.

### No abbreviations

Spell out names in full. Do not abbreviate. Package names are the only exception
(keep them brief).

```go
// Correct
command, response, request, message, interfaceName

// Wrong
cmd, resp, req, msg, ifname
```

### Receiver names

Use `self` for struct method receivers:

```go
// Correct
func (self *Server) Close() error { ... }

// Wrong
func (s *Server) Close() error { ... }
```

### Errors

- Name error values `err`.
- Sentinel error strings are prefixed with the package name, e.g.
  `errors.New("secure: invalid password")`.

### Goroutines

Every goroutine (and every function launched with `go`) must begin with
`defer deferutil.Recover()` so a panic in one goroutine is logged instead of
crashing the whole process:

```go
go func() {
    defer deferutil.Recover()
    // ...
}()
```

## Project structure

```
command/              # main entrypoint
internal/
  cli/                # urfave/cli command wiring
  client/             # adaptive multipath client (tcp + udp links, probing)
  server/             # server orchestrator + TCP transport
  core/               # transport-agnostic router (tun device + routing table)
  udp/                # server-side UDP listener transport
  secure/             # ChaCha20-Poly1305 authenticated record layer (TCP)
  obfuscate/          # headerless UDP packet codec + replay window
  compress/           # optional Snappy compressed connection
  ipv4/               # zero-copy IPv4 frame view + stream splitter
  tun/                # Linux TUN interface
  tuntest/            # in-memory tun.TUN for tests
  e2e/                # full-stack end-to-end tests
  deferutil/          # deferred panic recovery helper
  version/            # version/commit injected at build time
vendor/               # vendored dependencies
```

## Dependencies

All dependencies are vendored. After changing `go.mod`:

```bash
make vendor   # go mod tidy && go mod vendor
```

Always use `-mod=vendor` when building or testing.

## Linting

The project uses:

- **golangci-lint** (config in `.golangci.yml`): errcheck, staticcheck, unused,
  govet, ineffassign. Three staticcheck rules are suppressed because they
  conflict with the conventions above (`ST1000`, `ST1003`, `ST1006`).
- **mulint** (config in `mulint.yaml`): the internal naming/convention linter.
  It is optional locally and skipped in CI, so run `make lint` before opening a
  PR if you have it installed.

## Commit messages

- Use imperative mood: "Add feature" not "Added feature".
- First line: concise summary (under 72 characters).
- Body: explain what and why, not how.
