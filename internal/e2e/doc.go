// Package e2e exercises the full client/server stack over real loopback sockets
// using an in-memory tun device. It contains only tests.
package e2e

import "github.com/op/go-logging"

var log = logging.MustGetLogger("e2e") //nolint:unused
