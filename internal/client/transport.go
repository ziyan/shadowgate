package client

import "github.com/ziyan/shadowgate/internal/ipv4"

// transport is one physical path to the server that sends and receives whole
// IPv4 frames. A link serialises all sends through a single goroutine and reads
// through another, so implementations need not be safe for concurrent use.
type transport interface {
	name() string
	send(frame ipv4.Frame) error
	receive() (ipv4.Frame, error)
	close() error
}
