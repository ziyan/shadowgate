// Package tuntest provides an in-memory tun.TUN implementation for tests. It
// lets a test inject IPv4 frames as if they arrived on the local interface and
// observe frames the tunnel writes back out, without a real tun device or root.
package tuntest

import (
	"net"
	"sync"
	"time"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("tuntest") //nolint:unused

// FakeTUN is an in-memory tun.TUN. Frames passed to Inject are returned by Read;
// frames written to the device are made available through Observe.
type FakeTUN struct {
	inbound   chan []byte
	outbound  chan []byte
	closeOnce sync.Once
	closed    chan struct{}
}

func New() *FakeTUN {
	return &FakeTUN{
		inbound:  make(chan []byte, 64),
		outbound: make(chan []byte, 64),
		closed:   make(chan struct{}),
	}
}

func (self *FakeTUN) Read(buffer []byte) (int, error) {
	select {
	case frame := <-self.inbound:
		return copy(buffer, frame), nil
	case <-self.closed:
		return 0, net.ErrClosed
	}
}

func (self *FakeTUN) Write(buffer []byte) (int, error) {
	frame := append([]byte(nil), buffer...)
	select {
	case self.outbound <- frame:
	case <-self.closed:
	}
	return len(buffer), nil
}

func (self *FakeTUN) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *FakeTUN) Interface() string { return "faketun" }

// Inject makes frame appear as if it was read from the local interface.
func (self *FakeTUN) Inject(frame []byte) {
	self.inbound <- append([]byte(nil), frame...)
}

// Observe returns the next frame written to the device, or false on timeout.
func (self *FakeTUN) Observe(timeout time.Duration) ([]byte, bool) {
	select {
	case frame := <-self.outbound:
		return frame, true
	case <-time.After(timeout):
		return nil, false
	}
}
