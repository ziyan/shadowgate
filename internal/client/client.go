// Package client implements the shadowgate client. It opens one or more links
// to the server — a TCP link and a UDP link — probes each with keepalives, and
// sends tunnel traffic over the healthy link with the lowest latency, switching
// automatically as conditions change (or falling back when one path fails).
package client

import (
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/internal/deferutil"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/tun"
)

var log = logging.MustGetLogger("client")

// latencySwitchFactor is the hysteresis margin for switching between two
// *healthy* links purely for latency: the client stays on its current link
// unless another is faster by this factor (its smoothed RTT is less than the
// current link's divided by the factor). This — together with RTT smoothing —
// keeps the client from flapping when both links have similar latency, which
// would re-pin the server's return route mid-flow and cause heavy packet loss.
// A failed (unhealthy) link always triggers a switch regardless of this margin.
const latencySwitchFactor = 2

type Client struct {
	ip    net.IP
	tun   tun.TUN
	links []*link

	// active is the link currently chosen for outbound traffic. It is updated by
	// the monitor goroutine and read by the tun reader.
	active atomic.Pointer[link]

	closing   chan struct{}
	closeOnce sync.Once
	group     sync.WaitGroup
}

// NewClient opens the available transports to connect and tunnels over an
// already-opened tun device. It tries both UDP and TCP; whichever connects
// becomes a link, and the client adapts between them at runtime. It fails only
// if no transport can be established.
func NewClient(device tun.TUN, ip net.IP, network *net.IPNet, connect string, password []byte, useCompression bool, maxPadding int, timeout time.Duration) (*Client, error) {
	var links []*link

	if transport, err := dialUdp(connect, password, maxPadding, timeout); err != nil {
		log.Warningf("udp transport unavailable: %s", err)
	} else {
		links = append(links, newLink(transport, ip))
	}

	if transport, err := dialTcp(connect, password, useCompression, timeout); err != nil {
		log.Warningf("tcp transport unavailable: %s", err)
	} else {
		links = append(links, newLink(transport, ip))
	}

	if len(links) == 0 {
		return nil, errors.New("client: no transport could connect")
	}

	self := &Client{
		ip:      ip,
		tun:     device,
		links:   links,
		closing: make(chan struct{}),
	}
	self.active.Store(links[0])
	return self, nil
}

func (self *Client) Interface() string {
	return self.tun.Interface()
}

func (self *Client) Close() error {
	self.stop()
	return nil
}

func (self *Client) Run(signaling chan os.Signal) error {
	for _, current := range self.links {
		current.start()
	}

	self.group.Add(1)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.readTun()
	}()

	for _, current := range self.links {
		current := current
		self.group.Add(1)
		go func() {
			defer deferutil.Recover()
			defer self.group.Done()
			self.deliverFrames(current)
		}()
	}

	self.group.Add(1)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.monitor()
	}()

	<-signaling

	self.stop()
	return nil
}

func (self *Client) stop() {
	self.closeOnce.Do(func() {
		close(self.closing)
		_ = self.tun.Close()
		for _, current := range self.links {
			current.stop()
		}
	})
	self.group.Wait()
}

func (self *Client) readTun() {
	buffer := make([]byte, 65536)
	for {
		size, err := self.tun.Read(buffer)
		if err != nil {
			log.Warningf("failed to read from tun: %s", err)
			return
		}
		frame := ipv4.DecodeFrame(buffer[:size])
		if frame == nil {
			continue
		}
		if frame.Source().Equal(frame.Destination()) {
			continue // degenerate; also reserved for the keepalive convention
		}
		// Forward whatever the host routed into the tunnel — including traffic
		// from networks behind this client when it acts as a relay.
		if active := self.active.Load(); active != nil {
			active.Send(frame.Copy())
		}
	}
}

func (self *Client) deliverFrames(current *link) {
	for frame := range current.frames {
		if _, err := self.tun.Write(frame); err != nil {
			log.Warningf("failed to write to tun: %s", err)
		}
	}
}

// monitor periodically re-evaluates which link should carry outbound traffic.
func (self *Client) monitor() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			self.reselect()
		case <-self.closing:
			return
		}
	}
}

// reselect updates the active link. It prefers the healthy link with the lowest
// round-trip time, but sticks with the current link unless it becomes unhealthy
// or another link is faster by the hysteresis margin. When no link is healthy it
// moves to the one that replied most recently, the best guess at what will
// recover first.
func (self *Client) reselect() {
	current := self.active.Load()

	if best := self.bestHealthy(); best != nil {
		switch {
		case current == nil || !current.healthy():
			self.setActive(best)
		case best != current && best.rtt()*latencySwitchFactor < current.rtt():
			self.setActive(best)
		}
		return
	}

	if freshest := self.freshestLink(); freshest != nil && freshest != current {
		self.setActive(freshest)
	}
}

func (self *Client) bestHealthy() *link {
	var best *link
	for _, current := range self.links {
		if !current.healthy() {
			continue
		}
		if best == nil || current.rtt() < best.rtt() {
			best = current
		}
	}
	return best
}

func (self *Client) freshestLink() *link {
	var freshest *link
	newest := int64(-1)
	for _, current := range self.links {
		if reply := current.lastReply(); reply > newest {
			newest = reply
			freshest = current
		}
	}
	return freshest
}

func (self *Client) setActive(next *link) {
	if previous := self.active.Swap(next); previous != next {
		log.Noticef("active transport is now %s (rtt %s)", next.name(), next.rtt())
	}
}
