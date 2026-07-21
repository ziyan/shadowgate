package client

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ziyan/shadowgate/internal/deferutil"
	"github.com/ziyan/shadowgate/internal/ipv4"
)

const (
	// pingInterval is how often a link sends a keepalive probe.
	pingInterval = 1 * time.Second

	// healthTimeout is how long a link stays "healthy" after its last reply. It
	// is generous so an occasional burst of packet loss does not cause a needless
	// failover; a link whose transport actually fails is marked unhealthy
	// immediately (see supervise), so this does not slow real failover.
	healthTimeout = 10 * time.Second

	// unknownRtt is reported by a link that has not yet measured a round trip.
	unknownRtt = time.Hour

	// rttSmoothingShift sets the EWMA weight for round-trip samples: the estimate
	// keeps 1 - 1/2^shift of the old value and 1/2^shift of the new sample.
	rttSmoothingShift = 3 // alpha = 1/8

	// reconnect backoff bounds for re-dialing a failed transport.
	minReconnectBackoff = 1 * time.Second
	maxReconnectBackoff = 30 * time.Second
)

// dialer establishes a fresh transport to the server.
type dialer func() (transport, error)

// link keeps a transport to the server alive — re-dialing it whenever it fails —
// and tracks its health and latency by probing with keepalives. The server
// answers each keepalive (an IPv4 frame whose source equals its destination)
// with its own keepalive, which lets the link measure round-trip time and decide
// whether the path is currently usable.
type link struct {
	dial  dialer
	label string
	ip    net.IP

	outbound chan ipv4.Frame
	frames   chan ipv4.Frame

	rttNanos       int64 // atomic; nanoseconds, 0 means unknown
	lastReplyNanos int64 // atomic; UnixNano of the last keepalive reply
	lastPingNanos  int64 // atomic; UnixNano of the most recent probe sent

	closing   chan struct{}
	closeOnce sync.Once
	group     sync.WaitGroup

	now func() time.Time // injectable clock for tests; defaults to time.Now
}

func newLink(label string, dial dialer, ip net.IP) *link {
	return &link{
		dial:     dial,
		label:    label,
		ip:       ip,
		outbound: make(chan ipv4.Frame, 1024),
		frames:   make(chan ipv4.Frame, 1024),
		closing:  make(chan struct{}),
		now:      time.Now,
	}
}

func (self *link) name() string { return self.label }

func (self *link) start() {
	self.group.Add(1)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.supervise()
	}()
}

func (self *link) stop() {
	self.closeOnce.Do(func() {
		close(self.closing)
	})
	self.group.Wait()
	close(self.frames)
}

// supervise dials the transport and serves it, re-dialing with exponential
// backoff whenever it fails, until the link is closed.
func (self *link) supervise() {
	backoff := minReconnectBackoff
	for {
		select {
		case <-self.closing:
			return
		default:
		}

		transport, err := self.dial()
		if err != nil {
			log.Warningf("link %s: dial failed: %s", self.label, err)
			if !self.sleep(backoff) {
				return
			}
			backoff = nextBackoff(backoff)
			continue
		}
		backoff = minReconnectBackoff

		self.serve(transport)

		// The transport failed. Mark the link unhealthy right away so the client
		// fails over immediately rather than after the health timeout.
		atomic.StoreInt64(&self.lastReplyNanos, 0)
	}
}

func nextBackoff(current time.Duration) time.Duration {
	next := current * 2
	if next > maxReconnectBackoff {
		return maxReconnectBackoff
	}
	return next
}

// sleep waits for the given duration, returning false if the link is closed
// before it elapses.
func (self *link) sleep(duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-self.closing:
		return false
	}
}

// serve runs the send and receive loops over one transport until either fails or
// the link is closed, then closes the transport.
func (self *link) serve(transport transport) {
	atomic.StoreInt64(&self.lastPingNanos, 0) // measure RTT fresh on this connection

	failed := make(chan struct{})
	var failOnce sync.Once
	fail := func() { failOnce.Do(func() { close(failed) }) }

	var group sync.WaitGroup
	group.Add(2)
	go func() {
		defer deferutil.Recover()
		defer group.Done()
		defer fail()
		self.sendLoop(transport, failed)
	}()
	go func() {
		defer deferutil.Recover()
		defer group.Done()
		defer fail()
		self.receiveLoop(transport, failed)
	}()

	select {
	case <-failed:
	case <-self.closing:
	}
	_ = transport.close() // unblock a receive blocked in transport.receive
	group.Wait()
}

// Send queues a data frame for transmission, dropping it if the queue is full.
func (self *link) Send(frame ipv4.Frame) {
	select {
	case self.outbound <- frame:
	case <-self.closing:
	default:
	}
}

// healthy reports whether a keepalive reply arrived recently.
func (self *link) healthy() bool {
	last := atomic.LoadInt64(&self.lastReplyNanos)
	if last == 0 {
		return false
	}
	return self.now().UnixNano()-last < int64(healthTimeout)
}

// rtt returns the smoothed round-trip time, or unknownRtt if none measured yet.
func (self *link) rtt() time.Duration {
	value := atomic.LoadInt64(&self.rttNanos)
	if value == 0 {
		return unknownRtt
	}
	return time.Duration(value)
}

// recordRtt folds a new round-trip sample into an exponential moving average so
// per-sample jitter does not make transport selection flap. Only the receive
// loop calls this, so the load/store is free of a competing writer.
func (self *link) recordRtt(sample int64) {
	previous := atomic.LoadInt64(&self.rttNanos)
	if previous == 0 {
		atomic.StoreInt64(&self.rttNanos, sample)
		return
	}
	atomic.StoreInt64(&self.rttNanos, previous-(previous>>rttSmoothingShift)+(sample>>rttSmoothingShift))
}

// lastReply returns the UnixNano timestamp of the last keepalive reply, or 0.
func (self *link) lastReply() int64 {
	return atomic.LoadInt64(&self.lastReplyNanos)
}

func (self *link) sendLoop(transport transport, failed <-chan struct{}) {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	if !self.ping(transport) { // probe immediately so health is learned quickly
		return
	}

	for {
		select {
		case frame := <-self.outbound:
			if err := transport.send(frame); err != nil {
				log.Warningf("link %s: send failed: %s", self.label, err)
				return
			}
		case <-ticker.C:
			if !self.ping(transport) {
				return
			}
		case <-failed:
			return
		case <-self.closing:
			return
		}
	}
}

// ping sends a keepalive over the transport, returning false if the send failed
// (which means the transport is dead and the link should be re-dialed).
func (self *link) ping(transport transport) bool {
	// Only begin a new round-trip measurement when the previous probe has been
	// answered; otherwise keep timing against the oldest outstanding probe so a
	// link slower than the ping interval is not under-measured.
	if atomic.LoadInt64(&self.lastPingNanos) <= atomic.LoadInt64(&self.lastReplyNanos) {
		atomic.StoreInt64(&self.lastPingNanos, self.now().UnixNano())
	}
	if err := transport.send(ipv4.MakeFrame(self.ip, self.ip)); err != nil {
		log.Debugf("link %s: keepalive send failed: %s", self.label, err)
		return false
	}
	return true
}

func (self *link) receiveLoop(transport transport, failed <-chan struct{}) {
	for {
		frame, err := transport.receive()
		if err != nil {
			select {
			case <-self.closing:
			case <-failed:
			default:
				log.Warningf("link %s: receive failed: %s", self.label, err)
			}
			return
		}
		if frame == nil {
			continue
		}

		if frame.Source().Equal(frame.Destination()) {
			// keepalive reply from the server: update the smoothed round-trip time
			ping := atomic.LoadInt64(&self.lastPingNanos)
			now := self.now().UnixNano()
			if ping != 0 && now >= ping {
				self.recordRtt(now - ping)
			}
			atomic.StoreInt64(&self.lastReplyNanos, now)
			continue
		}

		// Deliver everything else to the tun; the host routes it (to this node,
		// or onward when this node forwards for a network behind it).
		select {
		case self.frames <- frame:
		case <-self.closing:
			return
		case <-failed:
			return
		}
	}
}
