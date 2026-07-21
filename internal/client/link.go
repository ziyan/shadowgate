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

	// healthTimeout is how long a link stays "healthy" after its last reply.
	healthTimeout = 4 * time.Second

	// unknownRtt is reported by a link that has not yet measured a round trip.
	unknownRtt = time.Hour

	// rttSmoothingShift sets the EWMA weight for round-trip samples: the estimate
	// keeps 1 - 1/2^shift of the old value and 1/2^shift of the new sample.
	rttSmoothingShift = 3 // alpha = 1/8
)

// link wraps a transport with keepalive probing and health/latency tracking.
// The server answers each keepalive (an IPv4 frame whose source equals its
// destination) with its own keepalive, which lets the link measure round-trip
// time and decide whether the path is currently usable.
type link struct {
	transport transport
	ip        net.IP

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

func newLink(transport transport, ip net.IP) *link {
	return &link{
		transport: transport,
		ip:        ip,
		outbound:  make(chan ipv4.Frame, 1024),
		frames:    make(chan ipv4.Frame, 1024),
		closing:   make(chan struct{}),
		now:       time.Now,
	}
}

func (self *link) name() string { return self.transport.name() }

func (self *link) start() {
	self.group.Add(2)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.sendLoop()
	}()
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.receiveLoop()
	}()
}

func (self *link) stop() {
	self.closeOnce.Do(func() {
		close(self.closing)
		_ = self.transport.close()
	})
	self.group.Wait()
	close(self.frames)
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

func (self *link) sendLoop() {
	ticker := time.NewTicker(pingInterval)
	defer ticker.Stop()

	self.ping() // probe immediately so health is learned quickly

	for {
		select {
		case frame := <-self.outbound:
			if err := self.transport.send(frame); err != nil {
				log.Warningf("link %s: failed to send frame: %s", self.name(), err)
				return
			}
		case <-ticker.C:
			self.ping()
		case <-self.closing:
			return
		}
	}
}

func (self *link) ping() {
	// Only begin a new round-trip measurement when the previous probe has been
	// answered; otherwise keep timing against the oldest outstanding probe so a
	// link slower than the ping interval is not under-measured.
	if atomic.LoadInt64(&self.lastPingNanos) <= atomic.LoadInt64(&self.lastReplyNanos) {
		atomic.StoreInt64(&self.lastPingNanos, self.now().UnixNano())
	}
	if err := self.transport.send(ipv4.MakeFrame(self.ip, self.ip)); err != nil {
		log.Debugf("link %s: failed to send keepalive: %s", self.name(), err)
	}
}

func (self *link) receiveLoop() {
	for {
		frame, err := self.transport.receive()
		if err != nil {
			select {
			case <-self.closing:
			default:
				log.Warningf("link %s: receive failed: %s", self.name(), err)
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
		}
	}
}
