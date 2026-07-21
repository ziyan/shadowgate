// Package core holds the transport-agnostic heart of a shadowgate server: the
// tun device and the routing table that maps a tunnel address to the transport
// peer that owns it. Transports (TCP, UDP) plug into a Router by registering a
// Sink per peer and calling Inbound for frames they receive; the Router moves
// frames between the tun device and those sinks.
package core

import (
	"net"
	"sync"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/internal/deferutil"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/tun"
)

var log = logging.MustGetLogger("core")

const (
	// maxRoutesPerSink bounds how many destination routes a single client (sink)
	// may install, so one client relaying (or spoofing) many source addresses
	// cannot exhaust the routing table on its own.
	maxRoutesPerSink = 1024

	// maxRoutes bounds the total routing table size across all clients.
	maxRoutes = 65536
)

// Sink delivers a frame toward a single peer. Implementations must not block
// (drop the frame instead) so one slow or dead peer cannot stall routing.
type Sink interface {
	Send(frame ipv4.Frame)
}

// Router owns the tun device and the routing table shared by all transports.
type Router struct {
	ip      net.IP
	network *net.IPNet
	device  tun.TUN

	// gateway is the tunnel address of a client to which frames read from the tun
	// with no other route are sent (the --gateway fallback). It may be nil.
	gateway net.IP

	// resolver maps a frame's destination to the connected client the host's own
	// routing table would forward it through.
	resolver *nextHopResolver

	mutex  sync.Mutex
	routes map[string]Sink
	// sinkKeys is the reverse index (sink -> its route keys), used to bound and
	// unregister a sink's routes without scanning the whole table.
	sinkKeys map[Sink]map[string]struct{}

	toTun chan ipv4.Frame
	done  chan struct{}

	group sync.WaitGroup
}

// NewRouter creates a router for the given tun device and tunnel subnet. gateway,
// if non-nil, is the tunnel address of a client that receives frames read from
// the tun with no other route.
func NewRouter(device tun.TUN, ip net.IP, network *net.IPNet, gateway net.IP) *Router {
	return &Router{
		ip:       ip,
		network:  network,
		device:   device,
		gateway:  gateway,
		resolver: newNextHopResolver(netlinkNextHop),
		routes:   make(map[string]Sink),
		sinkKeys: make(map[Sink]map[string]struct{}),
		toTun:    make(chan ipv4.Frame, 1024),
		done:     make(chan struct{}),
	}
}

// Interface returns the name of the underlying tun interface.
func (self *Router) Interface() string {
	return self.device.Interface()
}

// IP returns the server's own tunnel address.
func (self *Router) IP() net.IP {
	return self.ip
}

// Network returns the tunnel subnet.
func (self *Router) Network() *net.IPNet {
	return self.network
}

// Start launches the tun read and write loops.
func (self *Router) Start() {
	self.group.Add(2)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.readTun()
	}()
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.writeTun()
	}()
}

// Stop signals shutdown, closes the tun device, and waits for the loops to end.
func (self *Router) Stop() {
	close(self.done)
	_ = self.device.Close()
	self.group.Wait()
}

// Register associates a tunnel address with the sink that reaches it, replacing
// any existing route. Transports call this for every data frame received from a
// client so the return path follows whichever transport the client is actively
// using. Because a client's frames may carry arbitrary (even spoofed) source
// addresses, the number of routes is bounded per sink and overall so one client
// cannot exhaust memory; excess routes are dropped.
func (self *Router) Register(ip net.IP, sink Sink) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	key := ip.String()
	existing, present := self.routes[key]
	if present && existing == sink {
		return
	}
	if !self.hasCapacity(sink, present) {
		log.Debugf("route table full; dropping route for %s", key)
		return
	}
	if present {
		self.detach(existing, key)
	}
	self.attach(sink, key)
	log.Debugf("route registered: %s", key)
}

// EnsureRoute associates a tunnel address with a sink only if no route exists
// yet. Transports call this for keepalives so a route stays available (over
// whichever transport is still alive) without a keepalive on one transport
// stealing the return path from the transport actually carrying data.
func (self *Router) EnsureRoute(ip net.IP, sink Sink) {
	self.mutex.Lock()
	defer self.mutex.Unlock()

	key := ip.String()
	if _, ok := self.routes[key]; ok {
		return
	}
	if !self.hasCapacity(sink, false) {
		return
	}
	self.attach(sink, key)
	log.Debugf("route registered: %s", key)
}

// hasCapacity reports whether a route may be added for sink. movingKey is true
// when an existing route key is being moved to sink (so the global total does
// not grow).
func (self *Router) hasCapacity(sink Sink, movingKey bool) bool {
	if len(self.sinkKeys[sink]) >= maxRoutesPerSink {
		return false
	}
	if !movingKey && len(self.routes) >= maxRoutes {
		return false
	}
	return true
}

func (self *Router) attach(sink Sink, key string) {
	self.routes[key] = sink
	keys := self.sinkKeys[sink]
	if keys == nil {
		keys = make(map[string]struct{})
		self.sinkKeys[sink] = keys
	}
	keys[key] = struct{}{}
}

func (self *Router) detach(sink Sink, key string) {
	if keys := self.sinkKeys[sink]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(self.sinkKeys, sink)
		}
	}
}

// Unregister removes every route pointing at the given sink. It is O(routes for
// this sink), not a full-table scan, so a disconnecting client cannot stall the
// router while holding the lock.
func (self *Router) Unregister(sink Sink) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	for key := range self.sinkKeys[sink] {
		delete(self.routes, key)
	}
	delete(self.sinkKeys, sink)
}

func (self *Router) sink(ip string) (Sink, bool) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	existing, ok := self.routes[ip]
	return existing, ok
}

// Inbound routes a frame received from a transport peer (a client). Frames for
// the server's own tunnel address, and frames for destinations outside the
// tunnel subnet, are handed to the local tun so the server host forwards them
// per its own routing table (server acting as a gateway). Frames for another
// connected client are relayed to that client; frames for an unconnected
// in-subnet address are dropped.
func (self *Router) Inbound(frame ipv4.Frame) {
	destination := frame.Destination()
	if self.ip.Equal(destination) {
		self.deliverLocal(frame)
		return
	}
	if sink, ok := self.sink(destination.String()); ok {
		sink.Send(frame)
		return
	}
	if self.network.Contains(destination) {
		return // an in-subnet peer that is not connected; drop
	}
	self.deliverLocal(frame)
}

// forwardToClient routes a frame read from the server's OWN tun toward the
// connected client that should carry it. It tries, in order: a client that owns
// the destination directly; the client that is the host's own next hop toward
// the destination (so a route such as "default via <client> dev <tun>" makes
// egress through a client work); and the configured --gateway client. A frame
// with no match is dropped rather than written back to the tun (which would
// loop).
func (self *Router) forwardToClient(frame ipv4.Frame) {
	destination := frame.Destination()
	if sink, ok := self.sink(destination.String()); ok {
		sink.Send(frame)
		return
	}
	if nextHop := self.resolver.resolve(frame.Source(), destination); nextHop != nil {
		if sink, ok := self.sink(nextHop.String()); ok {
			sink.Send(frame)
			return
		}
	}
	if self.gateway != nil {
		if sink, ok := self.sink(self.gateway.String()); ok {
			sink.Send(frame)
		}
	}
}

func (self *Router) deliverLocal(frame ipv4.Frame) {
	select {
	case self.toTun <- frame:
	case <-self.done:
	}
}

func (self *Router) readTun() {
	buffer := make([]byte, 65536)
	for {
		size, err := self.device.Read(buffer)
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
		// forward whatever the server host routed into the tunnel to the client
		// that owns the destination.
		self.forwardToClient(frame.Copy())
	}
}

func (self *Router) writeTun() {
	for {
		select {
		case frame := <-self.toTun:
			if _, err := self.device.Write(frame); err != nil {
				log.Warningf("failed to write to tun: %s", err)
			}
		case <-self.done:
			return
		}
	}
}
