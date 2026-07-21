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

	mutex  sync.Mutex
	routes map[string]Sink

	toTun chan ipv4.Frame
	done  chan struct{}

	group sync.WaitGroup
}

func NewRouter(device tun.TUN, ip net.IP, network *net.IPNet) *Router {
	return &Router{
		ip:      ip,
		network: network,
		device:  device,
		routes:  make(map[string]Sink),
		toTun:   make(chan ipv4.Frame, 1024),
		done:    make(chan struct{}),
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
// using.
func (self *Router) Register(ip net.IP, sink Sink) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	key := ip.String()
	if existing, ok := self.routes[key]; !ok {
		log.Infof("new route registered: %s", key)
	} else if existing != sink {
		log.Infof("route for %s moved to a different transport", key)
	}
	self.routes[key] = sink
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
	log.Infof("new route registered: %s", key)
	self.routes[key] = sink
}

// Unregister removes every route pointing at the given sink.
func (self *Router) Unregister(sink Sink) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	for key, existing := range self.routes {
		if existing == sink {
			log.Infof("old route removed: %s", key)
			delete(self.routes, key)
		}
	}
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
// connected client that owns its destination. A destination with no registered
// route is dropped rather than written back to the tun (which would loop).
func (self *Router) forwardToClient(frame ipv4.Frame) {
	if sink, ok := self.sink(frame.Destination().String()); ok {
		sink.Send(frame)
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
