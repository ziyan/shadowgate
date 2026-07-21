package core

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/tuntest"
)

type recordingSink struct {
	mutex sync.Mutex
	count int
}

func (self *recordingSink) Send(frame ipv4.Frame) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.count++
}

func (self *recordingSink) received() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.count
}

func TestRouterRegisterEnsureUnregister(t *testing.T) {
	device := tuntest.New()
	serverIP := net.ParseIP("172.18.0.1")
	clientIP := net.ParseIP("172.18.0.2")
	_, network, err := net.ParseCIDR("172.18.0.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR: %s", err)
	}

	router := NewRouter(device, serverIP, network, nil)
	router.Start()
	defer router.Stop()

	toClient := ipv4.MakeFrame(serverIP, clientIP) // destination is the client
	firstSink := &recordingSink{}
	secondSink := &recordingSink{}

	router.Register(clientIP, firstSink)
	router.Inbound(toClient)
	if firstSink.received() != 1 {
		t.Fatalf("first sink received %d, want 1", firstSink.received())
	}

	// Register overwrites: a data frame moves the return route to the new sink.
	router.Register(clientIP, secondSink)
	router.Inbound(toClient)
	if secondSink.received() != 1 || firstSink.received() != 1 {
		t.Fatalf("after re-register: first=%d second=%d, want 1 and 1", firstSink.received(), secondSink.received())
	}

	// EnsureRoute does not steal an existing route.
	router.EnsureRoute(clientIP, firstSink)
	router.Inbound(toClient)
	if secondSink.received() != 2 || firstSink.received() != 1 {
		t.Fatalf("EnsureRoute stole the route: first=%d second=%d", firstSink.received(), secondSink.received())
	}

	// Unregister removes the route; the frame is dropped.
	router.Unregister(secondSink)
	router.Inbound(toClient)
	if secondSink.received() != 2 || firstSink.received() != 1 {
		t.Fatalf("frame delivered after unregister: first=%d second=%d", firstSink.received(), secondSink.received())
	}

	// EnsureRoute now fills the empty route (recovery after a transport dies).
	router.EnsureRoute(clientIP, firstSink)
	router.Inbound(toClient)
	if firstSink.received() != 2 {
		t.Fatalf("EnsureRoute did not fill empty route: first=%d", firstSink.received())
	}
}

func TestRouterBoundsRoutesPerSink(t *testing.T) {
	device := tuntest.New()
	serverIP := net.ParseIP("172.18.0.1")
	_, network, _ := net.ParseCIDR("172.18.0.0/24")
	router := NewRouter(device, serverIP, network, nil)

	// A single client that sources far more addresses than the cap must not grow
	// the table past the per-sink limit.
	sink := &recordingSink{}
	for i := 0; i < maxRoutesPerSink+100; i++ {
		router.Register(net.IPv4(10, byte(i>>16), byte(i>>8), byte(i)), sink)
	}

	router.mutex.Lock()
	perSink := len(router.sinkKeys[sink])
	total := len(router.routes)
	router.mutex.Unlock()
	if perSink != maxRoutesPerSink {
		t.Errorf("sink holds %d routes, want cap %d", perSink, maxRoutesPerSink)
	}
	if total != maxRoutesPerSink {
		t.Errorf("total routes %d, want %d", total, maxRoutesPerSink)
	}

	// Unregister must clear all of the sink's routes (and its index entry).
	router.Unregister(sink)
	router.mutex.Lock()
	total = len(router.routes)
	_, indexed := router.sinkKeys[sink]
	router.mutex.Unlock()
	if total != 0 || indexed {
		t.Errorf("after Unregister: routes=%d indexed=%v, want 0/false", total, indexed)
	}
}

func TestRouterForwardToClientEgress(t *testing.T) {
	device := tuntest.New()
	serverIP := net.ParseIP("172.18.0.1")
	clientIP := net.ParseIP("172.18.0.2")
	gatewayIP := net.ParseIP("172.18.0.9")
	external := net.ParseIP("1.1.1.1")
	_, network, _ := net.ParseCIDR("172.18.0.0/24")

	// A direct route wins over the resolver and the gateway.
	router := NewRouter(device, serverIP, network, gatewayIP)
	router.resolver = newNextHopResolver(func(source, destination net.IP) net.IP {
		t.Errorf("resolver consulted for a directly-routed destination")
		return nil
	})
	direct := &recordingSink{}
	router.Register(clientIP, direct)
	router.forwardToClient(ipv4.MakeFrame(serverIP, clientIP))
	if direct.received() != 1 {
		t.Fatalf("direct route: sink received %d, want 1", direct.received())
	}

	// The host's next hop toward an external destination is a connected client, so
	// egress is forwarded there.
	router = NewRouter(device, serverIP, network, nil)
	router.resolver = newNextHopResolver(func(source, destination net.IP) net.IP {
		if !destination.Equal(external) {
			t.Errorf("resolver asked for %s, want %s", destination, external)
		}
		return clientIP
	})
	nextHop := &recordingSink{}
	router.Register(clientIP, nextHop)
	router.forwardToClient(ipv4.MakeFrame(serverIP, external))
	if nextHop.received() != 1 {
		t.Fatalf("resolved next hop: sink received %d, want 1", nextHop.received())
	}

	// With no direct route and no resolvable next hop, the configured gateway
	// client carries the frame.
	router = NewRouter(device, serverIP, network, gatewayIP)
	router.resolver = newNextHopResolver(func(source, destination net.IP) net.IP { return nil })
	gateway := &recordingSink{}
	router.Register(gatewayIP, gateway)
	router.forwardToClient(ipv4.MakeFrame(serverIP, external))
	if gateway.received() != 1 {
		t.Fatalf("gateway fallback: sink received %d, want 1", gateway.received())
	}

	// With nothing to match, the frame is dropped (no panic, no loop back to tun).
	router = NewRouter(device, serverIP, network, nil)
	router.resolver = newNextHopResolver(func(source, destination net.IP) net.IP { return nil })
	router.forwardToClient(ipv4.MakeFrame(serverIP, external))
}

func TestNextHopResolverCaches(t *testing.T) {
	source := net.ParseIP("10.9.0.1")
	destination := net.ParseIP("1.1.1.1")
	nextHop := net.ParseIP("172.18.0.2")

	calls := 0
	resolver := newNextHopResolver(func(source, destination net.IP) net.IP {
		calls++
		return nextHop
	})
	now := time.Unix(0, 0)
	resolver.now = func() time.Time { return now }

	if got := resolver.resolve(source, destination); !got.Equal(nextHop) {
		t.Fatalf("resolve returned %s, want %s", got, nextHop)
	}
	if got := resolver.resolve(source, destination); !got.Equal(nextHop) {
		t.Fatalf("second resolve returned %s, want %s", got, nextHop)
	}
	if calls != 1 {
		t.Fatalf("lookup called %d times, want 1 (result should be cached)", calls)
	}

	// Past the TTL, the lookup is consulted again.
	now = now.Add(nextHopTtl + time.Second)
	if got := resolver.resolve(source, destination); !got.Equal(nextHop) {
		t.Fatalf("post-expiry resolve returned %s, want %s", got, nextHop)
	}
	if calls != 2 {
		t.Fatalf("lookup called %d times after expiry, want 2", calls)
	}
}

func TestRouterDeliversLocal(t *testing.T) {
	device := tuntest.New()
	serverIP := net.ParseIP("172.18.0.1")
	clientIP := net.ParseIP("172.18.0.2")
	_, network, _ := net.ParseCIDR("172.18.0.0/24")

	router := NewRouter(device, serverIP, network, nil)
	router.Start()
	defer router.Stop()

	toServer := ipv4.MakeFrame(clientIP, serverIP) // destination is the server itself
	router.Inbound(toServer)

	got, ok := device.Observe(time.Second)
	if !ok {
		t.Fatal("local frame was not written to the tun device")
	}
	if !bytes.Equal(got, toServer) {
		t.Errorf("tun received %x, want %x", got, toServer)
	}
}
