package udp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/internal/core"
	"github.com/ziyan/shadowgate/internal/deferutil"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/obfuscate"
)

var log = logging.MustGetLogger("udp")

const (
	// peerIdleTimeout is how long a UDP peer may go without any received
	// datagram before it is reaped. Because UDP is connectionless there is no
	// close event, so idle peers are expired to reclaim their route (letting the
	// client's other transport take over) and to bound memory.
	peerIdleTimeout = 60 * time.Second

	// reapInterval is how often idle UDP peers are swept.
	reapInterval = 15 * time.Second
)

// Listener is the server-side UDP transport. It reads obfuscated datagrams, and
// feeds decrypted frames into a core.Router; it registers a Sink per learned
// peer so the router can also route frames toward UDP clients.
type Listener struct {
	router *core.Router
	conn   *net.UDPConn
	codec  *obfuscate.Codec

	sequence uint64

	mutex sync.Mutex
	peers map[string]*udpPeer

	done  chan struct{}
	group sync.WaitGroup
}

type udpPeer struct {
	replay        obfuscate.ReplayWindow
	sink          core.Sink
	lastSeenNanos int64 // atomic; UnixNano of the last received datagram
}

// udpSink routes a frame toward one UDP client by its socket address.
type udpSink struct {
	listener *Listener
	address  *net.UDPAddr
}

func (self *udpSink) Send(frame ipv4.Frame) {
	self.listener.sendTo(self.address, frame)
}

func NewListener(router *core.Router, listen string, password []byte, maxPadding int) (*Listener, error) {
	key, err := obfuscate.DeriveKey(password)
	if err != nil {
		return nil, err
	}
	codec, err := obfuscate.NewCodec(key, maxPadding)
	if err != nil {
		return nil, err
	}
	address, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, err
	}
	return &Listener{
		router: router,
		conn:   conn,
		codec:  codec,
		peers:  make(map[string]*udpPeer),
		done:   make(chan struct{}),
	}, nil
}

// Addr reports the local UDP address the listener is bound to.
func (self *Listener) Addr() net.Addr {
	return self.conn.LocalAddr()
}

func (self *Listener) Start() {
	self.group.Add(2)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.readLoop()
	}()
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.reapLoop()
	}()
}

func (self *Listener) Stop() {
	close(self.done)
	_ = self.conn.Close()
	self.group.Wait()
}

func (self *Listener) reapLoop() {
	ticker := time.NewTicker(reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			self.reap()
		case <-self.done:
			return
		}
	}
}

// reap removes UDP peers that have gone silent, unregistering their routes so a
// still-alive transport for the same client can take over the return path.
func (self *Listener) reap() {
	cutoff := time.Now().UnixNano() - int64(peerIdleTimeout)

	var expired []core.Sink
	self.mutex.Lock()
	for key, client := range self.peers {
		if atomic.LoadInt64(&client.lastSeenNanos) < cutoff {
			expired = append(expired, client.sink)
			delete(self.peers, key)
			log.Debugf("udp peer expired: %s", key)
		}
	}
	self.mutex.Unlock()

	// unregister outside the lock to avoid nesting Listener.mutex and router.mutex
	for _, sink := range expired {
		self.router.Unregister(sink)
	}
}

func (self *Listener) readLoop() {
	buffer := make([]byte, 65536)
	for {
		size, address, err := self.conn.ReadFromUDP(buffer)
		if err != nil {
			select {
			case <-self.done:
			default:
				log.Warningf("failed to read datagram: %s", err)
			}
			return
		}

		sequence, _, payload, err := self.codec.Open(buffer[:size])
		if err != nil {
			log.Debugf("dropped undecryptable datagram from %s", address)
			continue
		}
		frame := ipv4.DecodeFrame(payload)
		if frame == nil {
			continue
		}
		source := frame.Source()
		if self.router.IP().Equal(source) {
			continue // a client must not claim the server's own address
		}

		client := self.peer(address)
		if !client.replay.Accept(sequence) {
			continue
		}
		atomic.StoreInt64(&client.lastSeenNanos, time.Now().UnixNano())

		if source.Equal(frame.Destination()) {
			// keepalive; keep a route available and reply
			self.router.EnsureRoute(source, client.sink)
			self.sendTo(address, ipv4.MakeFrame(self.router.IP(), self.router.IP()))
			continue
		}

		// A data frame: learn a route back to its source (a network behind the
		// client) via this client, then forward it.
		self.router.Register(source, client.sink)
		self.router.Inbound(frame.Copy())
	}
}

// peer returns the peer for a client socket address, creating it (and its sink)
// on first sight. Keying by socket address bounds the peer table to the number
// of connected clients, regardless of how many source addresses a client
// forwards. The route is not registered here; the read loop registers it per
// frame so the return path follows the client's active transport.
func (self *Listener) peer(address *net.UDPAddr) *udpPeer {
	key := address.String()
	self.mutex.Lock()
	defer self.mutex.Unlock()
	existing, ok := self.peers[key]
	if !ok {
		existing = &udpPeer{sink: &udpSink{listener: self, address: address}}
		self.peers[key] = existing
	}
	return existing
}

func (self *Listener) sendTo(address *net.UDPAddr, frame ipv4.Frame) {
	sequence := atomic.AddUint64(&self.sequence, 1)
	datagram, err := self.codec.Seal(sequence, 0, frame)
	if err != nil {
		log.Warningf("failed to seal frame: %s", err)
		return
	}
	if _, err := self.conn.WriteToUDP(datagram, address); err != nil {
		log.Warningf("failed to send datagram to %s: %s", address, err)
	}
}
