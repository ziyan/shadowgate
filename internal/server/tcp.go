package server

import (
	"bufio"
	"io"
	"net"
	"sync"

	"github.com/ziyan/shadowgate/internal/compress"
	"github.com/ziyan/shadowgate/internal/core"
	"github.com/ziyan/shadowgate/internal/deferutil"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/secure"
)

// tcpTransport is the server-side TCP transport. Each accepted connection is a
// stream of IPv4 frames; the transport feeds received frames into the shared
// router and registers a tcpSink so the router can route frames back to the
// connection.
type tcpTransport struct {
	router   *core.Router
	listener net.Listener
	password []byte
	compress bool

	mutex       sync.Mutex
	connections map[io.Closer]struct{}
	group       sync.WaitGroup
	done        chan struct{}
}

func newTcpTransport(router *core.Router, listen string, password []byte, useCompression bool) (*tcpTransport, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	return &tcpTransport{
		router:      router,
		listener:    listener,
		password:    password,
		compress:    useCompression,
		connections: make(map[io.Closer]struct{}),
		done:        make(chan struct{}),
	}, nil
}

func (self *tcpTransport) Addr() net.Addr {
	return self.listener.Addr()
}

func (self *tcpTransport) Start() {
	self.group.Add(1)
	go func() {
		defer deferutil.Recover()
		defer self.group.Done()
		self.acceptLoop()
	}()
}

func (self *tcpTransport) Stop() {
	self.closeOnce()
	self.closeConnections()
	self.group.Wait()
}

func (self *tcpTransport) closeOnce() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	select {
	case <-self.done:
	default:
		close(self.done)
		_ = self.listener.Close()
	}
}

func (self *tcpTransport) acceptLoop() {
	for {
		conn, err := self.listener.Accept()
		if err != nil {
			select {
			case <-self.done:
			default:
				log.Warningf("failed to accept tcp connection: %s", err)
			}
			return
		}
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}

		wrapped := wrapConnection(conn, self.password, self.compress)
		if !self.track(wrapped) {
			_ = wrapped.Close()
			return
		}
		self.group.Add(1)
		go func() {
			defer deferutil.Recover()
			defer self.group.Done()
			self.handle(conn.RemoteAddr(), wrapped)
		}()
	}
}

func (self *tcpTransport) handle(address net.Addr, conn io.ReadWriteCloser) {
	log.Infof("client connection established: %v", address)

	sink := &tcpSink{frames: make(chan ipv4.Frame, 1024), closing: make(chan struct{})}

	writerDone := make(chan struct{})
	go func() {
		defer deferutil.Recover()
		defer close(writerDone)
		self.writer(conn, address, sink)
	}()

	self.reader(conn, address, sink)

	self.router.Unregister(sink)
	close(sink.closing)
	_ = conn.Close()
	<-writerDone

	self.untrack(conn)
	log.Infof("client connection closed: %v", address)
}

func (self *tcpTransport) reader(conn io.ReadWriteCloser, address net.Addr, sink *tcpSink) {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 65536), 65536)
	scanner.Split(ipv4.ScanFrame)

	for scanner.Scan() {
		frame := ipv4.Frame(scanner.Bytes())
		origin := frame.Source()
		if self.router.IP().Equal(origin) {
			continue // a client must not claim the server's own address
		}

		if origin.Equal(frame.Destination()) {
			// keepalive from client; keep a route available and reply
			self.router.EnsureRoute(origin, sink)
			sink.Send(ipv4.MakeFrame(self.router.IP(), self.router.IP()))
			continue
		}

		// A data frame. Learn a route back to its source (which may be a network
		// behind the client, letting the server route through the client) and pin
		// it to this transport, then forward the frame.
		self.router.Register(origin, sink)
		self.router.Inbound(frame.Copy())
	}

	if err := scanner.Err(); err != nil {
		log.Warningf("failed to read frame from %s: %s", address, err)
	}
}

func (self *tcpTransport) writer(conn io.ReadWriteCloser, address net.Addr, sink *tcpSink) {
	for {
		select {
		case frame := <-sink.frames:
			if _, err := conn.Write(frame); err != nil {
				log.Warningf("failed to write frame to client %s: %s", address, err)
			}
		case <-sink.closing:
			return
		}
	}
}

func (self *tcpTransport) track(conn io.Closer) bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	select {
	case <-self.done:
		return false
	default:
	}
	self.connections[conn] = struct{}{}
	return true
}

func (self *tcpTransport) untrack(conn io.Closer) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	delete(self.connections, conn)
}

func (self *tcpTransport) closeConnections() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	for conn := range self.connections {
		_ = conn.Close()
	}
}

// tcpSink routes frames toward one connected TCP client via a buffered channel
// drained by the connection's writer goroutine.
type tcpSink struct {
	frames  chan ipv4.Frame
	closing chan struct{}
}

func (self *tcpSink) Send(frame ipv4.Frame) {
	select {
	case self.frames <- frame:
	default:
		// the client's queue is full; drop rather than stall the router
	}
}

// wrapConnection layers encryption (always) and optional compression over a raw
// stream connection. The server is the responder of the encrypted session.
func wrapConnection(conn io.ReadWriteCloser, password []byte, useCompression bool) io.ReadWriteCloser {
	encrypted := secure.NewEncryptedConnection(conn, password, false)
	if !useCompression {
		return encrypted
	}
	return compress.NewCompressedConnection(encrypted)
}
