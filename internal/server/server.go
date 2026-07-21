// Package server orchestrates a shadowgate server: it owns the shared router
// (tun device + routing table) and starts the enabled transports (TCP, UDP, or
// both), which all route through that single router so clients on different
// transports can reach each other.
package server

import (
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/internal/core"
	"github.com/ziyan/shadowgate/internal/tun"
	"github.com/ziyan/shadowgate/internal/udp"
)

var log = logging.MustGetLogger("server")

// Config selects which transports the server listens on and how they behave.
type Config struct {
	TCPListen string // TCP listen address; empty disables TCP
	UDPListen string // UDP listen address; empty disables UDP
	Password  []byte
	Compress  bool // TCP: Snappy-compress the stream
	Padding   int  // UDP: maximum random padding bytes per datagram
	Timeout   time.Duration
}

type Server struct {
	router *core.Router
	tcp    *tcpTransport
	udp    *udp.Listener

	stopOnce sync.Once
}

func NewServer(device tun.TUN, ip net.IP, network *net.IPNet, config Config) (*Server, error) {
	if config.TCPListen == "" && config.UDPListen == "" {
		return nil, errors.New("server: no transport enabled")
	}

	router := core.NewRouter(device, ip, network)
	self := &Server{router: router}

	if config.TCPListen != "" {
		transport, err := newTcpTransport(router, config.TCPListen, config.Password, config.Compress)
		if err != nil {
			return nil, err
		}
		self.tcp = transport
	}
	if config.UDPListen != "" {
		listener, err := udp.NewListener(router, config.UDPListen, config.Password, config.Padding)
		if err != nil {
			if self.tcp != nil {
				self.tcp.Stop()
			}
			return nil, err
		}
		self.udp = listener
	}

	return self, nil
}

func (self *Server) Interface() string {
	return self.router.Interface()
}

// TCPAddress reports the TCP listen address, or nil if TCP is disabled.
func (self *Server) TCPAddress() net.Addr {
	if self.tcp == nil {
		return nil
	}
	return self.tcp.Addr()
}

// UDPAddress reports the UDP listen address, or nil if UDP is disabled.
func (self *Server) UDPAddress() net.Addr {
	if self.udp == nil {
		return nil
	}
	return self.udp.Addr()
}

func (self *Server) Run(signaling chan os.Signal) error {
	self.router.Start()
	if self.tcp != nil {
		self.tcp.Start()
	}
	if self.udp != nil {
		self.udp.Start()
	}

	<-signaling

	self.stop()
	return nil
}

func (self *Server) Close() error {
	self.stop()
	return nil
}

func (self *Server) stop() {
	self.stopOnce.Do(func() {
		if self.tcp != nil {
			self.tcp.Stop()
		}
		if self.udp != nil {
			self.udp.Stop()
		}
		self.router.Stop()
	})
}
