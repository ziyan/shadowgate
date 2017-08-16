package server

import (
	"bufio"
	"io"
	"net"
	"os"
	"time"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/compress"
	"github.com/ziyan/shadowgate/ipv4"
	"github.com/ziyan/shadowgate/secure"
	"github.com/ziyan/shadowgate/tun"
)

var log = logging.MustGetLogger("server")

type registration struct {
	channel chan ipv4.Frame
	source  net.IP
}

type Server struct {
	ip       net.IP
	network  *net.IPNet
	password []byte
	timeout  time.Duration

	tun      tun.TUN
	listener net.Listener

	local    chan ipv4.Frame
	queue    chan ipv4.Frame
	register chan *registration

	done chan struct{}
}

func NewServer(ifname string, persist bool, ip net.IP, network *net.IPNet, listen string, password []byte, timeout time.Duration) (*Server, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}

	tun, err := tun.Open(ifname, persist)
	if err != nil {
		listener.Close()
		return nil, err
	}

	log.Noticef("tun interface created: %s", tun.Interface())

	return &Server{
		ip:       ip,
		network:  network,
		password: password,
		timeout:  timeout,
		tun:      tun,
		listener: listener,
		local:    make(chan ipv4.Frame, 1024),
		queue:    make(chan ipv4.Frame, 1024),
		register: make(chan *registration, 1024),
		done:     make(chan struct{}),
	}, nil
}

func (s *Server) Close() error {
	s.tun.Close()
	s.listener.Close()
	return nil
}

func (s *Server) Interface() string {
	return s.tun.Interface()
}

func (s *Server) Run(signaling chan os.Signal) error {

	done1 := make(chan struct{})
	go func() {
		s.run()
		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		s.listen()
		close(done2)
	}()

	done3 := make(chan struct{})
	go func() {
		s.route()
		close(done3)
	}()

	select {
	case <-signaling:
	case <-done1:
	case <-done2:
	case <-done3:
	}

	s.tun.Close()
	s.listener.Close()

	<-done1
	<-done2

	close(s.done)
	<-done3

	return nil
}

func (s *Server) route() {
	log.Infof("router started")

	// routing table
	routes := make(map[string]chan ipv4.Frame)

	quit := false
	for !quit {
		select {
		case f := <-s.queue:
			if s.ip.Equal(f.Destination()) {
				// route to local tun
				s.local <- f
			} else {
				// find client queue
				if c, ok := routes[f.Destination().String()]; ok {
					c <- f
				}
			}
		case r := <-s.register:
			if r.source != nil {
				// new route discovered
				log.Infof("new route registered: %s", r.source)
				routes[r.source.String()] = r.channel
			} else {
				// remove route that is gone
				for s, c := range routes {
					if c == r.channel {
						log.Infof("old route removed: %s", s)
						delete(routes, s)
					}
				}
			}
		case <-s.done:
			quit = true
		}
	}

	log.Infof("router stopped")
}

func (s *Server) run() {
	log.Infof("tun device opened")

	done := make(chan struct{})

	done1 := make(chan struct{})
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, err := s.tun.Read(buffer)
			if err != nil {
				log.Warningf("failed to get next frame: %s", err)
				break
			}
			f := ipv4.DecodeFrame(buffer[:n])
			if f == nil {
				continue
			}
			if !s.ip.Equal(f.Source()) || !s.network.Contains(f.Destination()) || f.Source().Equal(f.Destination()) {
				continue
			}

			log.Debugf("tun: frame: %s -> %s, size %d", f.Source(), f.Destination(), len(f.Payload()))

			s.queue <- f.Copy()
		}

		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		quit := false
		for !quit {
			select {
			case f := <-s.local:
				s.tun.Write(f)
			case <-done:
				quit = true
			}
		}

		close(done2)
	}()

	select {
	case <-done1:
	case <-done2:
	}

	close(done)
	s.tun.Close()

	<-done1
	<-done2

	log.Infof("tun device closed")
}

func (s *Server) listen() {
	defer s.listener.Close()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Warningf("failed to accept tcp connection: %s", err)
			break
		}

		go s.accept(conn.RemoteAddr(), compress.NewCompressedConnection(secure.NewEncryptedConnection(conn, s.password)))
	}
}

func (s *Server) accept(addr net.Addr, conn io.ReadWriteCloser) {
	log.Infof("client connection established: %v", addr)

	// create queue for this client
	remote := make(chan ipv4.Frame, 1024)
	defer func() {
		s.register <- &registration{channel: remote}
		close(remote)
	}()

	done := make(chan struct{})

	done1 := make(chan struct{})
	go func() {
		// source observed
		var source net.IP

		scanner := bufio.NewScanner(conn)
		scanner.Split(ipv4.ScanFrame)

		for scanner.Scan() {
			f := ipv4.Frame(scanner.Bytes())
			if s.ip.Equal(f.Source()) || !s.network.Contains(f.Source()) || !s.network.Contains(f.Destination()) {
				continue
			}

			if !source.Equal(f.Source()) {
				source = f.Source()
				s.register <- &registration{channel: remote, source: source}
			}

			if f.Source().Equal(f.Destination()) {
				// received a special f from client, reply with a special f
				remote <- ipv4.MakeFrame(s.ip, s.ip)
				continue
			}

			log.Debugf("tcp: frame: %s -> %s, size %d", f.Source(), f.Destination(), len(f.Payload()))

			s.queue <- f.Copy()
		}

		if err := scanner.Err(); err != nil {
			log.Warningf("failed to get next frame: %s", err)
		}

		log.Infof("client connection receiver stopped: %s", addr)
		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		quit := false
		for !quit {
			select {
			case f := <-remote:
				n, err := conn.Write(f)
				if err != nil {
					log.Warningf("failed to write frame to client %s: %s", addr, err)
				} else if n != len(f) {
					panic("server: did not write complete frame")
				}
			case <-done:
				quit = true
			}
		}

		log.Infof("client connection sender stopped: %s", addr)
		close(done2)
	}()

	select {
	case <-done1:
	case <-done2:
	}

	close(done)
	conn.Close()

	<-done1
	<-done2

	log.Infof("client connection closed: %s", addr)
}
