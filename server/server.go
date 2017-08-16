package server

import (
	"bufio"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/op/go-logging"

	"github.com/ziyan/shadowgate/compress"
	"github.com/ziyan/shadowgate/ipv4"
	"github.com/ziyan/shadowgate/secure"
	"github.com/ziyan/shadowgate/tun"
)

var log = logging.MustGetLogger("server")

type Server struct {
	ip       net.IP
	network  *net.IPNet
	password []byte
	timeout  time.Duration

	tun      tun.TUN
	listener net.Listener

	local   chan ipv4.Frame
	remotes map[string]chan ipv4.Frame
	mutex   sync.Mutex

	done chan struct{}
}

func NewServer(name string, persist bool, ip net.IP, network *net.IPNet, listen string, password []byte, timeout time.Duration) (*Server, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}

	tun, err := tun.Open(name, persist)
	if err != nil {
		listener.Close()
		return nil, err
	}

	return &Server{
		ip:       ip,
		network:  network,
		password: password,
		timeout:  timeout,
		tun:      tun,
		listener: listener,
		local:    make(chan ipv4.Frame, 1),
		remotes:  make(map[string]chan ipv4.Frame),
		done:     make(chan struct{}),
	}, nil
}

func (s *Server) Close() error {
	close(s.done)
	s.tun.Close()
	s.listener.Close()
	return nil
}

func (s *Server) Name() string {
	return s.tun.Name()
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

	quit := false
	for !quit {
		select {
		case <-signaling:
			quit = true
		case <-done1:
			quit = true
		case <-done2:
			quit = true
		}
	}
	return nil
}

func (s *Server) run() {
	defer s.tun.Close()

	done1 := make(chan struct{})
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, err := s.tun.Read(buffer)
			if err != nil {
				log.Warningf("failed to get next frame: %s", err)
				break
			}
			frame := ipv4.DecodeFrame(buffer[:n])
			if frame == nil {
				continue
			}
			if !s.ip.Equal(frame.Source()) || !s.network.Contains(frame.Destination()) || frame.Source().Equal(frame.Destination()) {
				continue
			}

			log.Debugf("tun: packet: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))

			// routing
			var channel chan ipv4.Frame
			s.mutex.Lock()
			if c, ok := s.remotes[frame.Destination().String()]; ok {
				channel = c
			}
			s.mutex.Unlock()
			if channel != nil {
				channel <- frame.Copy()
			}
		}

		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		for {
			select {
			case frame := <-s.local:
				s.tun.Write(frame)
			case <-s.done:
				break
			}
		}
		close(done2)
	}()

	select {
	case <-done1:
	case <-done2:
	}
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
	defer conn.Close()
	log.Infof("accepted connection in server mode from: %v", addr)

	// source observed
	var source net.IP

	// create queue for this client
	remote := make(chan ipv4.Frame, 1)
	defer func() {
		s.mutex.Lock()
		for ip, c := range s.remotes {
			if c == remote {
				delete(s.remotes, ip)
			}
		}
		s.mutex.Unlock()
		close(remote)
	}()

	done1 := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(conn)
		scanner.Split(ipv4.ScanFrame)

		for scanner.Scan() {
			frame := ipv4.Frame(scanner.Bytes())
			if s.ip.Equal(frame.Source()) || !s.network.Contains(frame.Source()) || !s.network.Contains(frame.Destination()) {
				continue
			}

			if !source.Equal(frame.Source()) {
				source = frame.Source()
				s.mutex.Lock()
				s.remotes[source.String()] = remote
				s.mutex.Unlock()
			}

			if frame.Source().Equal(frame.Destination()) {
				remote <- ipv4.MakeFrame(s.ip, s.ip)
				continue
			}

			log.Debugf("tcp: packet: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))

			if s.ip.Equal(frame.Destination()) {
				s.local <- frame.Copy()
			} else {
				var channel chan ipv4.Frame
				s.mutex.Lock()
				if c, ok := s.remotes[frame.Destination().String()]; ok {
					channel = c
				}
				s.mutex.Unlock()
				if channel != nil {
					channel <- frame.Copy()
				}
			}
		}

		if err := scanner.Err(); err != nil {
			log.Warningf("failed to get next frame: %s", err)
		}

		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		for {
			select {
			case frame := <-remote:
				conn.Write(frame)
			case <-s.done:
				break
			}
		}
		close(done2)
	}()

	select {
	case <-done1:
	case <-done2:
	}

	log.Infof("closing client connection from: %s", addr)
}
