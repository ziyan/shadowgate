package client

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

var log = logging.MustGetLogger("client")

type Client struct {
	ip      net.IP
	network *net.IPNet

	tun  tun.TUN
	conn io.ReadWriteCloser

	local  chan ipv4.Frame
	remote chan ipv4.Frame

	done chan struct{}
}

func NewClient(name string, persist bool, ip net.IP, network *net.IPNet, connect string, password []byte, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", connect, timeout)
	if err != nil {
		return nil, err
	}

	tun, err := tun.Open(name, persist)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return &Client{
		ip:      ip,
		network: network,
		tun:     tun,
		conn:    compress.NewCompressedConnection(secure.NewEncryptedConnection(conn, password)),
		local:   make(chan ipv4.Frame, 1),
		remote:  make(chan ipv4.Frame, 1),
		done:    make(chan struct{}),
	}, nil
}

func (c *Client) Close() error {
	close(c.done)
	c.tun.Close()
	c.conn.Close()
	return nil
}

func (c *Client) Name() string {
	return c.tun.Name()
}

func (c *Client) Run(signaling chan os.Signal) error {

	done1 := make(chan struct{})
	go func() {
		c.run()
		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		c.connect()
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

func (c *Client) run() {
	defer c.tun.Close()

	done1 := make(chan struct{})
	go func() {
		buffer := make([]byte, 65536)
		for {
			n, err := c.tun.Read(buffer)
			if err != nil {
				log.Warningf("failed to get next frame: %s", err)
				break
			}
			frame := ipv4.DecodeFrame(buffer[:n])
			if frame == nil {
				continue
			}
			if !c.ip.Equal(frame.Source()) || !c.network.Contains(frame.Destination()) || frame.Source().Equal(frame.Destination()) {
				continue
			}

			log.Debugf("tun: packet: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))
			c.remote <- frame.Copy()
		}

		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		for {
			select {
			case frame := <-c.local:
				c.tun.Write(frame)
			case <-c.done:
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

func (c *Client) connect() {
	defer c.conn.Close()

	log.Infof("server connected")

	done1 := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(c.conn)
		scanner.Split(ipv4.ScanFrame)

		for scanner.Scan() {
			frame := ipv4.Frame(scanner.Bytes())
			if !c.ip.Equal(frame.Destination()) || !c.network.Contains(frame.Source()) {
				continue
			}
			if frame.Source().Equal(frame.Destination()) {
				continue
			}

			log.Debugf("tcp: packet: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))
			c.local <- frame.Copy()
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
			case frame := <-c.remote:
				c.conn.Write(frame)
			case <-c.done:
				break
			}
		}
		close(done2)
	}()

	c.remote <- ipv4.MakeFrame(c.ip, c.ip)

	select {
	case <-done1:
	case <-done2:
	}

	log.Infof("closing connection to server")
}
