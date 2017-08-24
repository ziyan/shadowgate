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
}

func NewClient(ifname string, persist bool, ip net.IP, network *net.IPNet, connect string, password []byte, timeout time.Duration) (*Client, error) {
	conn, err := net.DialTimeout("tcp", connect, timeout)
	if err != nil {
		return nil, err
	}

	tun, err := tun.Open(ifname, persist)
	if err != nil {
		conn.Close()
		return nil, err
	}

	log.Noticef("tun interface created: %s", tun.Interface())

	return &Client{
		ip:      ip,
		network: network,
		tun:     tun,
		conn:    compress.NewCompressedConnection(secure.NewEncryptedConnection(conn, password)),
		local:   make(chan ipv4.Frame, 1024),
		remote:  make(chan ipv4.Frame, 1024),
	}, nil
}

func (c *Client) Close() error {
	c.tun.Close()
	c.conn.Close()
	return nil
}

func (c *Client) Interface() string {
	return c.tun.Interface()
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

	select {
	case <-signaling:
	case <-done1:
	case <-done2:
	}

	c.tun.Close()
	c.conn.Close()

	<-done1
	<-done2
	return nil
}

func (c *Client) run() {
	log.Infof("tun device opened")

	done := make(chan struct{})

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
			if !c.ip.Equal(frame.Source()) || frame.Source().Equal(frame.Destination()) {
				log.Warningf("tun: dropped: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))
				continue
			}

			log.Debugf("tun: packet: %s -> %s, size %d", frame.Source(), frame.Destination(), len(frame.Payload()))
			c.remote <- frame.Copy()
		}

		close(done1)
	}()

	done2 := make(chan struct{})
	go func() {
		quit := false
		for !quit {
			select {
			case frame := <-c.local:
				c.tun.Write(frame)
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
	c.tun.Close()

	<-done1
	<-done2

	log.Infof("tun device closed")
}

func (c *Client) connect() {
	log.Infof("server connection established")

	done := make(chan struct{})

	done1 := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(c.conn)
		scanner.Split(ipv4.ScanFrame)

		for scanner.Scan() {
			frame := ipv4.Frame(scanner.Bytes())
			if !c.ip.Equal(frame.Destination()) {
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
		quit := false
		for !quit {
			select {
			case frame := <-c.remote:
				n, err := c.conn.Write(frame)
				if err != nil {
					log.Warningf("failed to write frame to server: %s", err)
				} else if n != len(frame) {
					panic("server: did not write complete frame")
				}
			case <-done:
				quit = true
			}
		}

		close(done2)
	}()

	// send a special frame to make initialization faster
	c.remote <- ipv4.MakeFrame(c.ip, c.ip)

	select {
	case <-done1:
	case <-done2:
	}

	close(done)
	c.conn.Close()

	<-done1
	<-done2

	log.Infof("server connection closed")
}
