package client

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/obfuscate"
)

// udpTransport is a UDP path to the server: each frame travels as one obfuscated
// datagram (see internal/obfuscate).
type udpTransport struct {
	conn       *net.UDPConn
	codec      *obfuscate.Codec
	sequence   uint64
	replay     obfuscate.ReplayWindow
	recvBuffer []byte
}

func dialUdp(connect string, password []byte, maxPadding int, timeout time.Duration) (*udpTransport, error) {
	key, err := obfuscate.DeriveKey(password)
	if err != nil {
		return nil, err
	}
	codec, err := obfuscate.NewCodec(key, maxPadding)
	if err != nil {
		return nil, err
	}
	address, err := net.ResolveUDPAddr("udp", connect)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, address)
	if err != nil {
		return nil, err
	}
	return &udpTransport{conn: conn, codec: codec, recvBuffer: make([]byte, 65536)}, nil
}

func (self *udpTransport) name() string { return "udp" }

func (self *udpTransport) send(frame ipv4.Frame) error {
	sequence := atomic.AddUint64(&self.sequence, 1)
	datagram, err := self.codec.Seal(sequence, 0, frame)
	if err != nil {
		return err
	}
	_, err = self.conn.Write(datagram)
	return err
}

func (self *udpTransport) receive() (ipv4.Frame, error) {
	for {
		size, err := self.conn.Read(self.recvBuffer)
		if err != nil {
			return nil, err
		}
		sequence, _, payload, err := self.codec.Open(self.recvBuffer[:size])
		if err != nil {
			continue // undecryptable; drop
		}
		if !self.replay.Accept(sequence) {
			continue
		}
		frame := ipv4.DecodeFrame(payload)
		if frame == nil {
			continue
		}
		return frame.Copy(), nil
	}
}

func (self *udpTransport) close() error {
	return self.conn.Close()
}
