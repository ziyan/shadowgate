package client

import (
	"bufio"
	"io"
	"net"
	"time"

	"github.com/ziyan/shadowgate/internal/compress"
	"github.com/ziyan/shadowgate/internal/ipv4"
	"github.com/ziyan/shadowgate/internal/secure"
)

// tcpTransport is a TCP path to the server: a stream of length-delimited IPv4
// frames beneath the encryption (and optional compression) layer.
type tcpTransport struct {
	conn    io.ReadWriteCloser
	scanner *bufio.Scanner
}

func dialTcp(connect string, password []byte, useCompression bool, timeout time.Duration) (*tcpTransport, error) {
	conn, err := net.DialTimeout("tcp", connect, timeout)
	if err != nil {
		return nil, err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	wrapped := wrapConnection(conn, password, useCompression)
	scanner := bufio.NewScanner(wrapped)
	scanner.Buffer(make([]byte, 65536), 65536)
	scanner.Split(ipv4.ScanFrame)

	return &tcpTransport{conn: wrapped, scanner: scanner}, nil
}

func (self *tcpTransport) name() string { return "tcp" }

func (self *tcpTransport) send(frame ipv4.Frame) error {
	_, err := self.conn.Write(frame)
	return err
}

func (self *tcpTransport) receive() (ipv4.Frame, error) {
	if !self.scanner.Scan() {
		if err := self.scanner.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	return ipv4.Frame(self.scanner.Bytes()).Copy(), nil
}

func (self *tcpTransport) close() error {
	return self.conn.Close()
}

// wrapConnection layers encryption (always) and optional compression over a raw
// stream connection. The client is the initiator of the encrypted session.
func wrapConnection(conn io.ReadWriteCloser, password []byte, useCompression bool) io.ReadWriteCloser {
	encrypted := secure.NewEncryptedConnection(conn, password, true)
	if !useCompression {
		return encrypted
	}
	return compress.NewCompressedConnection(encrypted)
}
