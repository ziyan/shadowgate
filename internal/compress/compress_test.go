package compress

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestCompressedConnectionRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	sender := NewCompressedConnection(clientConn)
	receiver := NewCompressedConnection(serverConn)

	// highly compressible payload exercises the snappy framing.
	message := bytes.Repeat([]byte("shadowgate "), 512)

	writeErr := make(chan error, 1)
	go func() {
		_, err := sender.Write(message)
		writeErr <- err
	}()

	buffer := make([]byte, len(message))
	if _, err := io.ReadFull(receiver, buffer); err != nil {
		t.Fatalf("read failed: %s", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("write failed: %s", err)
	}

	if !bytes.Equal(buffer, message) {
		t.Error("decompressed payload does not match original")
	}
}
