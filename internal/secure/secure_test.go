package secure

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
)

// fakeConn is an io.ReadWriteCloser backed by independent reader/writer halves,
// used to capture ciphertext and to feed crafted bytes back in.
type fakeConn struct {
	reader io.Reader
	writer io.Writer
}

func (self fakeConn) Read(buffer []byte) (int, error)  { return self.reader.Read(buffer) }
func (self fakeConn) Write(buffer []byte) (int, error) { return self.writer.Write(buffer) }
func (self fakeConn) Close() error                     { return nil }

func TestEncryptedConnectionRoundTrip(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	password := []byte("correct horse battery staple")
	sender := NewEncryptedConnection(clientConn, password, true)
	receiver := NewEncryptedConnection(serverConn, password, false)

	// larger than maxRecordSize so it spans several records
	message := bytes.Repeat([]byte("shadowgate "), 4000)

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
		t.Error("decrypted payload does not match original")
	}
}

func TestEncryptedConnectionPartialReads(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	password := []byte("password")
	sender := NewEncryptedConnection(clientConn, password, true)
	receiver := NewEncryptedConnection(serverConn, password, false)

	message := []byte("the quick brown fox jumps over the lazy dog")
	go func() { _, _ = sender.Write(message) }()

	// read in tiny pieces to exercise the recvPending buffering
	var assembled []byte
	small := make([]byte, 5)
	for len(assembled) < len(message) {
		size, err := receiver.Read(small)
		if err != nil {
			t.Fatalf("read failed: %s", err)
		}
		assembled = append(assembled, small[:size]...)
	}
	if !bytes.Equal(assembled, message) {
		t.Errorf("assembled = %q, want %q", assembled, message)
	}
}

func TestEncryptedConnectionRejectsWrongPassword(t *testing.T) {
	var captured bytes.Buffer
	sender := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(nil), writer: &captured}, []byte("right-password"), true)
	if _, err := sender.Write([]byte("secret payload")); err != nil {
		t.Fatalf("Write: %s", err)
	}

	receiver := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(captured.Bytes()), writer: io.Discard}, []byte("wrong-password"), false)
	if _, err := receiver.Read(make([]byte, 64)); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("Read with wrong password error = %v, want ErrInvalidPassword", err)
	}
}

func TestEncryptedConnectionDetectsTampering(t *testing.T) {
	var captured bytes.Buffer
	password := []byte("password")
	sender := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(nil), writer: &captured}, password, true)
	if _, err := sender.Write([]byte("secret payload")); err != nil {
		t.Fatalf("Write: %s", err)
	}

	tampered := captured.Bytes()
	tampered[len(tampered)-1] ^= 0x01 // flip a byte in the payload tag

	receiver := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(tampered), writer: io.Discard}, password, false)
	if _, err := receiver.Read(make([]byte, 64)); err == nil {
		t.Fatal("Read of tampered stream succeeded, want an error")
	}
}

func TestEncryptedConnectionRejectsReflection(t *testing.T) {
	// An on-path attacker reflects the client's own salt and records back at the
	// client. Because the receive direction uses a different HKDF label, the
	// client must not authenticate its own outbound records as inbound.
	var captured bytes.Buffer
	password := []byte("password")
	sender := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(nil), writer: &captured}, password, true)
	if _, err := sender.Write([]byte("outbound payload")); err != nil {
		t.Fatalf("Write: %s", err)
	}

	// a receiver with the SAME initiator role (as the client itself would have)
	reflected := NewEncryptedConnection(fakeConn{reader: bytes.NewReader(captured.Bytes()), writer: io.Discard}, password, true)
	if _, err := reflected.Read(make([]byte, 64)); err == nil {
		t.Fatal("reflected records were accepted; direction key separation failed")
	}
}

func TestIncrementNonce(t *testing.T) {
	nonce := make([]byte, nonceSize)
	incrementNonce(nonce)
	if nonce[0] != 1 {
		t.Errorf("nonce[0] = %d, want 1", nonce[0])
	}

	nonce[0] = 0xff
	incrementNonce(nonce)
	if nonce[0] != 0 || nonce[1] != 1 {
		t.Errorf("carry failed: nonce = %v", nonce[:2])
	}
}
