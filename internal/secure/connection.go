package secure

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// nonceSize is the ChaCha20-Poly1305 nonce length.
const nonceSize = chacha20poly1305.NonceSize

// EncryptedConnection wraps a stream connection and transparently applies the
// authenticated record layer described in the package documentation. Each
// direction lazily performs its salt handshake on first use: the send salt is
// written on the first Write, and the receive salt is read on the first Read.
type EncryptedConnection struct {
	conn      io.ReadWriteCloser
	masterKey []byte

	// sendInfo/recvInfo are the direction-specific HKDF labels for this end. The
	// initiator (client) sends client->server and receives server->client; the
	// responder (server) is the mirror image.
	sendInfo string
	recvInfo string

	sendAead  cipher.AEAD
	sendNonce []byte

	recvAead    cipher.AEAD
	recvNonce   []byte
	recvPending []byte
	recvStarted bool

	// sendErr and recvErr persist a fatal error per direction. They are split so
	// the (single) writer goroutine and the (single) reader goroutine never touch
	// the same field, which a shared error would make a data race.
	sendErr error
	recvErr error
}

// NewEncryptedConnection wraps conn. initiator must be true on the dialing end
// (the client) and false on the accepting end (the server), so the two ends
// agree on which direction uses which key.
func NewEncryptedConnection(conn io.ReadWriteCloser, password []byte, initiator bool) *EncryptedConnection {
	self := &EncryptedConnection{conn: conn}
	if initiator {
		self.sendInfo, self.recvInfo = infoClientToServer, infoServerToClient
	} else {
		self.sendInfo, self.recvInfo = infoServerToClient, infoClientToServer
	}
	masterKey, err := deriveMasterKey(password)
	if err != nil {
		self.sendErr, self.recvErr = err, err
	}
	self.masterKey = masterKey
	return self
}

func (self *EncryptedConnection) Write(plaintext []byte) (int, error) {
	if self.sendErr != nil {
		return 0, self.sendErr
	}
	if self.sendAead == nil {
		if err := self.startSend(); err != nil {
			self.sendErr = err
			return 0, err
		}
	}

	written := 0
	for len(plaintext) > 0 {
		chunk := plaintext
		if len(chunk) > maxRecordSize {
			chunk = chunk[:maxRecordSize]
		}
		if err := self.writeRecord(chunk); err != nil {
			self.sendErr = err
			return written, err
		}
		written += len(chunk)
		plaintext = plaintext[len(chunk):]
	}
	return written, nil
}

func (self *EncryptedConnection) startSend() error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := newAead(self.masterKey, salt, self.sendInfo)
	if err != nil {
		return err
	}
	if _, err := self.conn.Write(salt); err != nil {
		return err
	}
	self.sendAead = aead
	self.sendNonce = make([]byte, nonceSize)
	return nil
}

func (self *EncryptedConnection) writeRecord(chunk []byte) error {
	var lengthHeader [lengthHeaderSize]byte
	binary.BigEndian.PutUint16(lengthHeader[:], uint16(len(chunk)))

	// seal the length and the payload back-to-back into one buffer so the whole
	// record goes out in a single write.
	record := make([]byte, 0, lengthHeaderSize+len(chunk)+2*tagSize)
	record = self.sendAead.Seal(record, self.sendNonce, lengthHeader[:], nil)
	incrementNonce(self.sendNonce)
	record = self.sendAead.Seal(record, self.sendNonce, chunk, nil)
	incrementNonce(self.sendNonce)

	_, err := self.conn.Write(record)
	return err
}

func (self *EncryptedConnection) Read(buffer []byte) (int, error) {
	// return any plaintext left over from a previous record before surfacing a
	// persisted error, so buffered data is not lost.
	if len(self.recvPending) > 0 {
		size := copy(buffer, self.recvPending)
		self.recvPending = self.recvPending[size:]
		return size, nil
	}
	if self.recvErr != nil {
		return 0, self.recvErr
	}
	if self.recvAead == nil {
		if err := self.startRecv(); err != nil {
			self.recvErr = err
			return 0, err
		}
	}

	plaintext, err := self.readRecord()
	if err != nil {
		self.recvErr = err
		return 0, err
	}

	size := copy(buffer, plaintext)
	if size < len(plaintext) {
		self.recvPending = plaintext[size:]
	}
	return size, nil
}

func (self *EncryptedConnection) startRecv() error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(self.conn, salt); err != nil {
		return err
	}
	aead, err := newAead(self.masterKey, salt, self.recvInfo)
	if err != nil {
		return err
	}
	self.recvAead = aead
	self.recvNonce = make([]byte, nonceSize)
	return nil
}

func (self *EncryptedConnection) readRecord() ([]byte, error) {
	sealedLength := make([]byte, lengthHeaderSize+tagSize)
	if _, err := io.ReadFull(self.conn, sealedLength); err != nil {
		return nil, err
	}
	lengthHeader, err := self.recvAead.Open(nil, self.recvNonce, sealedLength, nil)
	if err != nil {
		if !self.recvStarted {
			return nil, ErrInvalidPassword
		}
		return nil, ErrCorruptStream
	}
	incrementNonce(self.recvNonce)
	self.recvStarted = true

	length := int(binary.BigEndian.Uint16(lengthHeader))
	if length == 0 || length > maxRecordSize {
		return nil, ErrCorruptStream
	}

	sealedPayload := make([]byte, length+tagSize)
	if _, err := io.ReadFull(self.conn, sealedPayload); err != nil {
		return nil, err
	}
	plaintext, err := self.recvAead.Open(nil, self.recvNonce, sealedPayload, nil)
	if err != nil {
		return nil, ErrCorruptStream
	}
	incrementNonce(self.recvNonce)
	return plaintext, nil
}

func (self *EncryptedConnection) Close() error {
	return self.conn.Close()
}
