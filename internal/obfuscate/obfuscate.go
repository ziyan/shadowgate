// Package obfuscate implements shadowgate's headerless, fully-encrypted UDP
// packet format. Every datagram on the wire is
//
//	nonce (24 random bytes) || XChaCha20-Poly1305(key, nonce, plaintext)
//
// where the plaintext carries a small encrypted header, the payload, and random
// padding. There is no plaintext header, no handshake, and no fixed length, so a
// passive observer sees only high-entropy datagrams of varying size. Only a
// holder of the pre-shared password can produce or open a datagram.
package obfuscate

import (
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/op/go-logging"
	"golang.org/x/crypto/chacha20poly1305"
)

// KeySize is the derived key length in bytes.
const KeySize = 32

// keyIteration is the number of PBKDF2 iterations used to derive the key.
const keyIteration = 4096

// keySalt is a constant, compiled-in salt. It is never transmitted, so no
// fixed-length field appears on the wire; it also domain-separates UDP-mode keys
// from the TCP mode's derivation.
var keySalt = []byte("shadowgate-udp-v1")

// headerSize is the size of the encrypted, fixed header that precedes the
// payload inside the AEAD plaintext:
//
//	sequence uint64 | streamId uint16 | payloadLength uint16 | paddingLength uint16
const headerSize = 8 + 2 + 2 + 2

// ErrInvalidPacket is returned by Open for any datagram that cannot be
// authenticated and parsed, so callers can uniformly drop bad input.
var ErrInvalidPacket = errors.New("obfuscate: invalid packet")

var log = logging.MustGetLogger("obfuscate") //nolint:unused

// DeriveKey turns a password into a 32-byte key.
func DeriveKey(password []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), keySalt, keyIteration, KeySize)
}

// Codec seals and opens obfuscated datagrams. A Codec is safe for concurrent use
// by multiple goroutines: the underlying AEAD is stateless and each Seal draws a
// fresh random nonce.
type Codec struct {
	aead       cipher.AEAD
	maxPadding int
}

// NewCodec builds a Codec from a 32-byte key. maxPadding is the maximum number
// of random bytes appended (inside the encryption) to each datagram; 0 disables
// padding.
func NewCodec(key []byte, maxPadding int) (*Codec, error) {
	if maxPadding < 0 || maxPadding > 0xffff {
		return nil, errors.New("obfuscate: maxPadding out of range")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead, maxPadding: maxPadding}, nil
}

// Overhead reports the smallest datagram Open will consider: the nonce, the AEAD
// tag, and the fixed header.
func (self *Codec) Overhead() int {
	return self.aead.NonceSize() + self.aead.Overhead() + headerSize
}

// Seal builds an obfuscated datagram carrying payload on the given stream. The
// payload must be at most 65535 bytes.
func (self *Codec) Seal(sequence uint64, streamId uint16, payload []byte) ([]byte, error) {
	if len(payload) > 0xffff {
		return nil, errors.New("obfuscate: payload too large")
	}

	paddingLength, err := self.randomPadding()
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, headerSize+len(payload)+paddingLength)
	binary.BigEndian.PutUint64(plaintext[0:], sequence)
	binary.BigEndian.PutUint16(plaintext[8:], streamId)
	binary.BigEndian.PutUint16(plaintext[10:], uint16(len(payload)))
	binary.BigEndian.PutUint16(plaintext[12:], uint16(paddingLength))
	copy(plaintext[headerSize:], payload)
	if paddingLength > 0 {
		if _, err := rand.Read(plaintext[headerSize+len(payload):]); err != nil {
			return nil, err
		}
	}

	nonce := make([]byte, self.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Append the ciphertext directly after the nonce so the returned slice is
	// exactly nonce || ciphertext.
	return self.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open authenticates and parses a datagram, returning the sequence number,
// stream id, and payload. The returned payload is backed by a freshly allocated
// buffer and is safe to retain. Any malformed or unauthenticated datagram yields
// ErrInvalidPacket.
func (self *Codec) Open(datagram []byte) (sequence uint64, streamId uint16, payload []byte, err error) {
	nonceSize := self.aead.NonceSize()
	if len(datagram) < self.Overhead() {
		return 0, 0, nil, ErrInvalidPacket
	}

	nonce, ciphertext := datagram[:nonceSize], datagram[nonceSize:]
	plaintext, err := self.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, 0, nil, ErrInvalidPacket
	}
	if len(plaintext) < headerSize {
		return 0, 0, nil, ErrInvalidPacket
	}

	sequence = binary.BigEndian.Uint64(plaintext[0:])
	streamId = binary.BigEndian.Uint16(plaintext[8:])
	payloadLength := int(binary.BigEndian.Uint16(plaintext[10:]))
	paddingLength := int(binary.BigEndian.Uint16(plaintext[12:]))
	if headerSize+payloadLength+paddingLength != len(plaintext) {
		return 0, 0, nil, ErrInvalidPacket
	}

	return sequence, streamId, plaintext[headerSize : headerSize+payloadLength], nil
}

// randomPadding returns a uniform random padding length in [0, maxPadding].
func (self *Codec) randomPadding() (int, error) {
	if self.maxPadding == 0 {
		return 0, nil
	}
	var buffer [2]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return 0, err
	}
	value := int(binary.BigEndian.Uint16(buffer[:]))
	return value % (self.maxPadding + 1), nil
}
