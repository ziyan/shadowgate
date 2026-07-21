// Package secure provides an authenticated, encrypted record layer for a stream
// connection (the TCP transport).
//
// The wire format follows the Shadowsocks-AEAD / TLS-record pattern. Each
// direction is independent and begins with a random 32-byte salt sent in the
// clear; both peers derive a per-direction session key from the pre-shared
// password and that salt via HKDF, so the two directions never share a key and
// each can start its nonce counter at zero without risk of nonce reuse. After
// the salt, the stream is a sequence of records:
//
//	seal(length uint16) || seal(payload[length])
//
// where each seal is ChaCha20-Poly1305 with a 12-byte little-endian counter
// nonce that increments once per seal. Because every record carries a
// Poly1305 tag, tampering (or a wrong password) is detected and rejected.
package secure

import (
	"errors"

	"github.com/op/go-logging"
)

const (
	// KeySize is the session key size in bytes.
	KeySize = 32

	// KeyIteration is the number of PBKDF2 iterations used to derive the master
	// key from the password.
	KeyIteration = 4096

	// saltSize is the per-direction random salt prepended to each stream.
	saltSize = 32

	// tagSize is the Poly1305 authentication tag length appended to each seal.
	tagSize = 16

	// lengthHeaderSize is the size of the (encrypted) per-record length field.
	lengthHeaderSize = 2

	// maxRecordSize is the largest plaintext chunk sealed into a single record.
	maxRecordSize = 16 * 1024
)

// ErrInvalidPassword is returned when the first record fails to authenticate,
// which is what happens when the two peers were configured with different
// passwords.
var ErrInvalidPassword = errors.New("secure: invalid password")

// ErrCorruptStream is returned when a record past the first fails to
// authenticate or declares an invalid length.
var ErrCorruptStream = errors.New("secure: corrupt stream")

var log = logging.MustGetLogger("secure") //nolint:unused
