package secure

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"

	"golang.org/x/crypto/chacha20poly1305"
)

// masterKeySalt is a constant salt used when deriving the long-term key from the
// password. It domain-separates the TCP record layer's keys from other modes.
var masterKeySalt = []byte("shadowgate-tcp-v2")

// HKDF "info" labels bind each session key to the direction it protects, so a
// key derived for client->server traffic can never authenticate server->client
// traffic (which would otherwise allow an on-path attacker to reflect a peer's
// own records back at it).
const (
	infoClientToServer = "shadowgate-record-v2-c2s"
	infoServerToClient = "shadowgate-record-v2-s2c"
)

// deriveMasterKey turns the password into the long-term key.
func deriveMasterKey(password []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), masterKeySalt, KeyIteration, KeySize)
}

// newAead derives a per-direction session key from the master key, a random
// per-direction salt, and a direction-specific info label, returning a ready
// ChaCha20-Poly1305 cipher.
func newAead(masterKey, salt []byte, info string) (cipher.AEAD, error) {
	subkey, err := hkdf.Key(sha256.New, masterKey, salt, info, KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(subkey)
}

// incrementNonce advances a little-endian counter nonce by one, in place.
func incrementNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			break
		}
	}
}
