package obfuscate

import (
	"bytes"
	"errors"
	"testing"
)

func newTestCodec(t *testing.T, password string, maxPadding int) *Codec {
	t.Helper()
	key, err := DeriveKey([]byte(password))
	if err != nil {
		t.Fatalf("DeriveKey: %s", err)
	}
	codec, err := NewCodec(key, maxPadding)
	if err != nil {
		t.Fatalf("NewCodec: %s", err)
	}
	return codec
}

func TestSealOpenRoundTrip(t *testing.T) {
	codec := newTestCodec(t, "correct horse", 128)

	payload := []byte("the quick brown fox")
	datagram, err := codec.Seal(7, 3, payload)
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}

	sequence, streamId, got, err := codec.Open(datagram)
	if err != nil {
		t.Fatalf("Open: %s", err)
	}
	if sequence != 7 {
		t.Errorf("sequence = %d, want 7", sequence)
	}
	if streamId != 3 {
		t.Errorf("streamId = %d, want 3", streamId)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	sender := newTestCodec(t, "password-a", 0)
	receiver := newTestCodec(t, "password-b", 0)

	datagram, err := sender.Seal(1, 0, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}
	if _, _, _, err := receiver.Open(datagram); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open with wrong key error = %v, want ErrInvalidPacket", err)
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	codec := newTestCodec(t, "password", 0)
	datagram, err := codec.Seal(1, 0, []byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %s", err)
	}

	for index := range datagram {
		tampered := append([]byte(nil), datagram...)
		tampered[index] ^= 0x01
		if _, _, _, err := codec.Open(tampered); !errors.Is(err, ErrInvalidPacket) {
			t.Fatalf("Open of datagram tampered at byte %d error = %v, want ErrInvalidPacket", index, err)
		}
	}
}

func TestOpenRejectsShortDatagram(t *testing.T) {
	codec := newTestCodec(t, "password", 0)
	if _, _, _, err := codec.Open(make([]byte, codec.Overhead()-1)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("Open of short datagram error = %v, want ErrInvalidPacket", err)
	}
}

func TestSealPaddingVariesSizeAndBytes(t *testing.T) {
	codec := newTestCodec(t, "password", 256)
	payload := []byte("fixed payload")

	sizes := make(map[int]struct{})
	var previous []byte
	for i := 0; i < 64; i++ {
		datagram, err := codec.Seal(uint64(i+1), 0, payload)
		if err != nil {
			t.Fatalf("Seal: %s", err)
		}
		sizes[len(datagram)] = struct{}{}
		if previous != nil && bytes.Equal(previous, datagram) {
			t.Fatal("two seals produced identical bytes; nonce is not fresh")
		}
		previous = datagram

		// still opens regardless of padding
		if _, _, got, err := codec.Open(datagram); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("Open after padding: got %q err %v", got, err)
		}
	}
	if len(sizes) < 2 {
		t.Errorf("padding did not vary datagram size across 64 seals: sizes=%v", sizes)
	}
}

func TestReplayWindow(t *testing.T) {
	var window ReplayWindow

	if !window.Accept(1) {
		t.Fatal("first sequence 1 should be accepted")
	}
	if window.Accept(1) {
		t.Fatal("replay of sequence 1 should be rejected")
	}
	if !window.Accept(2) {
		t.Fatal("sequence 2 should be accepted")
	}
	// out-of-order but within window
	if !window.Accept(5) {
		t.Fatal("sequence 5 should be accepted")
	}
	if !window.Accept(3) {
		t.Fatal("in-window out-of-order sequence 3 should be accepted")
	}
	if window.Accept(3) {
		t.Fatal("replay of sequence 3 should be rejected")
	}
	// jump far ahead, then an old sequence must be rejected as too old
	if !window.Accept(5000) {
		t.Fatal("sequence 5000 should be accepted")
	}
	if window.Accept(2) {
		t.Fatal("sequence 2 is far outside the window and must be rejected")
	}
	if window.Accept(0) {
		t.Fatal("sequence 0 is never valid")
	}
}
