package ipv4

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestMakeFrameRoundTrip(t *testing.T) {
	source := net.ParseIP("172.18.0.2")
	destination := net.ParseIP("172.18.0.1")

	frame := MakeFrame(source, destination)

	if frame.Version() != 4 {
		t.Errorf("Version() = %d, want 4", frame.Version())
	}
	if frame.IHL() != 5 {
		t.Errorf("IHL() = %d, want 5", frame.IHL())
	}
	if frame.TotalLength() != minHeaderLength {
		t.Errorf("TotalLength() = %d, want %d", frame.TotalLength(), minHeaderLength)
	}
	if !frame.Source().Equal(source) {
		t.Errorf("Source() = %s, want %s", frame.Source(), source)
	}
	if !frame.Destination().Equal(destination) {
		t.Errorf("Destination() = %s, want %s", frame.Destination(), destination)
	}
}

func TestDecodeFrameAcceptsValid(t *testing.T) {
	original := MakeFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))

	frame := DecodeFrame(original)
	if frame == nil {
		t.Fatal("DecodeFrame returned nil for a valid frame")
	}
	if len(frame.Payload()) != 0 {
		t.Errorf("Payload() length = %d, want 0", len(frame.Payload()))
	}
}

func TestDecodeFrameRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":        make([]byte, 10),
		"wrong version":    append([]byte{0x60}, make([]byte, 19)...),
		"length mismatch":  func() []byte { b := MakeFrame(net.IPv4zero, net.IPv4zero); b.SetTotalLength(21); return b }(),
		"ihl below header": func() []byte { b := MakeFrame(net.IPv4zero, net.IPv4zero); b.SetIHL(4); return b }(),
		"ihl beyond total": func() []byte { b := MakeFrame(net.IPv4zero, net.IPv4zero); b.SetIHL(15); return b }(),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if frame := DecodeFrame(data); frame != nil {
				t.Errorf("DecodeFrame(%s) = %v, want nil", name, []byte(frame))
			}
		})
	}
}

func TestCopyIsIndependent(t *testing.T) {
	original := MakeFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	clone := original.Copy()

	clone.SetSource(net.ParseIP("10.0.0.9"))

	if original.Source().Equal(clone.Source()) {
		t.Error("Copy() did not produce an independent frame")
	}
}

func TestScanFrameSplitsStream(t *testing.T) {
	first := MakeFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))
	second := MakeFrame(net.ParseIP("10.0.0.3"), net.ParseIP("10.0.0.4"))

	stream := bytes.NewReader(append(append([]byte{}, first...), second...))
	scanner := bufio.NewScanner(stream)
	scanner.Split(ScanFrame)

	var frames []Frame
	for scanner.Scan() {
		frames = append(frames, Frame(scanner.Bytes()).Copy())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %s", err)
	}

	if len(frames) != 2 {
		t.Fatalf("scanned %d frames, want 2", len(frames))
	}
	if !frames[0].Source().Equal(first.Source()) {
		t.Errorf("frame 0 source = %s, want %s", frames[0].Source(), first.Source())
	}
	if !frames[1].Source().Equal(second.Source()) {
		t.Errorf("frame 1 source = %s, want %s", frames[1].Source(), second.Source())
	}
}

func TestScanFrameWaitsForFullFrame(t *testing.T) {
	frame := MakeFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"))

	advance, token, err := ScanFrame(frame[:10], false)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if advance != 0 || token != nil {
		t.Errorf("ScanFrame on partial frame = (%d, %v), want (0, nil)", advance, token)
	}
}

func TestScanFrameDiscardsGarbage(t *testing.T) {
	// non-IPv4 leading bytes should be skipped so the scanner can resynchronize.
	garbage := make([]byte, 40)
	advance, token, err := ScanFrame(garbage, false)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if advance != len(garbage) || token != nil {
		t.Errorf("ScanFrame on garbage = (%d, %v), want (%d, nil)", advance, token, len(garbage))
	}
}
