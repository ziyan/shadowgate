// Package ipv4 provides a thin, allocation-free view over raw IPv4 packets.
package ipv4

import (
	"net"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("ipv4") //nolint:unused

// minHeaderLength is the size in bytes of an IPv4 header with no options.
const minHeaderLength = 20

// Frame is a raw IPv4 packet. Accessors read directly from the backing slice,
// so a Frame must be validated with DecodeFrame (or produced by MakeFrame or
// ScanFrame) before its variable-length fields are used.
type Frame []byte

func (self Frame) Version() byte {
	return self[0] >> 4
}

func (self Frame) SetVersion(version byte) {
	self[0] = (version << 4) | (self[0] & 0x0f)
}

func (self Frame) IHL() byte {
	return self[0] & 0x0f
}

func (self Frame) SetIHL(ihl byte) {
	self[0] = (ihl & 0x0f) | (self[0] & 0xf0)
}

func (self Frame) DSCP() byte {
	return self[1] >> 2
}

func (self Frame) ECN() byte {
	return self[1] & 0x03
}

func (self Frame) TotalLength() uint16 {
	return (uint16(self[2]) << 8) | uint16(self[3])
}

func (self Frame) SetTotalLength(totalLength uint16) {
	self[2] = byte(totalLength >> 8)
	self[3] = byte(totalLength & 0x00ff)
}

func (self Frame) Identification() uint16 {
	return (uint16(self[4]) << 8) | uint16(self[5])
}

func (self Frame) Flags() byte {
	return self[6] >> 5
}

func (self Frame) FragmentOffset() uint16 {
	return (uint16(self[6]&0x1f) << 8) | uint16(self[7])
}

func (self Frame) TTL() byte {
	return self[8]
}

func (self Frame) Protocol() byte {
	return self[9]
}

func (self Frame) HeaderChecksum() uint16 {
	return (uint16(self[10]) << 8) | uint16(self[11])
}

func (self Frame) Source() net.IP {
	return net.IPv4(self[12], self[13], self[14], self[15])
}

func (self Frame) SetSource(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		self[12] = ip[0]
		self[13] = ip[1]
		self[14] = ip[2]
		self[15] = ip[3]
	}
}

func (self Frame) Destination() net.IP {
	return net.IPv4(self[16], self[17], self[18], self[19])
}

func (self Frame) SetDestination(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		self[16] = ip[0]
		self[17] = ip[1]
		self[18] = ip[2]
		self[19] = ip[3]
	}
}

func (self Frame) Options() []byte {
	return self[minHeaderLength : self.IHL()*4]
}

func (self Frame) Payload() []byte {
	return self[self.IHL()*4:]
}

func (self Frame) SourcePort() uint16 {
	payload := self.Payload()
	if len(payload) < 2 {
		return 0
	}
	return (uint16(payload[0]) << 8) | uint16(payload[1])
}

func (self Frame) DestinationPort() uint16 {
	payload := self.Payload()
	if len(payload) < 4 {
		return 0
	}
	return (uint16(payload[2]) << 8) | uint16(payload[3])
}

func (self Frame) Copy() Frame {
	other := make(Frame, len(self))
	copy(other, self)
	return other
}

func MakeFrame(source, destination net.IP) Frame {
	frame := make(Frame, minHeaderLength)
	frame.SetVersion(4)
	frame.SetIHL(5)
	frame.SetTotalLength(minHeaderLength)
	frame.SetSource(source)
	frame.SetDestination(destination)
	return frame
}

// valid reports whether data is a self-consistent IPv4 frame of exactly length
// bytes: version 4, a header length between 20 and 60 bytes that fits within the
// declared total length, and a total length that matches length.
func valid(data []byte, length int) bool {
	if length < minHeaderLength || len(data) < length {
		return false
	}
	if (data[0] >> 4) != 4 {
		return false
	}
	headerLength := int(data[0]&0x0f) * 4
	if headerLength < minHeaderLength || headerLength > length {
		return false
	}
	totalLength := (int(data[2]) << 8) | int(data[3])
	return totalLength == length
}

func DecodeFrame(data []byte) Frame {
	if len(data) < minHeaderLength {
		return nil
	}
	if !valid(data, len(data)) {
		return nil
	}
	return Frame(data)
}

// ScanFrame implements bufio.SplitFunc to split a stream into IPv4 frames.
func ScanFrame(data []byte, atEof bool) (advance int, token []byte, err error) {
	if len(data) < minHeaderLength {
		return 0, nil, nil
	}

	if (data[0] >> 4) != 4 {
		// not an IPv4 frame, resynchronize by discarding what we have
		return len(data), nil, nil
	}

	totalLength := (int(data[2]) << 8) | int(data[3])
	if totalLength < minHeaderLength {
		return len(data), nil, nil
	}

	if len(data) < totalLength {
		return 0, nil, nil
	}

	if !valid(data, totalLength) {
		// malformed header, discard this frame worth of bytes
		return totalLength, nil, nil
	}

	return totalLength, data[:totalLength], nil
}
