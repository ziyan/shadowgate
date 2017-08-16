package ipv4

import (
	"net"
)

type Frame []byte

func (f Frame) Version() byte {
	return f[0] >> 4
}

func (f Frame) SetVersion(version byte) {
	f[0] = (version << 4) | (f[0] & 0x0f)
}

func (f Frame) IHL() byte {
	return f[0] & 0x0f
}

func (f Frame) SetIHL(ihl byte) {
	f[0] = (ihl & 0x0f) | (f[0] & 0xf0)
}

func (f Frame) DSCP() byte {
	return f[1] >> 2
}

func (f Frame) ECN() byte {
	return f[1] & 0x03
}

func (f Frame) TotalLength() uint16 {
	return (uint16(f[2]) << 8) | uint16(f[3])
}

func (f Frame) SetTotalLength(totalLength uint16) {
	f[2] = byte(totalLength >> 8)
	f[3] = byte(totalLength & 0x00ff)
}

func (f Frame) Identification() uint16 {
	return (uint16(f[4]) << 8) | uint16(f[5])
}

func (f Frame) Flags() byte {
	return f[6] >> 5
}

func (f Frame) FragmentOffset() uint16 {
	return (uint16(f[6]&0x1f) << 8) | uint16(f[7])
}

func (f Frame) TTL() byte {
	return f[8]
}

func (f Frame) Protocol() byte {
	return f[9]
}

func (f Frame) HeaderChecksum() uint16 {
	return (uint16(f[10]) << 8) | uint16(f[11])
}

func (f Frame) Source() net.IP {
	return net.IPv4(f[12], f[13], f[14], f[15])
}

func (f Frame) SetSource(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		f[12] = ip[0]
		f[13] = ip[1]
		f[14] = ip[2]
		f[15] = ip[3]
	}
}

func (f Frame) Destination() net.IP {
	return net.IPv4(f[16], f[17], f[18], f[19])
}

func (f Frame) SetDestination(ip net.IP) {
	ip = ip.To4()
	if ip != nil {
		f[16] = ip[0]
		f[17] = ip[1]
		f[18] = ip[2]
		f[19] = ip[3]
	}
}

func (f Frame) Options() []byte {
	return f[20 : f.IHL()*4]
}

func (f Frame) Payload() []byte {
	return f[f.IHL()*4:]
}

func (f Frame) SourcePort() uint16 {
	p := f.Payload()
	return (uint16(p[0]) << 8) | uint16(p[1])
}

func (f Frame) DestinationPort() uint16 {
	p := f.Payload()
	return (uint16(p[2]) << 8) | uint16(p[3])
}

func (f Frame) Copy() Frame {
	g := make(Frame, len(f))
	copy(g, f)
	return g
}

func MakeFrame(source, destination net.IP) Frame {
	f := make(Frame, 20)
	f.SetVersion(4)
	f.SetIHL(5)
	f.SetTotalLength(20)
	f.SetSource(source)
	f.SetDestination(destination)
	return f
}

func DecodeFrame(data []byte) Frame {
	if len(data) < 20 {
		return nil
	}

	if (data[0] >> 4) != 4 {
		return nil
	}

	n := (int(data[2]) << 8) | int(data[3])
	if n != len(data) {
		return nil
	}

	return Frame(data)
}

// implements bufio.SplitFunc to split ip frames
func ScanFrame(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 20 {
		return 0, nil, nil
	}

	if (data[0] >> 4) != 4 {
		return len(data), nil, nil
	}

	n := (int(data[2]) << 8) | int(data[3])
	if n < 20 {
		return len(data), nil, nil
	}

	if len(data) < n {
		return 0, nil, nil
	}

	return n, data[:n], nil
}
