package ipv4

import (
	"net"
)

type Frame []byte

func (f Frame) Version() byte {
	return f[0] >> 4
}

func (f Frame) IHL() byte {
	return f[0] & 0x0f
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

func (f Frame) Destination() net.IP {
	return net.IPv4(f[16], f[17], f[18], f[19])
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
