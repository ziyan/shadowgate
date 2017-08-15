package main

import (
	"fmt"

	"github.com/ziyan/shadowgate/utils/ipv4"
	"github.com/ziyan/shadowgate/utils/tun"
)

func Stringify(f ipv4.Frame) string {
	if f.Version() != 4 {
		return fmt.Sprintf("[unknown packet, version %d]", f.Version())
	}
	if f.Protocol() == 0x06 {
		return fmt.Sprintf("[%s:%d ~> %s:%d, tcp, payload %d]", f.Source(), f.SourcePort(), f.Destination(), f.DestinationPort(), len(f.Payload()))
	}
	if f.Protocol() == 0x11 {
		return fmt.Sprintf("[%s:%d ~> %s:%d, udp, payload %d]", f.Source(), f.SourcePort(), f.Destination(), f.DestinationPort(), len(f.Payload()))
	}
	if f.Protocol() == 0x01 {
		return fmt.Sprintf("[%s ~> %s, icmp, ttl %d, payload %d]", f.Source(), f.Destination(), f.TTL(), len(f.Payload()))
	}
	return fmt.Sprintf("[%s ~> %s, protocol %d, payload %d]", f.Source(), f.Destination(), f.Protocol(), len(f.Payload()))
}

func main() {
	t, err := tun.Open("", false)
	if err != nil {
		panic(err)
	}

	frame := make([]byte, 1500)
	for {
		n, err := t.Read(frame)
		if err != nil {
			panic(err)
		}

		fmt.Printf("%s\n", Stringify(ipv4.Frame(frame[:n])))
	}
}
