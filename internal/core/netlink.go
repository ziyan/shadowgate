package core

import (
	"net"

	"github.com/vishvananda/netlink"
)

// netlinkNextHop asks the kernel which next hop the host would use to reach
// destination from source, honoring policy routing rules, and returns the
// gateway (next-hop) address or nil. It is the production lookup behind the
// router's nextHopResolver.
func netlinkNextHop(source, destination net.IP) net.IP {
	options := &netlink.RouteGetOptions{}
	if source != nil {
		options.SrcAddr = source
	}
	routes, err := netlink.RouteGetWithOptions(destination, options)
	if err != nil || len(routes) == 0 {
		return nil
	}
	return routes[0].Gw
}
