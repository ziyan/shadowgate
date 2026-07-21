package core

import (
	"net"
	"sync"
	"time"
)

const (
	// nextHopTtl is how long a resolved next hop is cached before the OS routing
	// table is consulted again.
	nextHopTtl = 10 * time.Second

	// maxNextHopEntries caps the resolver cache; it is flushed when exceeded.
	maxNextHopEntries = 4096
)

type nextHopEntry struct {
	nextHop net.IP // nil means "the host has no next hop toward here"
	expiry  int64  // UnixNano
}

// nextHopResolver caches OS routing-table lookups that map a (source,
// destination) pair to the next-hop address the host would use. The router uses
// it to forward a frame read from its own tun to the connected client that owns
// that next hop, so that a host route such as "default via <client> dev <tun>"
// makes egress through a client work. The lookup is injectable for tests.
type nextHopResolver struct {
	lookup func(source, destination net.IP) net.IP
	now    func() time.Time

	mutex sync.Mutex
	cache map[string]nextHopEntry
}

func newNextHopResolver(lookup func(source, destination net.IP) net.IP) *nextHopResolver {
	return &nextHopResolver{
		lookup: lookup,
		now:    time.Now,
		cache:  make(map[string]nextHopEntry),
	}
}

// resolve returns the host's next-hop address toward destination for a packet
// sourced at source, or nil if there is none. Results are cached for nextHopTtl.
func (self *nextHopResolver) resolve(source, destination net.IP) net.IP {
	key := source.String() + "|" + destination.String()
	now := self.now().UnixNano()

	self.mutex.Lock()
	if entry, ok := self.cache[key]; ok && entry.expiry > now {
		self.mutex.Unlock()
		return entry.nextHop
	}
	self.mutex.Unlock()

	nextHop := self.lookup(source, destination)

	self.mutex.Lock()
	if len(self.cache) >= maxNextHopEntries {
		self.cache = make(map[string]nextHopEntry)
	}
	self.cache[key] = nextHopEntry{nextHop: nextHop, expiry: now + int64(nextHopTtl)}
	self.mutex.Unlock()

	return nextHop
}
