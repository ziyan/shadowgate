package obfuscate

// replayWindowSize is the number of most-recent sequence numbers tracked for
// replay protection.
const replayWindowSize = 1024

// ReplayWindow is a sliding-window replay filter. Sequence numbers start at 1
// (0 is never valid). It is not safe for concurrent use; callers must confine a
// ReplayWindow to a single goroutine or guard it with a lock.
type ReplayWindow struct {
	top    uint64
	bitmap [replayWindowSize / 64]uint64
}

// Accept reports whether sequence is fresh. It returns true and records the
// sequence the first time it is seen, and false for a duplicate or a sequence so
// old it has fallen out of the window.
func (self *ReplayWindow) Accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}

	if sequence > self.top {
		difference := sequence - self.top
		if difference >= replayWindowSize {
			// the whole window is now stale
			for index := range self.bitmap {
				self.bitmap[index] = 0
			}
		} else {
			// clear the slots we are advancing into so stale bits from a prior
			// window generation are not mistaken for replays
			for value := self.top + 1; value <= sequence; value++ {
				self.clear(value % replayWindowSize)
			}
		}
		self.top = sequence
		self.set(sequence % replayWindowSize)
		return true
	}

	if self.top-sequence >= replayWindowSize {
		return false
	}
	if self.get(sequence % replayWindowSize) {
		return false
	}
	self.set(sequence % replayWindowSize)
	return true
}

func (self *ReplayWindow) set(index uint64) {
	self.bitmap[index/64] |= 1 << (index % 64)
}

func (self *ReplayWindow) clear(index uint64) {
	self.bitmap[index/64] &^= 1 << (index % 64)
}

func (self *ReplayWindow) get(index uint64) bool {
	return self.bitmap[index/64]&(1<<(index%64)) != 0
}
