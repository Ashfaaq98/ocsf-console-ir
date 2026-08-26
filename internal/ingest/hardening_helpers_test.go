package ingest

import (
	"runtime"
	"time"
)

func timeoutAfter() <-chan time.Time { return time.After(10 * time.Second) }

// allocatedBytes reports cumulative allocation, not live heap. The cost being
// measured is a tree that is garbage by the time the call returns, so anything
// sampled after a collection would miss it entirely.
func allocatedBytes() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}
