package ui

import (
	"sync/atomic"
	"time"
)

// A guard against two loads of the same collection running at once.
//
// There used to be one flag for all of them, shared by the findings queue and
// the events list. Pressing 1 and then 3 in quick succession made the events
// load return immediately — the findings load still held the flag — while that
// findings load went on to repaint the shared table. The Events screen then sat
// there titled and filled with findings.
//
// One guard per collection: what they protect is a query and a result set, and
// Triage's and Events' are different ones.

// loadWatchdog is how long a load may hold its guard before the next attempt
// assumes it died and takes it. A query that has not returned in this long has
// either failed silently or is never going to.
const loadWatchdog = 3 * time.Second

type loadGuard struct {
	busy      int32
	startedAt int64
}

// begin claims the guard, reporting whether the caller may proceed.
func (g *loadGuard) begin() bool {
	if !atomic.CompareAndSwapInt32(&g.busy, 0, 1) {
		return false
	}
	atomic.StoreInt64(&g.startedAt, time.Now().UnixNano())
	return true
}

// end releases it.
func (g *loadGuard) end() {
	atomic.StoreInt64(&g.startedAt, 0)
	atomic.StoreInt32(&g.busy, 0)
}

// busyNow reports whether a load is in flight.
func (g *loadGuard) busyNow() bool { return atomic.LoadInt32(&g.busy) == 1 }

// reclaimIfStuck frees a guard whose holder has been gone too long, and reports
// whether it did.
func (g *loadGuard) reclaimIfStuck() bool {
	if !g.busyNow() {
		return false
	}
	started := time.Unix(0, atomic.LoadInt64(&g.startedAt))
	if started.IsZero() || time.Since(started) > loadWatchdog {
		g.end()
		return true
	}
	return false
}

// startedAgo is how long the current load has been running, for diagnostics.
func (g *loadGuard) startedAgo() time.Duration {
	n := atomic.LoadInt64(&g.startedAt)
	if n == 0 {
		return 0
	}
	return time.Since(time.Unix(0, n))
}
