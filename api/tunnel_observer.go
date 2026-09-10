package api

import (
	"log"
	"sync"
	"time"
)

// packetErrorObserver counts continuing packet errors without flooding journald.
// It deliberately does not change which errors cause tunnel reconnection.
type packetErrorObserver struct {
	mu    sync.Mutex
	count uint64
	last  time.Time
}

func (o *packetErrorObserver) record(now time.Time) (uint64, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.count++
	if o.count == 1 || now.Sub(o.last) >= 30*time.Second {
		o.last = now
		return o.count, true
	}
	return o.count, false
}

func (o *packetErrorObserver) report(operation string, err error) {
	if total, emit := o.record(time.Now()); emit {
		log.Printf("Tunnel packet error: operation=%s total=%d error=%v; continuing (repeated logs limited to 30s)", operation, total, err)
	}
}
