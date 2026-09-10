package api

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestPacketErrorCountsAndLogRate(t *testing.T) {
	var observer packetErrorObserver
	now := time.Unix(100, 0)
	if n, emit := observer.record(now); n != 1 || !emit {
		t.Fatal(n, emit)
	}
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, emit := observer.record(now.Add(time.Second)); emit {
				t.Error("repeated error emitted early")
			}
		}()
	}
	wg.Wait()
	if n, emit := observer.record(now.Add(30 * time.Second)); n != 102 || !emit {
		t.Fatal(n, emit)
	}
}

func TestTunnelReconnectSleepCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); err != context.Canceled {
		t.Fatal(err)
	}
}

func TestPacketPoolHeadroom(t *testing.T) {
	pool := NewNetBuffer(1280 + datagramContextIDHeadroom)
	b := pool.Get()
	if len(b[datagramContextIDHeadroom:]) != 1280 {
		t.Fatal("payload allocation does not reserve context headroom")
	}
	pool.Put(b)
	pool.Put(make([]byte, 8))
	if len(pool.Get()) != 1281 {
		t.Fatal("foreign buffer accepted")
	}
}
