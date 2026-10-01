package cache

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elysian-premium-lines/backend/internal/model"
)

func TestMemoryStoreRejectsConcurrentSeatHold(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	var winners atomic.Int32
	var wg sync.WaitGroup
	for _, session := range []string{"a", "b"} {
		wg.Add(1)
		go func(session string) {
			defer wg.Done()
			_, err := store.ReplaceHold(ctx, model.SeatHold{ID: "offer." + session, OfferID: "offer", SessionID: session, SeatIDs: []string{"seat-1"}}, time.Minute)
			if err == nil {
				winners.Add(1)
			} else if err != ErrSeatConflict {
				t.Errorf("unexpected error: %v", err)
			}
		}(session)
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("got %d winners", winners.Load())
	}
}
func TestMemoryOTPExpiresAndLimitsAttempts(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	_ = store.SaveOTP(ctx, "phone", "123456", time.Minute, 2)
	if err := store.VerifyOTP(ctx, "phone", "000000"); err != ErrOTPInvalid {
		t.Fatalf("first attempt: %v", err)
	}
	if err := store.VerifyOTP(ctx, "phone", "000000"); err != ErrOTPInvalid {
		t.Fatalf("second attempt: %v", err)
	}
	if err := store.VerifyOTP(ctx, "phone", "123456"); err != ErrOTPAttempts {
		t.Fatalf("attempt limit: %v", err)
	}
}
func TestMemoryRateLimit(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		allowed, err := store.Allow(ctx, "ip", 2, time.Minute)
		if err != nil || !allowed {
			t.Fatalf("request %d rejected", i+1)
		}
	}
	allowed, err := store.Allow(ctx, "ip", 2, time.Minute)
	if err != nil || allowed {
		t.Fatal("request above limit accepted")
	}
}
