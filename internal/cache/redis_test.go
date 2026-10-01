package cache

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elysian-premium-lines/backend/internal/model"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

func TestRedisStoreContract(t *testing.T) {
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		t.Skip("TEST_REDIS_URL is required")
	}
	options, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	store := &RedisStore{client: redis.NewClient(options)}
	defer store.Close()
	ctx := context.Background()
	if err = store.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	offerID := uuid.NewString()
	seatID := uuid.NewString()
	var winners atomic.Int32
	var wait sync.WaitGroup
	for _, session := range []string{uuid.NewString(), uuid.NewString()} {
		wait.Add(1)
		go func(session string) {
			defer wait.Done()
			_, holdErr := store.ReplaceHold(ctx, model.SeatHold{ID: offerID + "." + uuid.NewString(), OfferID: offerID, SessionID: session, SeatIDs: []string{seatID}}, time.Minute)
			if holdErr == nil {
				winners.Add(1)
			} else if holdErr != ErrSeatConflict {
				t.Errorf("unexpected hold error: %v", holdErr)
			}
		}(session)
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("got %d hold winners", winners.Load())
	}

	otpKey := uuid.NewString()
	if err = store.SaveOTP(ctx, otpKey, "digest", time.Minute, 2); err != nil {
		t.Fatal(err)
	}
	if err = store.VerifyOTP(ctx, otpKey, "wrong"); err != ErrOTPInvalid {
		t.Fatalf("first OTP attempt: %v", err)
	}
	if err = store.VerifyOTP(ctx, otpKey, "wrong"); err != ErrOTPInvalid {
		t.Fatalf("second OTP attempt: %v", err)
	}
	if err = store.VerifyOTP(ctx, otpKey, "digest"); err != ErrOTPAttempts {
		t.Fatalf("OTP attempt limit: %v", err)
	}
}
