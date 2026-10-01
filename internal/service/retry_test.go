package service

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func pgErr(code string) error { return &pgconn.PgError{Code: code, Message: "test"} }

func TestIsSerializationFailure(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		if !isSerializationFailure(pgErr(code)) {
			t.Fatalf("expected %s to be retryable", code)
		}
	}
	for _, err := range []error{
		pgErr("23505"),
		pgErr("23503"),
		pgErr("23514"),
		pgErr("22P02"),
		pgErr("08006"),
		context.DeadlineExceeded,
		context.Canceled,
		errors.New("network is unreachable"),
		problem(409, "SEAT_UNAVAILABLE", "nope"),
		invalid(map[string]string{"a": "b"}),
	} {
		if isSerializationFailure(err) {
			t.Fatalf("expected %v to be non-retryable", err)
		}
	}
	// Wrapped the way wrapInternal does it.
	if !isSerializationFailure(wrapInternal(pgErr("40001"))) {
		t.Fatal("wrapped 40001 should still be retryable")
	}
}

func TestIsConstraintViolation(t *testing.T) {
	for _, code := range []string{"23000", "23502", "23503", "23505", "23514"} {
		if !isConstraintViolation(pgErr(code)) {
			t.Fatalf("expected %s to be a constraint violation", code)
		}
	}
	for _, code := range []string{"22P02", "40001", "08006", "42P01"} {
		if isConstraintViolation(pgErr(code)) {
			t.Fatalf("expected %s not to be a constraint violation", code)
		}
	}
	if isConstraintViolation(context.DeadlineExceeded) {
		t.Fatal("a context deadline is not a constraint violation")
	}
}

// A dropped connection used to be reported to the client as a 404.
func TestLookupErrDistinguishesNotFoundFromFailure(t *testing.T) {
	if err := lookupErr(nil, "X", "x"); err != nil {
		t.Fatalf("nil error should pass through, got %v", err)
	}
	err := lookupErr(pgx.ErrNoRows, "BOOKING_NOT_FOUND", "Booking not found.")
	var problem *Error
	if !errors.As(err, &problem) || problem.Status != 404 || problem.Code != "BOOKING_NOT_FOUND" {
		t.Fatalf("ErrNoRows produced %v", err)
	}
	for _, cause := range []error{context.DeadlineExceeded, errors.New("connection reset"), pgErr("22P02")} {
		err = lookupErr(cause, "BOOKING_NOT_FOUND", "Booking not found.")
		var problem *Error
		if errors.As(err, &problem) {
			t.Fatalf("cause %v produced a client problem %v", cause, err)
		}
	}
}

func TestRequireUUIDRejectsMalformedIdentifiers(t *testing.T) {
	if err := requireUUID("bookingId", "11111111-1111-1111-1111-111111111111"); err != nil {
		t.Fatalf("valid uuid rejected: %v", err)
	}
	for _, bad := range []string{"", "garbage", "<nil>", "1", "not-a-uuid-at-all-nope-1234"} {
		err := requireUUID("bookingId", bad)
		var problem *Error
		if !errors.As(err, &problem) {
			t.Fatalf("%q produced %T, want *Error", bad, err)
		}
		if problem.Status != 400 || problem.Code != "INVALID_IDENTIFIER" {
			t.Fatalf("%q produced status=%d code=%s", bad, problem.Status, problem.Code)
		}
		if problem.Fields["bookingId"] == "" {
			t.Fatalf("%q produced no field error", bad)
		}
	}
}

func TestIdempotencyKeyBounds(t *testing.T) {
	if msg := idempotencyKeyError("1234567"); msg == "" {
		t.Fatal("a 7-character key must be rejected (openapi declares minLength 8)")
	}
	if msg := idempotencyKeyError(""); msg == "" {
		t.Fatal("an empty key must be rejected")
	}
	if msg := idempotencyKeyError("12345678"); msg != "" {
		t.Fatalf("8 characters should be accepted, got %q", msg)
	}
	long := make([]byte, maxIdempotencyKeyLen+1)
	for i := range long {
		long[i] = 'k'
	}
	if msg := idempotencyKeyError(string(long)); msg == "" {
		t.Fatal("an oversized key must be rejected")
	}
	if msg := idempotencyKeyError(string(make([]byte, maxIdempotencyKeyLen))); msg != "" {
		t.Fatalf("a key at the limit should be accepted, got %q", msg)
	}
}

// The retry wrapper is the fix for Postgres 40001 under seat contention, which
// previously became a 500.
func TestSerializableRetryReplaysOnSerializationFailure(t *testing.T) {
	attempts := 0
	err := withSerializableRetry(context.Background(), func(pgx.Tx) error { return nil },
		func(context.Context, func(pgx.Tx) error) error {
			attempts++
			if attempts < 3 {
				return wrapInternal(pgErr("40001"))
			}
			return nil
		})
	if err != nil {
		t.Fatalf("expected the third attempt to succeed, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts=%d want 3", attempts)
	}
}

func TestSerializableRetryGivesUpAfterBoundedAttempts(t *testing.T) {
	attempts := 0
	err := withSerializableRetry(context.Background(), func(pgx.Tx) error { return nil },
		func(context.Context, func(pgx.Tx) error) error {
			attempts++
			return wrapInternal(pgErr("40001"))
		})
	if err == nil {
		t.Fatal("expected an error once the attempts are exhausted")
	}
	if attempts != serializableAttempts {
		t.Fatalf("attempts=%d want %d", attempts, serializableAttempts)
	}
}

func TestSerializableRetryDoesNotReplayDeterministicErrors(t *testing.T) {
	attempts := 0
	sentinel := problem(409, "SEAT_UNAVAILABLE", "One or more seats are no longer available.")
	err := withSerializableRetry(context.Background(), func(pgx.Tx) error { return nil },
		func(context.Context, func(pgx.Tx) error) error {
			attempts++
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected the original problem to survive, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

// An idempotent replay aborts the transaction on purpose and must not be
// retried, and must not be reported as an error either.
func TestSerializableRetrySwallowsIntentionalAbort(t *testing.T) {
	attempts := 0
	err := withSerializableRetry(context.Background(), func(pgx.Tx) error { return nil },
		func(context.Context, func(pgx.Tx) error) error {
			attempts++
			return errAbortTx
		})
	if err != nil {
		t.Fatalf("errAbortTx should be reported as success, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

func TestSerializableRetryStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	attempts := 0
	err := withSerializableRetry(ctx, func(pgx.Tx) error { return nil },
		func(context.Context, func(pgx.Tx) error) error {
			attempts++
			return wrapInternal(pgErr("40001"))
		})
	if err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if attempts != 1 {
		t.Fatalf("attempts=%d want 1", attempts)
	}
}

func TestHoldIDValidation(t *testing.T) {
	if !ValidHoldID("11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222") {
		t.Fatal("a well-formed hold id was rejected")
	}
	for _, bad := range []string{"", "garbage", "11111111-1111-1111-1111-111111111111", "11111111-1111-1111-1111-111111111111.", ".22222222-2222-2222-2222-222222222222", "a.b"} {
		if ValidHoldID(bad) {
			t.Fatalf("%q was accepted as a hold id", bad)
		}
	}
}

func TestAdminWriteErrorSeparatesConstraintFromInfrastructure(t *testing.T) {
	err := adminWriteError(pgErr("23505"), "resource", "Data is invalid or already in use.")
	var problem *Error
	if !errors.As(err, &problem) || problem.Status != 422 {
		t.Fatalf("a unique violation should be a 422, got %v", err)
	}
	err = adminWriteError(context.DeadlineExceeded, "resource", "Data is invalid or already in use.")
	if err == nil {
		t.Fatal("expected an infrastructure error")
	}
	if errors.As(err, &problem) {
		t.Fatalf("a context deadline should not be reported as a client problem, got %v", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the cause should be preserved for the log, got %v", err)
	}
}
