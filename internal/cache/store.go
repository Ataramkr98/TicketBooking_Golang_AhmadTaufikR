package cache

import (
	"context"
	"errors"
	"time"

	"github.com/elysian-premium-lines/backend/internal/model"
)

var ErrSeatConflict = errors.New("one or more seats are already held")
var ErrHoldNotFound = errors.New("seat hold not found")
var ErrOTPInvalid = errors.New("otp is invalid or expired")
var ErrOTPAttempts = errors.New("otp attempt limit reached")

type Store interface {
	ReplaceHold(context.Context, model.SeatHold, time.Duration) (model.SeatHold, error)
	GetHold(context.Context, string) (model.SeatHold, error)
	DeleteHold(context.Context, string, string) error
	SeatHolders(context.Context, string, []string) (map[string]string, error)
	SaveOTP(context.Context, string, string, time.Duration, int) error
	VerifyOTP(context.Context, string, string) error
	Allow(context.Context, string, int, time.Duration) (bool, error)
	Close() error
}
