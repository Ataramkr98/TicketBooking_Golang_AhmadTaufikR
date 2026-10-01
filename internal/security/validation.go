package security

import (
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ValidUUID reports whether value is a canonical UUID. Path parameters are
// interpolated into `$n::uuid` casts, so a malformed id reaches Postgres as
// SQLSTATE 22P02 (invalid_input_syntax) rather than pgx.ErrNoRows, and surfaces
// as a 500 instead of a 400.
func ValidUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	_, err := uuid.Parse(value)
	return err == nil
}

// ValidHoldID reports whether value is a hold id of the form
// "<offer-uuid>.<hold-uuid>", the shape ReplaceHold mints and the Redis scripts
// split on.
func ValidHoldID(value string) bool {
	offer, hold, found := strings.Cut(value, ".")
	if !found {
		return false
	}
	return ValidUUID(offer) && ValidUUID(hold)
}

var nonDigits = regexp.MustCompile(`\D`)
var passportPattern = regexp.MustCompile(`^[A-Za-z0-9]{6,20}$`)
var emailPattern = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)

func NormalizeIndonesianPhone(value string) string {
	digits := nonDigits.ReplaceAllString(value, "")
	if strings.HasPrefix(digits, "0") {
		digits = "62" + digits[1:]
	} else if strings.HasPrefix(digits, "8") {
		digits = "62" + digits
	}
	if !strings.HasPrefix(digits, "628") || len(digits) < 10 || len(digits) > 15 {
		return ""
	}
	return digits
}

func ValidIdentity(kind, value string) bool {
	value = strings.TrimSpace(value)
	if kind == "nik" {
		return len(value) == 16 && nonDigits.ReplaceAllString(value, "") == value
	}
	return kind == "passport" && passportPattern.MatchString(value)
}

func ValidDateOfBirth(value string, now time.Time) bool {
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && !parsed.After(now) && parsed.After(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC))
}

func ValidEmail(value string) bool {
	return emailPattern.MatchString(value)
}

func ValidOTPCode(value string) bool {
	if len(value) != 6 {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ValidName(value string) bool {
	v := strings.TrimSpace(value)
	return len(v) >= 3 && len(v) <= 120
}

func ValidGender(value string) bool {
	return value == "male" || value == "female"
}
