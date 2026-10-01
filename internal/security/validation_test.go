package security

import (
	"testing"
	"time"
)

func TestNormalizeIndonesianPhone(t *testing.T) {
	for _, input := range []string{"0812-3456-7890", "81234567890", "+62 812 3456 7890"} {
		if got := NormalizeIndonesianPhone(input); got != "6281234567890" {
			t.Fatalf("%q normalized to %q", input, got)
		}
	}
	if NormalizeIndonesianPhone("12345") != "" {
		t.Fatal("invalid phone accepted")
	}
}
func TestIdentityAndBirthDateValidation(t *testing.T) {
	if !ValidIdentity("nik", "1234567890123456") || !ValidIdentity("passport", "A1234567") {
		t.Fatal("valid identity rejected")
	}
	if ValidIdentity("nik", "123") || ValidIdentity("passport", "x!") {
		t.Fatal("invalid identity accepted")
	}
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	if !ValidDateOfBirth("1990-01-02", now) || ValidDateOfBirth("2027-01-01", now) {
		t.Fatal("birth date validation failed")
	}
}

func TestValidEmail(t *testing.T) {
	cases := map[string]bool{
		"user@example.com": true,
		"a@b.co":           true,
		"a@":               false,
		"@b.com":           false,
		"not-an-email":     false,
		"":                 false,
	}
	for in, want := range cases {
		if got := ValidEmail(in); got != want {
			t.Fatalf("ValidEmail(%q)=%v want %v", in, got, want)
		}
	}
}

func TestValidOTPCode(t *testing.T) {
	if !ValidOTPCode("123456") {
		t.Fatal("expected valid")
	}
	for _, bad := range []string{"12345", "1234567", "abcdef", ""} {
		if ValidOTPCode(bad) {
			t.Fatalf("expected invalid %q", bad)
		}
	}
}

func TestValidName(t *testing.T) {
	if !ValidName("Budi Santoso") {
		t.Fatal("expected valid")
	}
	if ValidName("Ab") || ValidName("") {
		t.Fatal("expected invalid short/empty")
	}
}

func TestValidGender(t *testing.T) {
	if !ValidGender("male") || !ValidGender("female") {
		t.Fatal("expected english enum valid")
	}
	if ValidGender("Laki-laki") {
		t.Fatal("legacy id enum should be rejected")
	}
}
