package security

import "testing"

func TestValidUUID(t *testing.T) {
	for _, good := range []string{
		"11111111-1111-1111-1111-111111111111",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
		"6ba7b814-9dad-11d1-80b4-00c04fd430c8",
		"550e8400-e29b-41d4-a716-446655440000",
		"f47ac10b-58cc-4372-a567-0e02b2c3d479",
	} {
		if !ValidUUID(good) {
			t.Fatalf("ValidUUID(%q)=false", good)
		}
	}
	// Everything below used to reach Postgres as a $n::uuid cast and come back
	// as SQLSTATE 22P02, which is not pgx.ErrNoRows and so became a 500.
	for _, bad := range []string{
		"",
		"garbage",
		"<nil>",
		"1",
		"11111111-1111-1111-1111-11111111111",
		"11111111-1111-1111-1111-1111111111111",
		"11111111111111111111111111111111",
		"11111111-1111-1111-1111-11111111111z",
		"11111111-1111-1111-1111-111111111111 ",
		"not-a-uuid-at-all-nope-12345678",
	} {
		if ValidUUID(bad) {
			t.Fatalf("ValidUUID(%q)=true", bad)
		}
	}
}

func TestValidHoldID(t *testing.T) {
	offer := "11111111-1111-1111-1111-111111111111"
	hold := "22222222-2222-2222-2222-222222222222"
	if !ValidHoldID(offer + "." + hold) {
		t.Fatal("a well-formed hold id was rejected")
	}
	for _, bad := range []string{
		"",
		offer,
		offer + ".",
		"." + hold,
		"garbage",
		offer + ".garbage",
		"garbage." + hold,
		offer + "." + hold + "." + offer,
	} {
		if ValidHoldID(bad) {
			t.Fatalf("ValidHoldID(%q)=true", bad)
		}
	}
}
