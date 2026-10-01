package service

import "testing"

// A JSON number used to be accepted wherever a string was expected, because
// fmt.Sprint(42.0) is "42".
func TestTextRejectsNonStrings(t *testing.T) {
	for _, value := range []any{42.0, true, []any{"a"}, map[string]any{"a": "b"}} {
		if _, err := text(map[string]any{"name": value}, "name"); err == nil {
			t.Fatalf("text accepted %#v as a name", value)
		}
	}
	if _, err := text(map[string]any{"name": "  Jakarta  "}, "name"); err != nil {
		t.Fatalf("valid name rejected: %v", err)
	}
	got, err := text(map[string]any{"name": "Jakarta"}, "name")
	if err != nil || got != "Jakarta" {
		t.Fatalf("text=%q err=%v", got, err)
	}
}

func TestTextRequiresPresentNonEmptyValue(t *testing.T) {
	for _, body := range []map[string]any{{}, {"name": nil}, {"name": ""}, {"name": "   "}} {
		if _, err := text(body, "name"); err == nil {
			t.Fatalf("text accepted %#v", body)
		}
	}
}

func TestTextEnforcesLengthLimit(t *testing.T) {
	long := make([]byte, maxTextLength+1)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := text(map[string]any{"name": string(long)}, "name"); err == nil {
		t.Fatal("expected an over-long value to be rejected")
	}
	if _, err := text(map[string]any{"name": string(long[:maxTextLength])}, "name"); err != nil {
		t.Fatalf("value at the limit rejected: %v", err)
	}
}

// Every foreign-key column goes through uuidText, so a non-UUID never reaches
// a $n::uuid cast and a 22P02 -> 500.
func TestUUIDTextValidatesForeignKeys(t *testing.T) {
	if _, err := uuidText(map[string]any{"city_id": "11111111-1111-1111-1111-111111111111"}, "city_id"); err != nil {
		t.Fatalf("valid uuid rejected: %v", err)
	}
	for _, bad := range []any{"1234", "", nil, 12.0} {
		if _, err := uuidText(map[string]any{"city_id": bad}, "city_id"); err == nil {
			t.Fatalf("uuidText accepted %#v", bad)
		}
	}
}

func TestOptionalTextDefaultsAndTypeChecks(t *testing.T) {
	got, err := optionalText(map[string]any{}, "status", "scheduled")
	if err != nil || got != "scheduled" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	got, err = optionalText(map[string]any{"status": "boarding"}, "status", "scheduled")
	if err != nil || got != "boarding" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if _, err = optionalText(map[string]any{"status": 3.0}, "status", "scheduled"); err == nil {
		t.Fatal("optionalText accepted a number as a status")
	}
}

// number used to truncate a float and apply no range check, so a huge
// distance_km overflowed the integer column.
func TestNumberEnforcesWholeNumberAndRange(t *testing.T) {
	got, err := number(map[string]any{"distance_km": 150.0}, "distance_km", 1, maxRouteDistanceKm)
	if err != nil || got != 150 {
		t.Fatalf("got=%d err=%v", got, err)
	}
	for _, bad := range []float64{150.5, 0, -1, 1e18, 1e30} {
		if _, err = number(map[string]any{"distance_km": bad}, "distance_km", 1, maxRouteDistanceKm); err == nil {
			t.Fatalf("number accepted %v", bad)
		}
	}
	if _, err = number(map[string]any{"distance_km": "150"}, "distance_km", 1, maxRouteDistanceKm); err == nil {
		t.Fatal("number accepted a string")
	}
}

func TestValidBookingStatusFilter(t *testing.T) {
	for _, status := range []string{"draft", "pending_payment", "paid", "ticketed", "expired", "cancelled"} {
		if !validBookingStatuses[status] {
			t.Fatalf("%s should be a valid filter", status)
		}
	}
	for _, status := range []string{"nonsense", "PAID", "refunded", ""} {
		if validBookingStatuses[status] {
			t.Fatalf("%q should not be a valid filter", status)
		}
	}
}
