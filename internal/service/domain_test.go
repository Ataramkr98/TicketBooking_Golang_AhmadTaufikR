package service

import "testing"

func TestCalculateBookingTotals(t *testing.T) {
	subtotal, tax, total := calculateBookingTotals(275000, 2, .11)
	if subtotal != 550000 || tax != 60500 || total != 610500 {
		t.Fatalf("subtotal=%d tax=%d total=%d", subtotal, tax, total)
	}
}

func TestBookingStateMachine(t *testing.T) {
	allowed := [][2]string{{"draft", "pending_payment"}, {"pending_payment", "paid"}, {"paid", "ticketed"}, {"draft", "expired"}, {"pending_payment", "cancelled"}}
	for _, transition := range allowed {
		if !bookingTransitionAllowed(transition[0], transition[1]) {
			t.Fatalf("expected transition %s -> %s", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]string{{"draft", "paid"}, {"ticketed", "draft"}, {"expired", "pending_payment"}, {"paid", "cancelled"}} {
		if bookingTransitionAllowed(transition[0], transition[1]) {
			t.Fatalf("unexpected transition %s -> %s", transition[0], transition[1])
		}
	}
}
