package provider

import (
	"context"
	"testing"
)

func TestSimulatorPaymentMethods(t *testing.T) {
	provider := NewSimulatorPayment()
	for _, method := range []string{"va", "qris", "wallet"} {
		instruction, err := provider.Create(context.Background(), PaymentRequest{Reference: "REF-1", Method: method, Phone: "6281234567890", Amount: 111000})
		if err != nil || instruction.Provider != "simulator" || len(instruction.Fields) == 0 {
			t.Fatalf("method=%s instruction=%v err=%v", method, instruction, err)
		}
	}
	if _, err := provider.Create(context.Background(), PaymentRequest{Method: "cash"}); err == nil {
		t.Fatal("unsupported method accepted")
	}
}
