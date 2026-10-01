package provider

import (
	"context"
	"fmt"
	"strings"
)

type PaymentRequest struct {
	Reference, Method, Phone string
	Amount                   int64
}
type PaymentInstruction struct {
	Provider string
	Fields   map[string]any
}
type PaymentProvider interface {
	Create(context.Context, PaymentRequest) (PaymentInstruction, error)
}

type SimulatorPayment struct{}

func NewSimulatorPayment() *SimulatorPayment { return &SimulatorPayment{} }
func (s *SimulatorPayment) Create(_ context.Context, request PaymentRequest) (PaymentInstruction, error) {
	fields := map[string]any{"title": "Simulated payment", "message": "Complete payment, then verify in development mode."}
	switch request.Method {
	case "va":
		suffix := request.Phone
		if len(suffix) > 8 {
			suffix = suffix[len(suffix)-8:]
		}
		fields["virtual_account"] = "8808" + suffix
	case "qris":
		fields["qr_payload"] = "ELY-QRS-" + request.Reference
	case "wallet":
		fields["redirect_url"] = "https://example.invalid/elysian-wallet/" + request.Reference
	default:
		return PaymentInstruction{}, fmt.Errorf("unsupported simulator method %q", request.Method)
	}
	return PaymentInstruction{Provider: "simulator", Fields: fields}, nil
}

type NotificationSender interface {
	SendOTP(context.Context, string, string) error
}
type LogNotification struct{}

func NewLogNotification() *LogNotification { return &LogNotification{} }
func (n *LogNotification) SendOTP(_ context.Context, phone, code string) error {
	_ = strings.HasPrefix(phone, "62")
	_ = code
	return nil
}
