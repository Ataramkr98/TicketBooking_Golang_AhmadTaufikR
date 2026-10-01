package provider

import (
	"context"
	"encoding/json"
	"time"

	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/hibiken/asynq"
)

const NotificationOTPTask = "notification:otp"

type OTPNotification struct {
	Phone string `json:"phone"`
	Code  string `json:"code"`
}

type AsynqNotification struct {
	client *asynq.Client
	vault  *security.Vault
}

func NewAsynqNotification(options asynq.RedisClientOpt, vault *security.Vault) *AsynqNotification {
	return &AsynqNotification{client: asynq.NewClient(options), vault: vault}
}

func (n *AsynqNotification) SendOTP(ctx context.Context, phone, code string) error {
	payload, err := json.Marshal(OTPNotification{Phone: phone, Code: code})
	if err != nil {
		return err
	}
	ciphertext, err := n.vault.Encrypt(string(payload))
	if err != nil {
		return err
	}
	_, err = n.client.EnqueueContext(ctx, asynq.NewTask(NotificationOTPTask, ciphertext), asynq.Queue("critical"), asynq.MaxRetry(3), asynq.Retention(time.Hour))
	return err
}

func (n *AsynqNotification) Close() error { return n.client.Close() }

func DecodeOTPNotification(vault *security.Vault, ciphertext []byte) (OTPNotification, error) {
	plaintext, err := vault.Decrypt(ciphertext)
	if err != nil {
		return OTPNotification{}, err
	}
	var payload OTPNotification
	err = json.Unmarshal([]byte(plaintext), &payload)
	return payload, err
}
