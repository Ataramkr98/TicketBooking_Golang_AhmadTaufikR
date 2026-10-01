package security

import (
	"bytes"
	"testing"
	"time"
)

func TestVaultRoundTripAndStableHash(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	hashKey := bytes.Repeat([]byte{2}, 32)
	vault, err := NewVault(key, hashKey)
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := vault.Encrypt("3174000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("3174000000000001")) {
		t.Fatal("ciphertext contains plaintext")
	}
	plain, err := vault.Decrypt(cipher)
	if err != nil || plain != "3174000000000001" {
		t.Fatalf("round trip: %q %v", plain, err)
	}
	if !bytes.Equal(vault.Hash("6281234567890"), vault.Hash("6281234567890")) {
		t.Fatal("hash must be deterministic")
	}
}
func TestSessionSigner(t *testing.T) {
	signer := NewSessionSigner(bytes.Repeat([]byte{3}, 32), time.Hour)
	id, value := signer.New()
	got, ok := signer.Verify(value)
	if !ok || got != id {
		t.Fatal("valid signed session rejected")
	}
	if _, ok = signer.Verify(value + "tampered"); ok {
		t.Fatal("tampered session accepted")
	}
}
