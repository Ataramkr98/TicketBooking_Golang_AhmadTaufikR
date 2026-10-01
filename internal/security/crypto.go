package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Vault struct{ encryptionKey, hashKey []byte }

func NewVault(encryptionKey, hashKey []byte) (*Vault, error) {
	if len(encryptionKey) != 32 {
		return nil, errors.New("encryption key must be 32 bytes")
	}
	if len(hashKey) < 32 {
		return nil, errors.New("hash key must be at least 32 bytes")
	}
	return &Vault{encryptionKey: encryptionKey, hashKey: hashKey}, nil
}

func (v *Vault) Encrypt(plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(v.encryptionKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func (v *Vault) Decrypt(ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(v.encryptionKey)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aead.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, payload := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, payload, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (v *Vault) Hash(value string) []byte {
	mac := hmac.New(sha256.New, v.hashKey)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

type SessionSigner struct {
	key []byte
	ttl time.Duration
}

func NewSessionSigner(key []byte, ttl time.Duration) *SessionSigner {
	return &SessionSigner{key: key, ttl: ttl}
}
func (s *SessionSigner) New() (string, string) {
	id := uuid.NewString()
	exp := time.Now().Add(s.ttl).Unix()
	payload := fmt.Sprintf("%s.%d", id, exp)
	return id, payload + "." + s.sign(payload)
}
func (s *SessionSigner) Verify(value string) (string, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return "", false
	}
	payload := parts[0] + "." + parts[1]
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(s.sign(payload))) != 1 {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(parts[1], "%d", &exp); err != nil || time.Now().Unix() >= exp {
		return "", false
	}
	if _, err := uuid.Parse(parts[0]); err != nil {
		return "", false
	}
	return parts[0], true
}
func (s *SessionSigner) sign(value string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func SignToken(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func VerifyToken(key []byte, value, signature string) bool {
	return hmac.Equal([]byte(SignToken(key, value)), []byte(signature))
}
