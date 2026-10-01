package cache

import (
	"context"
	"sync"
	"time"

	"github.com/elysian-premium-lines/backend/internal/model"
)

type otpEntry struct {
	Code                  string
	ExpiresAt             time.Time
	Attempts, MaxAttempts int
}
type rateEntry struct {
	Count     int
	ExpiresAt time.Time
}
type MemoryStore struct {
	mu         sync.Mutex
	holds      map[string]model.SeatHold
	seatOwners map[string]string
	otps       map[string]otpEntry
	rates      map[string]rateEntry
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{holds: map[string]model.SeatHold{}, seatOwners: map[string]string{}, otps: map[string]otpEntry{}, rates: map[string]rateEntry{}}
}
func seatKey(offerID, seatID string) string { return offerID + ":" + seatID }

func (m *MemoryStore) ReplaceHold(_ context.Context, hold model.SeatHold, ttl time.Duration) (model.SeatHold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	if previous, ok := m.holds[hold.ID]; ok && previous.SessionID != hold.SessionID {
		return model.SeatHold{}, ErrHoldNotFound
	}
	for _, seatID := range hold.SeatIDs {
		if owner := m.seatOwners[seatKey(hold.OfferID, seatID)]; owner != "" && owner != hold.ID {
			return model.SeatHold{}, ErrSeatConflict
		}
	}
	if previous, ok := m.holds[hold.ID]; ok {
		for _, seatID := range previous.SeatIDs {
			delete(m.seatOwners, seatKey(previous.OfferID, seatID))
		}
	}
	hold.ExpiresAt = time.Now().Add(ttl)
	for _, seatID := range hold.SeatIDs {
		m.seatOwners[seatKey(hold.OfferID, seatID)] = hold.ID
	}
	m.holds[hold.ID] = hold
	return hold, nil
}

func (m *MemoryStore) GetHold(_ context.Context, id string) (model.SeatHold, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	hold, ok := m.holds[id]
	if !ok {
		return model.SeatHold{}, ErrHoldNotFound
	}
	return hold, nil
}
func (m *MemoryStore) DeleteHold(_ context.Context, id, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hold, ok := m.holds[id]
	if !ok || hold.SessionID != sessionID {
		return ErrHoldNotFound
	}
	for _, seatID := range hold.SeatIDs {
		delete(m.seatOwners, seatKey(hold.OfferID, seatID))
	}
	delete(m.holds, id)
	return nil
}
func (m *MemoryStore) SeatHolders(_ context.Context, offerID string, seatIDs []string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	out := map[string]string{}
	for _, seatID := range seatIDs {
		if owner := m.seatOwners[seatKey(offerID, seatID)]; owner != "" {
			out[seatID] = m.holds[owner].SessionID
		}
	}
	return out, nil
}
func (m *MemoryStore) SaveOTP(_ context.Context, key, code string, ttl time.Duration, maxAttempts int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.otps[key] = otpEntry{Code: code, ExpiresAt: time.Now().Add(ttl), MaxAttempts: maxAttempts}
	return nil
}
func (m *MemoryStore) VerifyOTP(_ context.Context, key, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.otps[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		delete(m.otps, key)
		return ErrOTPInvalid
	}
	if entry.Attempts >= entry.MaxAttempts {
		delete(m.otps, key)
		return ErrOTPAttempts
	}
	if entry.Code != code {
		entry.Attempts++
		m.otps[key] = entry
		return ErrOTPInvalid
	}
	delete(m.otps, key)
	return nil
}
func (m *MemoryStore) Allow(_ context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := m.rates[key]
	if entry.ExpiresAt.IsZero() || time.Now().After(entry.ExpiresAt) {
		entry = rateEntry{ExpiresAt: time.Now().Add(window)}
	}
	entry.Count++
	m.rates[key] = entry
	return entry.Count <= limit, nil
}
func (m *MemoryStore) Close() error { return nil }
func (m *MemoryStore) cleanup() {
	now := time.Now()
	for id, hold := range m.holds {
		if now.After(hold.ExpiresAt) {
			for _, seatID := range hold.SeatIDs {
				delete(m.seatOwners, seatKey(hold.OfferID, seatID))
			}
			delete(m.holds, id)
		}
	}
	for key, otp := range m.otps {
		if now.After(otp.ExpiresAt) {
			delete(m.otps, key)
		}
	}
	for key, entry := range m.rates {
		if now.After(entry.ExpiresAt) {
			delete(m.rates, key)
		}
	}
}
