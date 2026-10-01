package cache

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/model"
	"github.com/redis/go-redis/v9"
)

type RedisStore struct{ client *redis.Client }

func NewRedisStore(addr, password string, db int) *RedisStore {
	return &RedisStore{client: redis.NewClient(&redis.Options{Addr: addr, Password: password, DB: db})}
}
func (r *RedisStore) Ping(ctx context.Context) error { return r.client.Ping(ctx).Err() }
func offerFromHoldID(id string) string {
	parts := strings.SplitN(id, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}
func redisHoldKey(offerID, id string) string { return "hold:{" + offerID + "}:" + id }
func redisSeatKey(offerID, id string) string { return "seatlock:{" + offerID + "}:" + id }

var replaceHoldScript = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
local desired = cjson.decode(ARGV[3])
for _, seat in ipairs(desired.seat_ids) do
  local owner = redis.call('GET', 'seatlock:{' .. ARGV[2] .. '}:' .. seat)
  if owner and owner ~= desired.id then return -1 end
end
if old then
  local decoded = cjson.decode(old)
  if decoded.session_id ~= ARGV[1] then return -2 end
  for _, seat in ipairs(decoded.seat_ids) do redis.call('DEL', 'seatlock:{' .. ARGV[2] .. '}:' .. seat) end
end
for _, seat in ipairs(desired.seat_ids) do redis.call('SET', 'seatlock:{' .. ARGV[2] .. '}:' .. seat, desired.id, 'PX', ARGV[4]) end
redis.call('SET', KEYS[1], ARGV[3], 'PX', ARGV[4])
return 1
`)

func (r *RedisStore) ReplaceHold(ctx context.Context, hold model.SeatHold, ttl time.Duration) (model.SeatHold, error) {
	hold.ExpiresAt = time.Now().Add(ttl)
	payload, _ := json.Marshal(hold)
	result, err := replaceHoldScript.Run(ctx, r.client, []string{redisHoldKey(hold.OfferID, hold.ID)}, hold.SessionID, hold.OfferID, string(payload), ttl.Milliseconds()).Int()
	if err != nil {
		return model.SeatHold{}, err
	}
	if result == -1 {
		return model.SeatHold{}, ErrSeatConflict
	}
	if result == -2 {
		return model.SeatHold{}, ErrHoldNotFound
	}
	return hold, nil
}
func (r *RedisStore) GetHold(ctx context.Context, id string) (model.SeatHold, error) {
	offerID := offerFromHoldID(id)
	value, err := r.client.Get(ctx, redisHoldKey(offerID, id)).Bytes()
	if err == redis.Nil {
		return model.SeatHold{}, ErrHoldNotFound
	}
	if err != nil {
		return model.SeatHold{}, err
	}
	var hold model.SeatHold
	if json.Unmarshal(value, &hold) != nil {
		return model.SeatHold{}, ErrHoldNotFound
	}
	return hold, nil
}

var deleteHoldScript = redis.NewScript(`
local old = redis.call('GET', KEYS[1])
if not old then return 0 end
local decoded = cjson.decode(old)
if decoded.session_id ~= ARGV[1] then return -1 end
for _, seat in ipairs(decoded.seat_ids) do
  local key = 'seatlock:{' .. ARGV[2] .. '}:' .. seat
  if redis.call('GET', key) == decoded.id then redis.call('DEL', key) end
end
redis.call('DEL', KEYS[1])
return 1
`)

func (r *RedisStore) DeleteHold(ctx context.Context, id, sessionID string) error {
	offerID := offerFromHoldID(id)
	if offerID == "" {
		return ErrHoldNotFound
	}
	result, err := deleteHoldScript.Run(ctx, r.client, []string{redisHoldKey(offerID, id)}, sessionID, offerID).Int()
	if err != nil {
		return err
	}
	if result != 1 {
		return ErrHoldNotFound
	}
	return nil
}
func (r *RedisStore) SeatHolders(ctx context.Context, offerID string, seatIDs []string) (map[string]string, error) {
	if len(seatIDs) == 0 {
		return map[string]string{}, nil
	}
	keys := make([]string, len(seatIDs))
	for i, id := range seatIDs {
		keys[i] = redisSeatKey(offerID, id)
	}
	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i, value := range values {
		if id, ok := value.(string); ok {
			hold, err := r.GetHold(ctx, id)
			if err == nil {
				out[seatIDs[i]] = hold.SessionID
			}
		}
	}
	return out, nil
}
func (r *RedisStore) SaveOTP(ctx context.Context, key, code string, ttl time.Duration, maxAttempts int) error {
	redisKey := "otp:" + key
	pipe := r.client.TxPipeline()
	pipe.HSet(ctx, redisKey, "code", code, "attempts", 0, "max_attempts", maxAttempts)
	pipe.Expire(ctx, redisKey, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

var verifyOTPScript = redis.NewScript(`
local stored = redis.call('HGET', KEYS[1], 'code')
if not stored then return -1 end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts') or '0')
local maximum = tonumber(redis.call('HGET', KEYS[1], 'max_attempts') or '0')
if attempts >= maximum then redis.call('DEL', KEYS[1]); return -2 end
if stored ~= ARGV[1] then redis.call('HINCRBY', KEYS[1], 'attempts', 1); return -1 end
redis.call('DEL', KEYS[1])
return 1
`)

func (r *RedisStore) VerifyOTP(ctx context.Context, key, code string) error {
	result, err := verifyOTPScript.Run(ctx, r.client, []string{"otp:" + key}, code).Int()
	if err != nil {
		return err
	}
	switch result {
	case 1:
		return nil
	case -2:
		return ErrOTPAttempts
	default:
		return ErrOTPInvalid
	}
}

var rateScript = redis.NewScript(`local count=redis.call('INCR',KEYS[1]);if count==1 then redis.call('PEXPIRE',KEYS[1],ARGV[1]) end;return count`)

func (r *RedisStore) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	count, err := rateScript.Run(ctx, r.client, []string{"rate:" + key}, window.Milliseconds()).Int()
	return count <= limit, err
}
func (r *RedisStore) Close() error { return r.client.Close() }
