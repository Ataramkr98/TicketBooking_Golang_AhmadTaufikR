package config

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Canonical APP_ENV values. Every guard in the codebase branches on one of
// these, so an unrecognised value is a configuration error rather than a silent
// downgrade to relaxed development behaviour.
const (
	EnvDevelopment = "development"
	EnvStaging     = "staging"
	EnvProduction  = "production"
)

// environmentAliases maps the spellings operators actually type onto the three
// canonical values. The previous code compared APP_ENV against the exact string
// "production", so "Production", "prod", or "staging" switched off every
// production guard: the secret-length check, placeholder rejection, the
// simulator payment endpoint, the webhook, and the OTP debug code.
var environmentAliases = map[string]string{
	"":            EnvDevelopment,
	"dev":         EnvDevelopment,
	"develop":     EnvDevelopment,
	"development": EnvDevelopment,
	"local":       EnvDevelopment,
	"stage":       EnvStaging,
	"staging":     EnvStaging,
	"stg":         EnvStaging,
	"prod":        EnvProduction,
	"production":  EnvProduction,
}

// NormalizeEnvironment lower-cases and trims APP_ENV and resolves it to one of
// the canonical values, failing loudly on anything unknown.
func NormalizeEnvironment(raw string) (string, error) {
	key := strings.ToLower(strings.TrimSpace(raw))
	if canonical, ok := environmentAliases[key]; ok {
		return canonical, nil
	}
	return "", fmt.Errorf("APP_ENV: unknown value %q (want one of development, staging, production)", strings.TrimSpace(raw))
}

// isProduction reports whether the environment name runs production guards.
// Only the development environment is relaxed.
func isProduction(env string) bool { return env != EnvDevelopment }

type Config struct {
	Environment          string
	HTTPAddr             string
	DatabaseURL          string
	CacheDriver          string
	RedisAddr            string
	RedisPassword        string
	RedisDB              int
	CORSOrigins          []string
	SessionSecret        []byte
	EncryptionKey        []byte
	PIIHashKey           []byte
	JWTSecret            []byte
	QRSigningKey         []byte
	TaxRate              float64
	SeatHoldTTL          time.Duration
	OTPTTL               time.Duration
	OTPMaxAttempts       int
	AdminSeedEmail       string
	AdminSeedPassword    string
	AdminSeedRole        string
	OperatorSeedEmail    string
	OperatorSeedPassword string
}

// IsProduction reports whether every production guard is active: real secrets,
// the Redis cache, no simulator payment endpoint, no payment webhook, no OTP
// debug codes, and Secure cookies.
//
// Staging counts as production on purpose. A staging box usually holds a copy
// of production PII and is reachable from outside the office, so relaxing the
// guards for it would expose exactly what the guards exist to protect.
// Staging differs from production in deployment identity only, never in how
// strictly it validates itself.
func (c Config) IsProduction() bool { return isProduction(c.Environment) }

// IsDevelopment reports the relaxed local mode: generated development secrets,
// the in-memory cache, the simulator payment provider, and OTP debug codes.
func (c Config) IsDevelopment() bool { return c.Environment == EnvDevelopment }

func Load() (Config, error) {
	_ = godotenv.Load()
	rawEnv := get("APP_ENV", EnvDevelopment)
	env, err := NormalizeEnvironment(rawEnv)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{
		Environment:          env,
		HTTPAddr:             get("HTTP_ADDR", ":8080"),
		DatabaseURL:          get("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/elysian?sslmode=disable"),
		CacheDriver:          get("CACHE_DRIVER", "memory"),
		RedisAddr:            get("REDIS_ADDR", "127.0.0.1:6379"),
		RedisPassword:        os.Getenv("REDIS_PASSWORD"),
		CORSOrigins:          split(get("CORS_ORIGINS", "http://localhost:5173")),
		SessionSecret:        secret("SESSION_SECRET", env),
		PIIHashKey:           secret("PII_HASH_KEY", env),
		JWTSecret:            secret("JWT_SECRET", env),
		QRSigningKey:         secret("QR_SIGNING_KEY", env),
		AdminSeedEmail:       get("ADMIN_SEED_EMAIL", "admin@elysian.local"),
		AdminSeedPassword:    os.Getenv("ADMIN_SEED_PASSWORD"),
		AdminSeedRole:        get("ADMIN_SEED_ROLE", "admin"),
		OperatorSeedEmail:    get("OPERATOR_SEED_EMAIL", "operator@elysian.local"),
		OperatorSeedPassword: os.Getenv("OPERATOR_SEED_PASSWORD"),
	}
	cfg.RedisDB, err = strconv.Atoi(get("REDIS_DB", "0"))
	if err != nil {
		return Config{}, fmt.Errorf("REDIS_DB: %w", err)
	}
	cfg.TaxRate, err = strconv.ParseFloat(get("TAX_RATE", "0.11"), 64)
	if err != nil {
		return Config{}, fmt.Errorf("TAX_RATE: %w", err)
	}
	cfg.SeatHoldTTL, err = time.ParseDuration(get("SEAT_HOLD_TTL", "10m"))
	if err != nil {
		return Config{}, fmt.Errorf("SEAT_HOLD_TTL: %w", err)
	}
	cfg.OTPTTL, err = time.ParseDuration(get("OTP_TTL", "5m"))
	if err != nil {
		return Config{}, fmt.Errorf("OTP_TTL: %w", err)
	}
	cfg.OTPMaxAttempts, err = strconv.Atoi(get("OTP_MAX_ATTEMPTS", "5"))
	if err != nil {
		return Config{}, fmt.Errorf("OTP_MAX_ATTEMPTS: %w", err)
	}
	cfg.EncryptionKey, err = encryptionKey(env)
	if err != nil {
		return Config{}, err
	}
	if cfg.CacheDriver != "memory" && cfg.CacheDriver != "redis" {
		return Config{}, errors.New("CACHE_DRIVER must be memory or redis")
	}
	if cfg.IsProduction() && cfg.CacheDriver != "redis" {
		return Config{}, errors.New("APP_ENV=" + env + " requires CACHE_DRIVER=redis")
	}
	if cfg.IsProduction() && (len(cfg.SessionSecret) < 32 || len(cfg.PIIHashKey) < 32 || len(cfg.JWTSecret) < 32 || len(cfg.QRSigningKey) < 32) {
		return Config{}, errors.New("APP_ENV=" + env + " secrets must each contain at least 32 bytes")
	}
	if cfg.IsProduction() && (placeholder("SESSION_SECRET") || placeholder("PII_HASH_KEY") || placeholder("JWT_SECRET") || placeholder("QR_SIGNING_KEY") || os.Getenv("PII_ENCRYPTION_KEY") == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		return Config{}, errors.New("APP_ENV=" + env + " secrets must not use .env.example placeholders")
	}
	if cfg.TaxRate < 0 || cfg.TaxRate > 1 {
		return Config{}, errors.New("TAX_RATE must be between 0 and 1")
	}
	return cfg, nil
}

func get(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
func split(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
func placeholder(name string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(os.Getenv(name))), "replace-with")
}
func secret(name, env string) []byte {
	if value := os.Getenv(name); value != "" {
		return []byte(value)
	}
	sum := sha256.Sum256([]byte("elysian-development-" + name))
	if isProduction(env) {
		// Returning nil here makes the length check in Load fail with a clear
		// message instead of signing sessions with a public constant.
		return nil
	}
	return sum[:]
}
func encryptionKey(env string) ([]byte, error) {
	value := os.Getenv("PII_ENCRYPTION_KEY")
	if value == "" {
		if isProduction(env) {
			return nil, errors.New("PII_ENCRYPTION_KEY is required when APP_ENV=" + env)
		}
		sum := sha256.Sum256([]byte("elysian-development-encryption-key"))
		return sum[:], nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("PII_ENCRYPTION_KEY must be base64-encoded 32 bytes")
	}
	return decoded, nil
}
