# Elysian Premium Lines Backend

Go API for the `ticketing-bus` frontend: Fiber, PostgreSQL, SQLC, and a cache layer (in-memory or Redis).

## Prerequisites

- Go 1.26+
- PostgreSQL 15+
- Redis only required for production mode or when running `cmd/worker` with Redis locks

## Development setup (no Docker)

1. Create a dedicated PostgreSQL database (e.g. `elysian`). Do not point `DATABASE_URL` at a database with important data.
2. Copy config and set seed secrets:

```powershell
Copy-Item .env.example .env
# Demo default (if ADMIN_SEED_PASSWORD is empty): AdminPassword123!
# For anything non-local, set a strong password before seeding.
$env:ADMIN_SEED_PASSWORD = "AdminPassword123!"
```

Generate a base64 32-byte encryption key:

```powershell
[Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
```

3. Migrate, seed, then run the API from this folder:

```powershell
go run ./cmd/migrate up
go run ./cmd/seed
go run ./cmd/api
```

API: `http://localhost:8080` — health at `/health/live` and `/health/ready`.

4. Run the frontend from `ticketing-bus`:

```powershell
$env:VITE_API_BASE_URL = "http://localhost:8080/api/v1"
npm run dev
```

`CACHE_DRIVER=memory` runs seat locks, OTP, and expiry scheduling inside the API process. That mode is only safe for single-instance development. Production refuses to start unless `CACHE_DRIVER=redis`; OTP notifications and booking expiry are handled by a separate worker:

```powershell
go run ./cmd/worker
```

## Tooling and verification

```powershell
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0 generate
go test ./...
go vet ./...
```

The PostgreSQL integration suite rolls back/migrates schema — point it only at a dedicated test database:

```powershell
$env:TEST_DATABASE_URL = "postgres://postgres:password@localhost:5432/elysian_test?sslmode=disable"
go test -tags=integration -v ./internal/service
```

Redis contract tests run when a test instance is provided. Go’s race detector on Windows also needs a C toolchain (e.g. MinGW GCC):

```powershell
$env:TEST_REDIS_URL = "redis://localhost:6379/15"
go test -v ./internal/cache
$env:CGO_ENABLED = "1"
go test -race ./...
```

HTTP contract: [`docs/openapi.yaml`](docs/openapi.yaml).

## Sessions, CSRF, and curl

- Guest mutations: HttpOnly session cookie `elysian_guest`, CSRF cookie `elysian_csrf`, and header `X-CSRF-Token` (same value as the cookie).
- Booking / checkout / payment simulation also require header `Idempotency-Key`.
- **Admin mutations with curl:** send the CSRF cookie **and** `X-CSRF-Token`. A Bearer token alone is rejected (`CSRF_INVALID`).

Example:

```powershell
# after login, capture Set-Cookie elysian_csrf from any API response
curl.exe -s -b cookies.txt -H "Authorization: Bearer $TOKEN" `
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" `
  -d '{"status":"boarding"}' `
  http://localhost:8080/api/v1/admin/trips/$TRIP_ID
```

## Admin API

Seed with `ADMIN_SEED_EMAIL`, `ADMIN_SEED_PASSWORD`, `ADMIN_SEED_ROLE`, and optional `OPERATOR_SEED_PASSWORD`. Login: `POST /api/v1/admin/auth/login`, then `Authorization: Bearer <token>`.

- **Operator:** monitor bookings, change trip status, cancel unpaid bookings, scan tickets; master-data create/update/delete requires **admin**.
- Status-only trip body `{ "status": "boarding" }` is allowed for **admin** and **operator**; operators sending extra master fields get `403 OPERATOR_TRIP_STATUS_ONLY`.

## Environment

See `.env.example` for all variables and comments.
