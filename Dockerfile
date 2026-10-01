# syntax=docker/dockerfile:1

# ---- build stage -----------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src

RUN apk add --no-cache ca-certificates tzdata

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags "-s -w" -o /out/api     ./cmd/api \
 && go build -trimpath -ldflags "-s -w" -o /out/migrate ./cmd/migrate \
 && go build -trimpath -ldflags "-s -w" -o /out/worker  ./cmd/worker \
 && go build -trimpath -ldflags "-s -w" -o /out/seed    ./cmd/seed

# ---- runtime stage ---------------------------------------------------------
# 3.24 is the current Alpine stable series (3.22 reaches EOL in 2027-05).
FROM alpine:3.24 AS runtime

RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 app

WORKDIR /app

# cmd/migrate resolves "database/migrations" relative to the working directory,
# so the SQL files have to travel with the binary.
COPY --from=build --chown=app:app /out/ /app/bin/
COPY --from=build --chown=app:app /src/database/migrations/ /app/database/migrations/

ENV HTTP_ADDR=:8080
EXPOSE 8080
USER app

# busybox wget ships with alpine, so no extra tooling is needed here.
# /health/ready verifies a live database connection (therefore it succeeds
# only once migrations have been applied); /health/live is process-only.
# Compose services that do not serve HTTP override this with a disabled check.
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD wget -qO- "http://127.0.0.1:8080/health/ready" >/dev/null || exit 1

# The image carries FOUR binaries but one entrypoint, so the default is the
# HTTP API. Compose selects a different one with `entrypoint:` — NOT with
# `command:`, which would be appended to this argv and leave the API running.
# See the note at the top of ../docker-compose.yml.
ENTRYPOINT ["/app/bin/api"]