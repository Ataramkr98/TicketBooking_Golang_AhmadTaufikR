//go:build integration

package service

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elysian-premium-lines/backend/internal/cache"
	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/model"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMigrationAndSQLCQueries(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// Every migration, in the order cmd/migrate applies them. This used to run
	// 001_init only, so 002, 003 and 004 were never executed against a real
	// Postgres by any test: an index that cannot be created, or one that
	// collides with existing rows, would have shipped undetected.
	applyAllMigrations(t, pool, "down")
	applyAllMigrations(t, pool, "up")
	t.Cleanup(func() { applyAllMigrations(t, pool, "down") })
	key := sha256.Sum256([]byte("integration-test-key"))
	vault, err := security.NewVault(key[:], key[:])
	if err != nil {
		t.Fatal(err)
	}
	svc := New(config.Config{
		Environment:    "development",
		TaxRate:        .11,
		SeatHoldTTL:    10 * time.Minute,
		OTPTTL:         5 * time.Minute,
		OTPMaxAttempts: 5,
		QRSigningKey:   key[:],
	}, pool, cache.NewMemoryStore(), vault)
	if err = svc.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO cities(name,slug) VALUES('Jakarta','jakarta')`); err != nil {
		t.Fatal(err)
	}
	cities, err := svc.ListCities(ctx, "Jak")
	if err != nil || len(cities) != 1 || cities[0].Name != "Jakarta" {
		t.Fatalf("cities=%v err=%v", cities, err)
	}

	var destinationCityID, originTerminalID, destinationTerminalID, routeID, busID, seatID, tripID, offerID string
	if err = pool.QueryRow(ctx, `INSERT INTO cities(name,slug) VALUES('Bandung','bandung') RETURNING id::text`).Scan(&destinationCityID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO terminals(city_id,name) SELECT id,'Pondok Pinang' FROM cities WHERE slug='jakarta' RETURNING id::text`).Scan(&originTerminalID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO terminals(city_id,name) VALUES($1,'Pasteur') RETURNING id::text`, destinationCityID).Scan(&destinationTerminalID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO routes(origin_terminal_id,destination_terminal_id,distance_km,estimated_duration_minutes) VALUES($1,$2,150,180) RETURNING id::text`, originTerminalID, destinationTerminalID).Scan(&routeID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO buses(code,name,amenities) VALUES('INT-01','Elysian Integration','["Wi-Fi","USB"]') RETURNING id::text`).Scan(&busID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO bus_seats(bus_id,code,deck,class,position_row,position_col) VALUES($1,'1A','executive','executive',1,1) RETURNING id::text`, busID).Scan(&seatID); err != nil {
		t.Fatal(err)
	}
	departure := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)
	if err = pool.QueryRow(ctx, `INSERT INTO trips(route_id,bus_id,departure_at,arrival_at) VALUES($1,$2,$3,$4) RETURNING id::text`, routeID, busID, departure, departure.Add(3*time.Hour)).Scan(&tripID); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `INSERT INTO trip_fares(trip_id,class,deck,price_amount) VALUES($1,'executive','executive',100000) RETURNING id::text`, tripID).Scan(&offerID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO trip_seats(trip_id,bus_seat_id) VALUES($1,$2)`, tripID, seatID); err != nil {
		t.Fatal(err)
	}

	sessionID := uuid.NewString()
	hold, err := svc.ReplaceHold(ctx, "", offerID, sessionID, []string{seatID})
	if err != nil {
		t.Fatal(err)
	}
	booking, err := svc.CreateBooking(ctx, hold.ID, sessionID, "integration-booking")
	if err != nil {
		t.Fatal(err)
	}
	if booking.Subtotal != 100000 || booking.Tax != 11000 || booking.Total != 111000 {
		t.Fatalf("server total mismatch: %+v", booking)
	}
	payment, err := svc.Checkout(ctx, booking.ID, sessionID, "integration-checkout", CheckoutInput{
		Contact: model.Contact{Name: "Integration User", Phone: "0812-3456-7890", Email: "integration@example.test"},
		Passengers: []model.PassengerInput{{
			SeatID: seatID, FullName: "Integration Passenger", IdentityType: "nik",
			IdentityNumber: "1234567890123456", DateOfBirth: "1990-01-02", Gender: "male",
		}},
		PaymentMethod: "qris",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.MarkPaymentPaid(ctx, payment.ID, sessionID, "integration-paid"); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.MarkPaymentPaid(ctx, payment.ID, sessionID, "integration-paid"); err != nil {
		t.Fatal(err)
	}
	code, err := svc.RequestOTP(ctx, "081234567890")
	if err != nil || len(code) != 6 {
		t.Fatalf("request otp code=%q err=%v", code, err)
	}
	phone, err := svc.VerifyOTP(ctx, "081234567890", code)
	if err != nil {
		t.Fatal(err)
	}
	tickets, err := svc.ListTickets(ctx, phone)
	if err != nil || len(tickets) != 1 {
		t.Fatalf("tickets=%v err=%v", tickets, err)
	}
}

// migrationFile mirrors the record cmd/migrate builds from the migrations
// directory.
type migrationFile struct {
	version int64
	name    string
	path    string
}

// collectMigrations reproduces the discovery and ordering in
// cmd/migrate/main.go: read the directory, keep "<version>_<name>.<dir>.sql",
// parse the leading integer of the stem, skip anything that does not parse,
// and sort ascending for "up" and descending for "down".
//
// The logic lives in package main, so it cannot be imported here and is
// duplicated rather than reimplemented differently. If cmd/migrate's rules
// change, this copy has to change with it; the point of running the real
// migration files in the real order is that the test stays a faithful
// rehearsal of the deploy path.
func collectMigrations(t *testing.T, direction string) []migrationFile {
	t.Helper()
	dir := filepath.Join("..", "..", "database", "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var files []migrationFile
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		parts := strings.Split(name, ".")
		if len(parts) < 3 {
			continue
		}
		if parts[len(parts)-2] != direction {
			continue
		}
		version, err := strconv.ParseInt(strings.Split(parts[0], "_")[0], 10, 64)
		if err != nil {
			continue
		}
		files = append(files, migrationFile{version: version, name: name, path: filepath.Join(dir, name)})
	}
	sort.Slice(files, func(i, j int) bool {
		if direction == "up" {
			return files[i].version < files[j].version
		}
		return files[i].version > files[j].version
	})
	return files
}

// applyAllMigrations runs every migration of the given direction. Unlike
// cmd/migrate it does not consult schema_migrations: the test owns its scratch
// database outright and must be able to re-apply the full set over whatever a
// previous run left behind.
func applyAllMigrations(t *testing.T, pool *pgxpool.Pool, direction string) {
	t.Helper()
	// A teardown must not be able to fail the test it is cleaning up after, so
	// it reports through t.Errorf and carries on to the next file.
	report := t.Errorf
	if direction == "up" {
		report = func(format string, args ...any) { t.Fatalf(format, args...) }
	}
	for _, file := range collectMigrations(t, direction) {
		sql, err := os.ReadFile(file.path)
		if err != nil {
			report("read migration %s: %v", file.name, err)
			return
		}
		// Strip UTF-8 BOM if present, as cmd/migrate does.
		if len(sql) >= 3 && sql[0] == 0xef && sql[1] == 0xbb && sql[2] == 0xbf {
			sql = sql[3:]
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			report("exec migration %s: %v", file.name, err)
			return
		}
	}
}
