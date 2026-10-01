package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/elysian-premium-lines/backend/internal/security"
)

// fleetCodePattern identifies the bulk-generated seat occupancy snapshot. It is
// deliberately outside the 1xx range used by the curated revenue history.
const fleetCodePattern = `'ELY-DEMO-9%'`

// seedFleetOccupancy books a realistic share of the seats on trips departing
// within the next three days. A seat map that is 100% available and an
// occupancy KPI close to zero immediately read as an empty system, so the
// dataset needs background demand. Seats are chosen from an md5 of the trip id
// and seat code, which keeps the same buses full on every run instead of
// shuffling the demo, and the curated walkthrough trip is excluded so the
// documented booking flow still has plenty of inventory. Everything is inserted
// set-based from one temp table, so hundreds of bookings cost a handful of
// round trips rather than one query per seat.
func seedFleetOccupancy(ctx context.Context, tx pgx.Tx, vault *security.Vault, demoTripID string) error {
	cleanup := []string{
		`UPDATE trip_seats SET status='available', booking_id=NULL, reserved_until=NULL
		  WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + fleetCodePattern + `)`,
		`UPDATE payment_events SET payment_id = NULL
		  WHERE payment_id IN (SELECT p.id FROM payments p
		    JOIN bookings b ON b.id = p.booking_id
		    WHERE b.code LIKE ` + fleetCodePattern + `)`,
		`DELETE FROM tickets WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + fleetCodePattern + `)`,
		`DELETE FROM payments WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + fleetCodePattern + `)`,
		`DELETE FROM bookings WHERE code LIKE ` + fleetCodePattern,
	}
	for _, stmt := range cleanup {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("clear fleet occupancy: %w", err)
		}
	}

	// One reusable ciphertext stands in for every background passenger's phone
	// and identity value: it stays genuinely decryptable by the vault, which
	// fabricated bytes would not be, without paying an encryption round trip per
	// seat. These rows are atmosphere, not the demo passenger's records.
	phoneCipher, err := vault.Encrypt("6281111000000")
	if err != nil {
		return err
	}
	nikCipher, err := vault.Encrypt("3171000000000000")
	if err != nil {
		return err
	}
	instruction, err := json.Marshal(paymentInstruction("qris", 0))
	if err != nil {
		return err
	}

	const names = `ARRAY['Rina Kusuma','Budi Hartono','Siti Rahayu','Agus Setiawan','Dewi Anggraini','Eko Prasetyo','Lina Marlina','Joko Susilo','Maya Sari','Hendra Wijaya','Fitri Handayani','Rizky Ramadhan','Nur Aisyah','Teuku Fahmi','Putu Dayu','Wawan Gunawan','Indah Permatasari','Dimas Aditya','Yuni Astuti','Bayu Saputra','Halim Kusnadi','Ratna Dewi','Tono Haryono','Citra Ayuningtyas']`

	// Each hash window is six hex digits wide so the cast to bigint can never
	// overflow. Every trip draws its own fill rate between 25% and 64% so the
	// fleet is not uniform, and created_at is always in the past: a payment
	// dated in the future would make the revenue chart group a day that has not
	// happened yet.
	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE fleet_seed ON COMMIT DROP AS
		SELECT 'ELY-DEMO-9' || lpad((row_number() OVER (ORDER BY t.departure_at, bs.code))::text, 4, '0') AS code,
		       t.id AS trip_id,
		       tf.id AS offer_id,
		       bs.id AS seat_id,
		       bs.code AS seat_code,
		       bs.class,
		       tf.price_amount AS price,
		       nm.names[(1 + (('x' || substr(md5(t.id::text || bs.code), 7, 6))::bit(24)::bigint % array_length(nm.names, 1)))::int] AS passenger,
		       now() - make_interval(hours => (1 + (('x' || substr(md5(bs.code || t.id::text), 13, 6))::bit(24)::bigint % 168))::int) AS created_at
		FROM trip_seats ts
		JOIN trips t ON t.id = ts.trip_id
		JOIN bus_seats bs ON bs.id = ts.bus_seat_id
		JOIN trip_fares tf ON tf.trip_id = t.id AND tf.class = bs.class
		CROSS JOIN LATERAL (SELECT `+names+` AS names) nm
		WHERE ts.status = 'available'
		  AND t.status = 'scheduled'
		  AND t.id <> $1::uuid
		  AND t.departure_at > now()
		  AND t.departure_at < now() + interval '3 days'
		  AND (('x' || substr(md5(t.id::text || bs.code), 1, 6))::bit(24)::bigint % 100)
		      < 25 + (('x' || substr(md5(t.id::text), 1, 6))::bit(24)::bigint % 40)`, demoTripID); err != nil {
		return fmt.Errorf("build fleet occupancy plan: %w", err)
	}

	// Foreign keys are filled parent-first so each statement can join back to
	// the plan through the unique booking code.
	stmts := []struct {
		label string
		sql   string
		args  []any
	}{
		{"bookings", `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,contact_phone_ciphertext,contact_phone_hash,subtotal_amount,tax_amount,total_amount,expires_at,created_at,updated_at)
			SELECT code, gen_random_uuid(), trip_id, offer_id, 'ticketed', passenger, $1, $2,
			       price, price * 11 / 100, price + price * 11 / 100,
			       now() + interval '30 days', created_at, created_at
			FROM fleet_seed`, []any{phoneCipher, vault.Hash("6281111000000")}},
		{"booking items", `
			INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price)
			SELECT b.id, f.seat_id, f.seat_code, f.class, f.price
			FROM fleet_seed f JOIN bookings b ON b.code = f.code`, nil},
		{"passengers", `
			INSERT INTO passengers(booking_item_id,full_name,identity_type,identity_ciphertext,identity_hash,date_of_birth,gender)
			SELECT bi.id, f.passenger, 'nik', $1, $2,
			       DATE '1985-03-04' + (('x' || substr(md5(f.code), 1, 6))::bit(24)::bigint % 12000)::int,
			       CASE WHEN ('x' || substr(md5(f.code), 7, 6))::bit(24)::bigint % 2 = 0 THEN 'female' ELSE 'male' END
			FROM fleet_seed f
			JOIN bookings b ON b.code = f.code
			JOIN booking_items bi ON bi.booking_id = b.id`, []any{nikCipher, vault.Hash("3171000000000000")}},
		{"payments", `
			INSERT INTO payments(booking_id,provider,provider_reference,method,amount,status,instruction,paid_at,expires_at,created_at,updated_at)
			SELECT b.id, 'simulator', 'PAY-' || substr(f.code, 5), 'qris',
			       f.price + f.price * 11 / 100, 'paid', $1::jsonb,
			       f.created_at, now() + interval '1 day', f.created_at, f.created_at
			FROM fleet_seed f JOIN bookings b ON b.code = f.code`, []any{string(instruction)}},
		{"tickets", `
			INSERT INTO tickets(booking_id,booking_item_id,code,status,qr_nonce,issued_at)
			SELECT b.id, bi.id, 'TKT-' || substr(f.code, 5), 'active', gen_random_uuid(), f.created_at
			FROM fleet_seed f
			JOIN bookings b ON b.code = f.code
			JOIN booking_items bi ON bi.booking_id = b.id`, nil},
		{"seat holds", `
			UPDATE trip_seats ts SET status = 'booked', booking_id = b.id
			FROM fleet_seed f
			JOIN bookings b ON b.code = f.code
			WHERE ts.trip_id = f.trip_id AND ts.bus_seat_id = f.seat_id`, nil},
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			return fmt.Errorf("seed fleet occupancy %s: %w", stmt.label, err)
		}
	}
	return nil
}
