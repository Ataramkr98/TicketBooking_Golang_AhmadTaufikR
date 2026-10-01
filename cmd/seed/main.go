package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type routeSeed struct {
	OriginTerminal, DestinationTerminal, BusCode string
	Distance, Duration                           int
	Hour, Minute                                 int
	SleeperPrice, ExecutivePrice                 int64
}

// generatedBookingCodes selects bookings created by ad-hoc usage or smoke tests
// (codes like ELY-96559C1FEBFC) while preserving the curated ELY-DEMO-* dataset
// that the public demo accounts depend on.
const generatedBookingCodes = `(SELECT id FROM bookings WHERE code NOT LIKE 'ELY-DEMO-%')`

// resetGeneratedData clears transactional data produced by repeated testing so
// the demo dashboard and the demo passenger's ticket list stay curated.
// Deletion order follows the foreign-key graph: seat reservations and payment
// event references are released first (both are RESTRICT), then tickets and
// payments, then the bookings themselves (items and passengers cascade).
func resetGeneratedData(ctx context.Context, tx pgx.Tx) error {
	stmts := []string{
		`UPDATE trip_seats SET booking_id = NULL, status = 'available', reserved_until = NULL
		  WHERE booking_id IN ` + generatedBookingCodes,
		`UPDATE payment_events SET payment_id = NULL
		  WHERE payment_id IN (SELECT p.id FROM payments p
		    JOIN bookings b ON b.id = p.booking_id
		    WHERE b.code NOT LIKE 'ELY-DEMO-%')`,
		`DELETE FROM tickets WHERE booking_id IN ` + generatedBookingCodes,
		`DELETE FROM payments WHERE booking_id IN ` + generatedBookingCodes,
		`DELETE FROM bookings WHERE code NOT LIKE 'ELY-DEMO-%'`,
		`DELETE FROM idempotency_keys`,
		`DELETE FROM admin_audit_logs`,
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// historyBooking describes one curated paid booking used to populate the
// admin dashboard's 7-day revenue window and booking feed.
type historyBooking struct {
	code      string
	name      string
	phone     string
	email     string
	dob       string
	gender    string
	method    string
	dayOffset int
}

// curatedHistory is a deterministic week of past bookings. Every day of the
// 7-day revenue window is covered, so the dashboard chart always renders.
// Codes use the ELY-DEMO-1xx range, which `seed -reset` preserves.
var curatedHistory = []historyBooking{
	{"ELY-DEMO-101", "Rina Kusuma", "081234567891", "rina.kusuma@example.com", "1991-03-14", "female", "va", 6},
	{"ELY-DEMO-102", "Agus Prasetyo", "081234567892", "agus.prasetyo@example.com", "1988-11-02", "male", "qris", 5},
	{"ELY-DEMO-103", "Dewi Anggraini", "081234567893", "dewi.anggraini@example.com", "1995-07-21", "female", "wallet", 5},
	{"ELY-DEMO-104", "Fajar Nugroho", "081234567894", "fajar.nugroho@example.com", "1993-01-09", "male", "va", 4},
	{"ELY-DEMO-105", "Maya Sari", "081234567895", "maya.sari@example.com", "1997-09-30", "female", "qris", 3},
	{"ELY-DEMO-106", "Hendra Wijaya", "081234567896", "hendra.wijaya@example.com", "1985-05-16", "male", "va", 3},
	{"ELY-DEMO-107", "Putri Ayu", "081234567897", "putri.ayu@example.com", "1999-12-05", "female", "wallet", 2},
	{"ELY-DEMO-108", "Bayu Setiawan", "081234567898", "bayu.setiawan@example.com", "1990-06-27", "male", "qris", 1},
	{"ELY-DEMO-109", "Lia Kartika", "081234567899", "lia.kartika@example.com", "1994-02-11", "female", "va", 1},
	{"ELY-DEMO-110", "Indra Lesmana", "081234567800", "indra.lesmana@example.com", "1987-08-19", "male", "qris", 0},
}

// historyCodePattern identifies the generated revenue-history snapshot.
const historyCodePattern = `'ELY-DEMO-1%'`

// pickHistorySeatSQL selects any still-available seat on a scheduled trip
// departing within the next five days.
const pickHistorySeatSQL = `
	SELECT t.id::text, tf.id::text, bs.id::text, bs.code, bs.class, tf.price_amount
	FROM trip_seats ts
	JOIN trips t ON t.id = ts.trip_id
	JOIN bus_seats bs ON bs.id = ts.bus_seat_id
	JOIN trip_fares tf ON tf.trip_id = t.id AND tf.class = bs.class
	WHERE ts.status = 'available' AND t.status = 'scheduled'
	  AND t.departure_at > now() AND t.departure_at < now() + interval '5 days'
	ORDER BY t.departure_at, bs.code
	LIMIT 1`

// seedRevenueHistory rebuilds the curated 7-day booking history. It deletes the
// previous snapshot first, which keeps re-seeding idempotent and guarantees no
// booking is left pointing at a seat it no longer holds. Foreign keys are
// released in the same order as resetGeneratedData.
func seedRevenueHistory(ctx context.Context, tx pgx.Tx, vault *security.Vault) error {
	cleanup := []string{
		`UPDATE trip_seats SET status='available', booking_id=NULL, reserved_until=NULL
		  WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + historyCodePattern + `)`,
		`UPDATE payment_events SET payment_id = NULL
		  WHERE payment_id IN (SELECT p.id FROM payments p
		    JOIN bookings b ON b.id = p.booking_id
		    WHERE b.code LIKE ` + historyCodePattern + `)`,
		`DELETE FROM tickets WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + historyCodePattern + `)`,
		`DELETE FROM payments WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE ` + historyCodePattern + `)`,
		`DELETE FROM bookings WHERE code LIKE ` + historyCodePattern,
	}
	for _, stmt := range cleanup {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("clear history snapshot: %w", err)
		}
	}

	for i, h := range curatedHistory {
		created := time.Now().Add(-time.Duration(h.dayOffset) * 24 * time.Hour)

		var tripID, offerID, seatID, seatCode, classType string
		var price int64
		err := tx.QueryRow(ctx, pickHistorySeatSQL).Scan(&tripID, &offerID, &seatID, &seatCode, &classType, &price)
		if err != nil {
			log.Printf("seed warning: revenue history stopped after %d rows (no seat available in window): %v", i, err)
			return nil
		}

		tax := price * 11 / 100
		total := price + tax
		nik := fmt.Sprintf("31%014d", 750000000000+int64(i*7919))
		phoneCipher, err := vault.Encrypt(h.phone)
		if err != nil {
			return err
		}
		emailCipher, err := vault.Encrypt(h.email)
		if err != nil {
			return err
		}
		nikCipher, err := vault.Encrypt(nik)
		if err != nil {
			return err
		}

		var bookingID string
		err = tx.QueryRow(ctx, `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,contact_phone_ciphertext,contact_phone_hash,contact_email_ciphertext,subtotal_amount,tax_amount,total_amount,expires_at,created_at,updated_at)
			VALUES($1,gen_random_uuid(),$2::uuid,$3::uuid,'ticketed',$4,$5,$6,$7,$8,$9,$10,now()+interval '30 days',$11::timestamptz,$11::timestamptz)
			RETURNING id::text`,
			h.code, tripID, offerID, h.name, phoneCipher, vault.Hash("62"+h.phone[1:]), emailCipher,
			price, tax, total, created).Scan(&bookingID)
		if err != nil {
			return fmt.Errorf("insert history booking %s: %w", h.code, err)
		}

		var itemID string
		err = tx.QueryRow(ctx, `
			INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price)
			VALUES($1::uuid,$2::uuid,$3,$4,$5) RETURNING id::text`,
			bookingID, seatID, seatCode, classType, price).Scan(&itemID)
		if err != nil {
			return fmt.Errorf("insert history item %s: %w", h.code, err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO passengers(booking_item_id,full_name,identity_type,identity_ciphertext,identity_hash,date_of_birth,gender)
			VALUES($1::uuid,$2,'nik',$3,$4,$5::date,$6)`,
			itemID, h.name, nikCipher, vault.Hash(nik), h.dob, h.gender)
		if err != nil {
			return fmt.Errorf("insert history passenger %s: %w", h.code, err)
		}

		instruction, err := json.Marshal(paymentInstruction(h.method, i))
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO payments(booking_id,provider,provider_reference,method,amount,status,instruction,paid_at,expires_at,created_at,updated_at)
			VALUES($1::uuid,'simulator',$2,$3,$4,'paid',$5,$6::timestamptz,now()+interval '1 day',$6::timestamptz,$6::timestamptz)`,
			bookingID, "PAY-"+h.code[len("ELY-"):], h.method, total, instruction, created)
		if err != nil {
			return fmt.Errorf("insert history payment %s: %w", h.code, err)
		}

		_, err = tx.Exec(ctx, `
			INSERT INTO tickets(booking_id,booking_item_id,code,status,qr_nonce,issued_at)
			VALUES($1::uuid,$2::uuid,$3,'active',gen_random_uuid(),$4::timestamptz)`,
			bookingID, itemID, "TKT-"+h.code[len("ELY-"):], created)
		if err != nil {
			return fmt.Errorf("insert history ticket %s: %w", h.code, err)
		}

		_, err = tx.Exec(ctx, `UPDATE trip_seats SET status='booked', booking_id=$1::uuid
			WHERE trip_id=$2::uuid AND bus_seat_id=$3::uuid`, bookingID, tripID, seatID)
		if err != nil {
			return fmt.Errorf("reserve history seat %s: %w", h.code, err)
		}
	}
	return nil
}

// paymentInstruction builds the simulated provider payload surfaced on the
// payment page, mirroring the shapes the live payment adapter would return.
func paymentInstruction(method string, index int) map[string]any {
	switch method {
	case "qris":
		return map[string]any{
			"qr_payload": fmt.Sprintf("00020101021226670016ID.CO.ELYSIAN.WWW011893600918%08d5204581253033605802ID5914ELYSIAN LINES6007JAKARTA6304ABCD", 1000+index),
			"message":    "Simulated Elysian QRIS payment",
		}
	case "wallet":
		return map[string]any{"wallet": "ElysianPay", "message": "Simulated ElysianPay wallet debit"}
	default:
		banks := []string{"BCA", "Mandiri", "BNI", "BRI"}
		return map[string]any{
			"virtual_account": fmt.Sprintf("8808%012d", 1000+index),
			"bank":            banks[index%len(banks)],
			"message":         "Simulated virtual account payment",
		}
	}
}

func main() {
	reset := flag.Bool("reset", false, "delete bookings/tickets/payments created by testing before seeding (keeps curated ELY-DEMO-* data)")
	flag.Parse()
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	adminPassword, operatorPassword := requireSeedSecrets(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		log.Fatal(err)
	}
	defer tx.Rollback(ctx)

	if *reset {
		if err := resetGeneratedData(ctx, tx); err != nil {
			log.Fatalf("reset generated demo data: %v", err)
		}
		log.Printf("reset: removed test bookings, tickets, payments, and audit entries (curated ELY-DEMO-* data kept)")
	}

	cities := map[string]string{}
	for _, name := range []string{"Jakarta", "Surabaya", "Bandung", "Yogyakarta", "Semarang"} {
		slug := strings.ToLower(name)
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO cities(name,slug) VALUES($1,$2) ON CONFLICT(slug) DO UPDATE SET name=EXCLUDED.name,active=true RETURNING id::text`, name, slug).Scan(&id)
		must(err)
		cities[name] = id
	}
	terminalDefs := map[string]string{"Pulo Gebang": "Jakarta", "Pondok Pinang": "Jakarta", "Gambir": "Jakarta", "Bungurasih": "Surabaya", "Surabaya Kota": "Surabaya", "Bandung Pasteur": "Bandung", "Bandung Central": "Bandung", "Giwangan": "Yogyakarta", "Terboyo": "Semarang"}
	terminals := map[string]string{}
	for name, city := range terminalDefs {
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO terminals(city_id,name) VALUES($1,$2) ON CONFLICT(city_id,name) DO UPDATE SET active=true RETURNING id::text`, cities[city], name).Scan(&id)
		must(err)
		terminals[name] = id
	}
	busDefs := map[string]string{"MONARCH": "Elysian Monarch v2", "IMPERIAL": "Elysian Imperial Gold", "NIGHTSHADE": "Elysian Nightshade", "GOLDLINE": "Elysian Gold Line"}
	buses := map[string]string{}
	amenities, _ := json.Marshal([]string{"Wi-Fi", "Warm meal", "Entertainment kit", "Priority boarding"})
	for code, name := range busDefs {
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO buses(code,name,amenities) VALUES($1,$2,$3) ON CONFLICT(code) DO UPDATE SET name=EXCLUDED.name,amenities=EXCLUDED.amenities,active=true RETURNING id::text`, code, name, amenities).Scan(&id)
		must(err)
		buses[code] = id
		for i := 1; i <= 8; i++ {
			_, err = tx.Exec(ctx, `INSERT INTO bus_seats(bus_id,code,deck,class,position_row,position_col) VALUES($1,$2,'sleeper','sleeper',$3,$4) ON CONFLICT(bus_id,code) DO NOTHING`, id, "S"+itoa(i), (i-1)/2, (i-1)%2)
			must(err)
		}
		for i := 1; i <= 16; i++ {
			_, err = tx.Exec(ctx, `INSERT INTO bus_seats(bus_id,code,deck,class,position_row,position_col) VALUES($1,$2,'executive','executive',$3,$4) ON CONFLICT(bus_id,code) DO NOTHING`, id, "E"+itoa(i), (i-1)/4, (i-1)%4)
			must(err)
		}
	}
	routes := []routeSeed{{"Pulo Gebang", "Bungurasih", "MONARCH", 780, 630, 8, 0, 550000, 780000}, {"Pondok Pinang", "Surabaya Kota", "IMPERIAL", 770, 585, 20, 0, 580000, 780000}, {"Pulo Gebang", "Bungurasih", "NIGHTSHADE", 780, 600, 21, 30, 580000, 800000}, {"Gambir", "Bandung Pasteur", "GOLDLINE", 150, 180, 8, 30, 500000, 750000}, {"Bandung Central", "Bungurasih", "MONARCH", 690, 660, 19, 0, 620000, 820000}}
	// A nil *time.Location would make every time.Date call below panic. Images
	// built without tzdata get a fixed +07:00 zone instead, which is correct for
	// WIB all year round.
	jakarta := time.FixedZone("WIB", 7*60*60)
	if loc, loadErr := time.LoadLocation("Asia/Jakarta"); loadErr != nil {
		log.Printf("warning: tzdata is unavailable (%v); seeding departures in a fixed +07:00 zone", loadErr)
	} else {
		jakarta = loc
	}
	today := time.Now().In(jakarta)
	for _, r := range routes {
		var routeID string
		err = tx.QueryRow(ctx, `INSERT INTO routes(origin_terminal_id,destination_terminal_id,distance_km,estimated_duration_minutes) VALUES($1,$2,$3,$4) ON CONFLICT(origin_terminal_id,destination_terminal_id) DO UPDATE SET distance_km=EXCLUDED.distance_km,estimated_duration_minutes=EXCLUDED.estimated_duration_minutes,active=true RETURNING id::text`, terminals[r.OriginTerminal], terminals[r.DestinationTerminal], r.Distance, r.Duration).Scan(&routeID)
		must(err)
		for day := 1; day <= 30; day++ {
			departure := time.Date(today.Year(), today.Month(), today.Day(), r.Hour, r.Minute, 0, 0, jakarta).AddDate(0, 0, day)
			arrival := departure.Add(time.Duration(r.Duration) * time.Minute)
			var tripID string
			err = tx.QueryRow(ctx, `INSERT INTO trips(route_id,bus_id,departure_at,arrival_at) VALUES($1,$2,$3,$4) ON CONFLICT(route_id,bus_id,departure_at) DO UPDATE SET arrival_at=EXCLUDED.arrival_at,status='scheduled' RETURNING id::text`, routeID, buses[r.BusCode], departure, arrival).Scan(&tripID)
			must(err)
			for _, fare := range []struct {
				class string
				price int64
			}{{"sleeper", r.SleeperPrice}, {"executive", r.ExecutivePrice}} {
				_, err = tx.Exec(ctx, `INSERT INTO trip_fares(trip_id,class,deck,price_amount) VALUES($1,$2,$2,$3) ON CONFLICT(trip_id,class) DO UPDATE SET price_amount=EXCLUDED.price_amount`, tripID, fare.class, fare.price)
				must(err)
			}
			_, err = tx.Exec(ctx, `INSERT INTO trip_seats(trip_id,bus_seat_id) SELECT $1,id FROM bus_seats WHERE bus_id=$2 ON CONFLICT DO NOTHING`, tripID, buses[r.BusCode])
			must(err)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	must(err)
	var adminID string
	err = tx.QueryRow(ctx, `INSERT INTO admin_users(name,email,password_hash,role) VALUES('Elysian Administrator',$1,$2,$3) ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,role=EXCLUDED.role,active=true,updated_at=now() RETURNING id::text`, strings.ToLower(cfg.AdminSeedEmail), string(hash), cfg.AdminSeedRole).Scan(&adminID)
	must(err)

	operatorHash, err := bcrypt.GenerateFromPassword([]byte(operatorPassword), bcrypt.DefaultCost)
	must(err)
	var operatorID string
	err = tx.QueryRow(ctx, `INSERT INTO admin_users(name,email,password_hash,role) VALUES('Elysian Station Operator',$1,$2,'operator') ON CONFLICT(email) DO UPDATE SET password_hash=EXCLUDED.password_hash,role=EXCLUDED.role,active=true,updated_at=now() RETURNING id::text`, strings.ToLower(cfg.OperatorSeedEmail), string(operatorHash)).Scan(&operatorID)
	must(err)

	vault, err := security.NewVault(cfg.EncryptionKey, cfg.PIIHashKey)
	must(err)

	// Prefer first Jakarta→Surabaya trip tomorrow ordered by departure; else any tomorrow; else warn.
	var demoTripID, demoOfferID, demoBusID string
	var demoPrice int64
	err = tx.QueryRow(ctx, `
		SELECT t.id::text, f.id::text, t.bus_id::text, f.price_amount
		FROM trips t
		JOIN trip_fares f ON f.trip_id = t.id AND f.class = 'sleeper'
		JOIN routes r ON r.id = t.route_id
		JOIN terminals ot ON ot.id = r.origin_terminal_id
		JOIN cities oc ON oc.id = ot.city_id
		JOIN terminals dt ON dt.id = r.destination_terminal_id
		JOIN cities dc ON dc.id = dt.city_id
		WHERE oc.slug = 'jakarta' AND dc.slug = 'surabaya'
		  AND (t.departure_at AT TIME ZONE 'Asia/Jakarta')::date = ($1::timestamptz AT TIME ZONE 'Asia/Jakarta')::date + interval '1 day'
		ORDER BY t.departure_at
		LIMIT 1
	`, today).Scan(&demoTripID, &demoOfferID, &demoBusID, &demoPrice)
	if err != nil {
		err = tx.QueryRow(ctx, `
			SELECT t.id::text, f.id::text, t.bus_id::text, f.price_amount
			FROM trips t
			JOIN trip_fares f ON f.trip_id = t.id AND f.class = 'sleeper'
			WHERE (t.departure_at AT TIME ZONE 'Asia/Jakarta')::date = ($1::timestamptz AT TIME ZONE 'Asia/Jakarta')::date + interval '1 day'
			ORDER BY t.departure_at
			LIMIT 1
		`, today).Scan(&demoTripID, &demoOfferID, &demoBusID, &demoPrice)
	}
	if err != nil {
		log.Printf("seed warning: no trip found for demo bookings tomorrow; reference data still seeded: %v", err)
	}

	if err == nil {
		// A missing seat used to be swallowed, and the guarded insert below then
		// left a status='ticketed' booking with zero booking_items: an orphan paid
		// booking with no ticket at all.
		var seatS1, seatS2, seatS3 string
		for _, seat := range []struct {
			code string
			into *string
		}{{"S1", &seatS1}, {"S2", &seatS2}, {"S3", &seatS3}} {
			mustCtx("look up demo seat "+seat.code, tx.QueryRow(ctx, `SELECT id::text FROM bus_seats WHERE bus_id=$1::uuid AND code=$2`, demoBusID, seat.code).Scan(seat.into))
		}

		// contact_phone_ciphertext is nullable, so a swallowed encryption failure
		// stored NULL PII on a 'ticketed' booking and rendered it blank in the
		// admin manifest.
		phoneCipher, err := vault.Encrypt("081234567890")
		mustCtx("encrypt demo contact phone", err)
		phoneHash := vault.Hash("6281234567890")
		emailCipher, err := vault.Encrypt("budi.santoso@example.com")
		mustCtx("encrypt demo contact email", err)
		phone2Cipher, err := vault.Encrypt("081298765432")
		mustCtx("encrypt demo contact phone 2", err)
		phone2Hash := vault.Hash("6281298765432")
		email2Cipher, err := vault.Encrypt("siti.rahmawati@example.com")
		mustCtx("encrypt demo contact email 2", err)
		nikCipher1, err := vault.Encrypt("3174011505900001")
		mustCtx("encrypt demo NIK 1", err)
		nikHash1 := vault.Hash("3174011505900001")
		nikCipher2, err := vault.Encrypt("3174012008940002")
		mustCtx("encrypt demo NIK 2", err)
		nikHash2 := vault.Hash("3174012008940002")

		// 1. Confirmed Ticketed Booking (ELY-DEMO-001)
		var b1ID string
		b1Session := uuid.New()
		err = tx.QueryRow(ctx, `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,contact_phone_ciphertext,contact_phone_hash,contact_email_ciphertext,subtotal_amount,tax_amount,total_amount,expires_at)
			VALUES('ELY-DEMO-001',$1,$2::uuid,$3::uuid,'ticketed','Budi Santoso',$4,$5,$6,550000,60500,610500,now()+interval '30 days')
			ON CONFLICT(code) DO UPDATE SET trip_id=EXCLUDED.trip_id,offer_id=EXCLUDED.offer_id,status='ticketed',contact_name='Budi Santoso',contact_phone_ciphertext=$4,contact_phone_hash=$5,contact_email_ciphertext=$6,expires_at=EXCLUDED.expires_at,created_at=now(),updated_at=now() RETURNING id::text
		`, b1Session, demoTripID, demoOfferID, phoneCipher, phoneHash, emailCipher).Scan(&b1ID)

		if err == nil {
			var bi1ID string
			err = tx.QueryRow(ctx, `
				INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price)
				VALUES($1::uuid,$2::uuid,'S1','sleeper',550000)
				ON CONFLICT(booking_id,seat_code) DO UPDATE SET unit_price=EXCLUDED.unit_price RETURNING id::text
			`, b1ID, seatS1).Scan(&bi1ID)

			if err == nil {
				// Each of these used to discard its error and let the seed report
				// success, which could leave a 'ticketed' booking with no passenger,
				// payment, ticket, or seat.
				_, err = tx.Exec(ctx, `
					INSERT INTO passengers(booking_item_id,full_name,identity_type,identity_ciphertext,identity_hash,date_of_birth,gender)
					VALUES($1::uuid,'Budi Santoso','nik',$2,$3,'1990-05-15','male')
					ON CONFLICT(booking_item_id) DO NOTHING
				`, bi1ID, nikCipher1, nikHash1)
				mustCtx("insert demo passenger ELY-DEMO-001", err)

				instJSON, _ := json.Marshal(map[string]any{"virtual_account": "88081234567890", "bank": "BCA", "message": "Simulated BCA Virtual Account payment"})
				_, err = tx.Exec(ctx, `
					INSERT INTO payments(booking_id,provider,provider_reference,method,amount,status,instruction,paid_at,expires_at)
					VALUES($1::uuid,'simulator','PAY-DEMO-001','va',610500,'paid',$2,now(),now()+interval '1 day')
					ON CONFLICT(booking_id) DO UPDATE SET status='paid',paid_at=now()
				`, b1ID, instJSON)
				mustCtx("insert demo payment ELY-DEMO-001", err)

				_, err = tx.Exec(ctx, `
					INSERT INTO tickets(booking_id,booking_item_id,code,status,qr_nonce)
					VALUES($1::uuid,$2::uuid,'TKT-DEMO-001','active',gen_random_uuid())
					ON CONFLICT(booking_item_id) DO UPDATE SET status='active'
				`, b1ID, bi1ID)
				mustCtx("insert demo ticket ELY-DEMO-001", err)

				_, err = tx.Exec(ctx, `UPDATE trip_seats SET status='booked',booking_id=$1::uuid WHERE trip_id=$2::uuid AND bus_seat_id=$3::uuid`, b1ID, demoTripID, seatS1)
				mustCtx("reserve demo seat S1", err)
			}
		}

		// 2. Second Confirmed Ticketed Booking for Siti Rahmawati (ELY-DEMO-002)
		var b2ID string
		b2Session := uuid.New()
		err = tx.QueryRow(ctx, `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,contact_phone_ciphertext,contact_phone_hash,contact_email_ciphertext,subtotal_amount,tax_amount,total_amount,expires_at)
			VALUES('ELY-DEMO-002',$1,$2::uuid,$3::uuid,'ticketed','Siti Rahmawati',$4,$5,$6,550000,60500,610500,now()+interval '30 days')
			ON CONFLICT(code) DO UPDATE SET trip_id=EXCLUDED.trip_id,offer_id=EXCLUDED.offer_id,status='ticketed',contact_name='Siti Rahmawati',contact_phone_ciphertext=$4,contact_phone_hash=$5,contact_email_ciphertext=$6,expires_at=EXCLUDED.expires_at,created_at=now(),updated_at=now() RETURNING id::text
		`, b2Session, demoTripID, demoOfferID, phone2Cipher, phone2Hash, email2Cipher).Scan(&b2ID)

		if err == nil {
			var bi2ID string
			err = tx.QueryRow(ctx, `
				INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price)
				VALUES($1::uuid,$2::uuid,'S2','sleeper',550000)
				ON CONFLICT(booking_id,seat_code) DO UPDATE SET unit_price=EXCLUDED.unit_price RETURNING id::text
			`, b2ID, seatS2).Scan(&bi2ID)

			if err == nil {
				_, err = tx.Exec(ctx, `
					INSERT INTO passengers(booking_item_id,full_name,identity_type,identity_ciphertext,identity_hash,date_of_birth,gender)
					VALUES($1::uuid,'Siti Rahmawati','nik',$2,$3,'1994-08-20','female')
					ON CONFLICT(booking_item_id) DO NOTHING
				`, bi2ID, nikCipher2, nikHash2)
				mustCtx("insert demo passenger ELY-DEMO-002", err)

				qrisJSON, _ := json.Marshal(map[string]any{"qr_payload": "00020101021226670016ID.CO.ELYSIAN.WWW0118936009180000000000021508123456789052045812530336054066105005802ID5914ELYSIAN LINES6007JAKARTA62070703A016304ABCD", "message": "Simulated Elysian QRIS payment"})
				_, err = tx.Exec(ctx, `
					INSERT INTO payments(booking_id,provider,provider_reference,method,amount,status,instruction,paid_at,expires_at)
					VALUES($1::uuid,'simulator','PAY-DEMO-002','qris',610500,'paid',$2,now(),now()+interval '1 day')
					ON CONFLICT(booking_id) DO UPDATE SET status='paid',paid_at=now()
				`, b2ID, qrisJSON)
				mustCtx("insert demo payment ELY-DEMO-002", err)

				_, err = tx.Exec(ctx, `
					INSERT INTO tickets(booking_id,booking_item_id,code,status,qr_nonce)
					VALUES($1::uuid,$2::uuid,'TKT-DEMO-002','active',gen_random_uuid())
					ON CONFLICT(booking_item_id) DO UPDATE SET status='active'
				`, b2ID, bi2ID)
				mustCtx("insert demo ticket ELY-DEMO-002", err)

				_, err = tx.Exec(ctx, `UPDATE trip_seats SET status='booked',booking_id=$1::uuid WHERE trip_id=$2::uuid AND bus_seat_id=$3::uuid`, b2ID, demoTripID, seatS2)
				mustCtx("reserve demo seat S2", err)
			}
		}

		// 3. Pending Payment Booking (ELY-DEMO-003)
		var b3ID string
		b3Session := uuid.New()
		err = tx.QueryRow(ctx, `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,contact_phone_ciphertext,contact_phone_hash,subtotal_amount,tax_amount,total_amount,expires_at)
			VALUES('ELY-DEMO-003',$1,$2::uuid,$3::uuid,'pending_payment','Ahmad Fauzi',$4,$5,550000,60500,610500,now()+interval '2 hours')
			ON CONFLICT(code) DO UPDATE SET trip_id=EXCLUDED.trip_id,offer_id=EXCLUDED.offer_id,status='pending_payment',expires_at=EXCLUDED.expires_at,created_at=now(),updated_at=now() RETURNING id::text
		`, b3Session, demoTripID, demoOfferID, phoneCipher, phoneHash).Scan(&b3ID)
		if err == nil {
			var bi3ID string
			err = tx.QueryRow(ctx, `
				INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price)
				VALUES($1::uuid,$2::uuid,'S3','sleeper',550000)
				ON CONFLICT(booking_id,seat_code) DO NOTHING RETURNING id::text
			`, b3ID, seatS3).Scan(&bi3ID)
			if err == nil {
				vaJSON, _ := json.Marshal(map[string]any{"virtual_account": "88089988776655", "bank": "Mandiri", "message": "Transfer to the Mandiri Virtual Account"})
				_, err = tx.Exec(ctx, `
					INSERT INTO payments(booking_id,provider,provider_reference,method,amount,status,instruction,expires_at)
					VALUES($1::uuid,'simulator','PAY-DEMO-003','va',610500,'pending',$2,now()+interval '2 hours')
					ON CONFLICT(booking_id) DO NOTHING
				`, b3ID, vaJSON)
				mustCtx("insert demo payment ELY-DEMO-003", err)
				_, err = tx.Exec(ctx, `UPDATE trip_seats SET status='reserved',booking_id=$1::uuid,reserved_until=now()+interval '2 hours' WHERE trip_id=$2::uuid AND bus_seat_id=$3::uuid`, b3ID, demoTripID, seatS3)
				mustCtx("reserve demo seat S3", err)
			}
		}

		// 4. Cancelled Booking (ELY-DEMO-004)
		_, err = tx.Exec(ctx, `
			INSERT INTO bookings(code,session_id,trip_id,offer_id,status,contact_name,subtotal_amount,tax_amount,total_amount,expires_at)
			VALUES('ELY-DEMO-004',gen_random_uuid(),$1::uuid,$2::uuid,'cancelled','Dewi Lestari',550000,60500,610500,now()-interval '1 day')
			ON CONFLICT(code) DO UPDATE SET trip_id=EXCLUDED.trip_id,offer_id=EXCLUDED.offer_id,status='cancelled',expires_at=EXCLUDED.expires_at,created_at=now(),updated_at=now()
		`, demoTripID, demoOfferID)
		mustCtx("insert demo booking ELY-DEMO-004", err)

		// Self-heal the curated rows: re-point reservations at the refreshed trip,
		// bring demo payments inside the 7-day revenue window, and un-board the
		// demo tickets so the gate-scan demo starts clean on every re-seed.
		_, err = tx.Exec(ctx, `UPDATE trip_seats SET status='available', booking_id=NULL, reserved_until=NULL
			WHERE booking_id IN (SELECT id FROM bookings WHERE code LIKE 'ELY-DEMO-%') AND trip_id <> $1::uuid`, demoTripID)
		must(err)
		_, err = tx.Exec(ctx, `UPDATE payments SET created_at=now(), updated_at=now(),
			expires_at=CASE WHEN status='pending' THEN now()+interval '2 hours' ELSE now()+interval '1 day' END
			WHERE provider_reference IN ('PAY-DEMO-001','PAY-DEMO-002','PAY-DEMO-003')`)
		must(err)
		_, err = tx.Exec(ctx, `UPDATE tickets SET status='active', boarded_at=NULL, issued_at=now()
			WHERE code IN ('TKT-DEMO-001','TKT-DEMO-002')`)
		must(err)

		// Curated 7-day revenue history so the dashboard chart, booking feed, and
		// occupancy figures look alive on any date the dataset is generated.
		must(seedRevenueHistory(ctx, tx, vault))
		// Background demand: seat maps, the admin booking feed, and the
		// occupancy KPI should resemble a live operator, not an empty system.
		must(seedFleetOccupancy(ctx, tx, vault, demoTripID))

		// Seed initial audit log entries
		_, err = tx.Exec(ctx, `INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id,metadata) VALUES($1::uuid,'seed_bootstrap','system','system',jsonb_build_object('message','Initial demo dataset seeded'))`, adminID)
		mustCtx("insert seed audit entry", err)
		_, err = tx.Exec(ctx, `INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id,metadata) VALUES($1::uuid,'scan','ticket','TKT-DEMO-001',jsonb_build_object('gate','Gate A - Pulo Gebang','result','verified'))`, operatorID)
		mustCtx("insert demo scan audit entry", err)
		_, err = tx.Exec(ctx, `INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id,metadata) VALUES($1::uuid,'update_status','trips',$2,jsonb_build_object('previous','scheduled','current','boarding'))`, operatorID, demoTripID)
		mustCtx("insert demo trip status audit entry", err)
	}

	must(tx.Commit(ctx))
	log.Println("seed completed with demo accounts, bookings, tickets, and audit logs")
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// mustCtx is must() with the operation named, for the demo dataset where a
// silent failure would leave a 'ticketed' booking with no ticket behind it.
func mustCtx(what string, err error) {
	if err != nil {
		log.Fatalf("seed: %s: %v", what, err)
	}
}

// requireSeedSecrets resolves the two seed passwords. The fallbacks are printed
// in the README and in .env.example, so anywhere but local development an
// unset password is a hard failure rather than a publicly known admin account.
func requireSeedSecrets(cfg config.Config) (adminPassword, operatorPassword string) {
	if cfg.IsProduction() {
		if cfg.AdminSeedPassword == "" {
			log.Fatalf("ADMIN_SEED_PASSWORD must be set when APP_ENV=%s; refusing to seed a publicly known admin password", cfg.Environment)
		}
		if cfg.OperatorSeedPassword == "" {
			log.Fatalf("OPERATOR_SEED_PASSWORD must be set when APP_ENV=%s; refusing to seed a publicly known operator password", cfg.Environment)
		}
	}
	adminPassword, operatorPassword = cfg.AdminSeedPassword, cfg.OperatorSeedPassword
	if adminPassword == "" {
		adminPassword = "AdminPassword123!"
		log.Printf("ADMIN_SEED_PASSWORD unset; using demo default AdminPassword123! (development only)")
	}
	if operatorPassword == "" {
		operatorPassword = "OperatorPassword123!"
		log.Printf("OPERATOR_SEED_PASSWORD unset; using demo default OperatorPassword123! (development only)")
	}
	return adminPassword, operatorPassword
}
func itoa(value int) string {
	const digits = "0123456789"
	if value < 10 {
		return string(digits[value])
	}
	return string(digits[value/10]) + string(digits[value%10])
}
