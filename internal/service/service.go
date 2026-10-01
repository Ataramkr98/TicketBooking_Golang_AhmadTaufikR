package service

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elysian-premium-lines/backend/internal/cache"
	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/db"
	"github.com/elysian-premium-lines/backend/internal/model"
	"github.com/elysian-premium-lines/backend/internal/provider"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	cfg             config.Config
	pool            *pgxpool.Pool
	queries         *db.Queries
	cache           cache.Store
	vault           *security.Vault
	now             func() time.Time
	paymentProvider provider.PaymentProvider
	notification    provider.NotificationSender
}

func New(cfg config.Config, pool *pgxpool.Pool, store cache.Store, vault *security.Vault) *Service {
	return &Service{cfg: cfg, pool: pool, queries: db.New(pool), cache: store, vault: vault, now: time.Now, paymentProvider: provider.NewSimulatorPayment(), notification: provider.NewLogNotification()}
}
func (s *Service) UseNotification(sender provider.NotificationSender) {
	if sender != nil {
		s.notification = sender
	}
}
func (s *Service) Ping(ctx context.Context) error { _, err := s.queries.Ping(ctx); return err }
func (s *Service) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	return s.cache.Allow(ctx, key, limit, window)
}

func pgUUID(value string) (pgtype.UUID, error) {
	id, err := uuid.Parse(value)
	if err != nil {
		return pgtype.UUID{}, err
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}
func uuidString(value pgtype.UUID) string {
	if !value.Valid {
		return ""
	}
	return uuid.UUID(value.Bytes).String()
}

const (
	// maxPassengersPerBooking matches the seat-hold limit and the maxItems
	// declared for CheckoutRequest in docs/openapi.yaml. The check runs before
	// any transaction is opened so an oversized body never costs a SERIALIZABLE
	// snapshot and a row lock.
	maxPassengersPerBooking = 6
	// maxSearchHorizonDays bounds how far ahead a trip search may look. The seed
	// only schedules 30 days out, so a year is already generous; an unbounded
	// date turns every typo into a full-table scan that returns an empty list.
	maxSearchHorizonDays = 365
	// minIdempotencyKeyLen is the minLength docs/openapi.yaml declares for the
	// Idempotency-Key header; the previous check only rejected an empty string.
	minIdempotencyKeyLen = 8
	// maxIdempotencyKeyLen caps what gets stored in idempotency_keys, whose
	// primary key includes the raw key.
	maxIdempotencyKeyLen = 200
)

const (
	// serializableAttempts and serializableBackoff bound the retry for
	// SERIALIZABLE transactions aborted by the Postgres concurrency detector.
	serializableAttempts = 3
	serializableBackoff  = 25 * time.Millisecond
)

// jakartaLocation is the timezone the search SQL filters on
// (`departure_at AT TIME ZONE 'Asia/Jakarta'`). An image built without tzdata
// gets a fixed +07:00 zone rather than a nil location, which is correct for WIB
// all year round.
var jakartaLocation = func() *time.Location {
	if loc, err := time.LoadLocation("Asia/Jakarta"); err == nil {
		return loc
	}
	log.Printf("warning: tzdata is unavailable; using a fixed +07:00 zone for Asia/Jakarta")
	return time.FixedZone("WIB", 7*60*60)
}()

// ValidHoldID reports whether value has the "<offer_uuid>.<hold_uuid>" shape
// that ReplaceHold mints and the cache stores it under.
func ValidHoldID(value string) bool { return security.ValidHoldID(value) }

// idempotencyKeyError returns the field message for an unacceptable
// Idempotency-Key, or an empty string when the key is usable.
func idempotencyKeyError(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "Idempotency-Key header is required."
	}
	if len(trimmed) < minIdempotencyKeyLen || len(trimmed) > maxIdempotencyKeyLen {
		return fmt.Sprintf("Idempotency-Key must be between %d and %d characters.", minIdempotencyKeyLen, maxIdempotencyKeyLen)
	}
	return ""
}

// errAbortTx ends a serializable transaction without reporting a failure. It
// marks a path where the answer is already known (an idempotent replay, say) and
// the transaction must be rolled back but not retried.
var errAbortTx = errors.New("transaction aborted by intent")

// runSerializable executes fn inside a SERIALIZABLE transaction, replaying the
// whole transaction when Postgres aborts it with 40001 or 40P01. Booking
// creation, checkout, and payment capture all take row locks on contested seats
// and checkout holds FOR UPDATE on the booking row, so serialization_failure is
// a routine outcome under load rather than an exceptional one; without the retry
// wrapInternal turned it into a 500.
func (s *Service) runSerializable(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return withSerializableRetry(ctx, fn, s.runSerializableOnce)
}

// withSerializableRetry carries the policy separately from the database, so the
// policy (which errors are replayable, how many attempts, what is returned) is
// unit testable without a live Postgres.
func withSerializableRetry(ctx context.Context, fn func(tx pgx.Tx) error, once func(ctx context.Context, fn func(tx pgx.Tx) error) error) error {
	for attempt := 1; ; attempt++ {
		err := once(ctx, fn)
		if err == nil {
			return nil
		}
		// A deliberate rollback, not a conflict: never replay it.
		if errors.Is(err, errAbortTx) {
			return nil
		}
		if !isSerializationFailure(err) {
			return err
		}
		if attempt >= serializableAttempts {
			return wrapInternal(err)
		}
		select {
		case <-ctx.Done():
			return wrapInternal(ctx.Err())
		case <-time.After(time.Duration(attempt) * serializableBackoff):
		}
	}
}

func (s *Service) runSerializableOnce(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return wrapInternal(err)
	}
	// No-op once the transaction has committed or rolled back.
	defer tx.Rollback(ctx)
	if err = fn(tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapInternal(err)
	}
	return nil
}

func (s *Service) ListCities(ctx context.Context, query string) ([]model.City, error) {
	rows, err := s.queries.ListCities(ctx, strings.TrimSpace(query))
	if err != nil {
		return nil, wrapInternal(err)
	}
	out := make([]model.City, len(rows))
	for i, row := range rows {
		out[i] = model.City{ID: uuidString(row.ID), Name: row.Name, Slug: row.Slug}
	}
	return out, nil
}
func (s *Service) ListDestinations(ctx context.Context, originID string) ([]model.City, error) {
	id, err := pgUUID(originID)
	if err != nil {
		return nil, invalid(map[string]string{"origin_id": "Invalid origin city."})
	}
	rows, err := s.queries.ListDestinationCities(ctx, id)
	if err != nil {
		return nil, wrapInternal(err)
	}
	out := make([]model.City, len(rows))
	for i, row := range rows {
		out[i] = model.City{ID: uuidString(row.ID), Name: row.Name, Slug: row.Slug}
	}
	return out, nil
}

type SearchInput struct {
	OriginCityID, DestinationCityID, Date, Class, Sort string
	Periods                                            []string
	Passengers                                         int
	MaxPrice                                           int64
}

func (s *Service) SearchTrips(ctx context.Context, input SearchInput) ([]model.TripOffer, error) {
	if _, err := uuid.Parse(input.OriginCityID); err != nil {
		return nil, invalid(map[string]string{"origin_city_id": "Invalid origin city."})
	}
	if _, err := uuid.Parse(input.DestinationCityID); err != nil || input.DestinationCityID == input.OriginCityID {
		return nil, invalid(map[string]string{"destination_city_id": "Invalid destination city."})
	}
	if _, err := time.Parse("2006-01-02", input.Date); err != nil {
		return nil, invalid(map[string]string{"departure_date": "Invalid departure date."})
	}
	// The search SQL compares against (departure_at AT TIME ZONE 'Asia/Jakarta')::date,
	// so the horizon is judged on calendar dates in that zone. ISO dates sort
	// lexicographically, so the string comparisons below are exact.
	today := s.now().In(jakartaLocation)
	if input.Date > today.AddDate(0, 0, maxSearchHorizonDays).Format("2006-01-02") {
		return nil, invalid(map[string]string{"departure_date": "Departure date is more than a year ahead."})
	}
	if input.Date < today.AddDate(0, 0, -1).Format("2006-01-02") {
		return nil, invalid(map[string]string{"departure_date": "Departure date is in the past."})
	}
	if input.Passengers < 1 || input.Passengers > 6 {
		return nil, invalid(map[string]string{"passengers": "Passenger count must be between 1 and 6."})
	}
	if input.Class != "" && input.Class != "sleeper" && input.Class != "executive" {
		return nil, invalid(map[string]string{"class": "Class must be sleeper or executive."})
	}
	switch input.Sort {
	case "", "price_asc", "price_desc", "duration_asc", "departure_asc":
	default:
		return nil, invalid(map[string]string{"sort": "Invalid sort option."})
	}
	args := []any{input.OriginCityID, input.DestinationCityID, input.Date, input.Passengers}
	where := []string{"oc.id = $1::uuid", "dc.id = $2::uuid", "(t.departure_at AT TIME ZONE 'Asia/Jakarta')::date = $3::date", "t.status = 'scheduled'", `(SELECT count(*) FROM trip_seats sx JOIN bus_seats bx ON bx.id=sx.bus_seat_id WHERE sx.trip_id=t.id AND bx.class=f.class AND sx.status='available') >= $4`}
	if input.Class != "" {
		args = append(args, input.Class)
		where = append(where, fmt.Sprintf("f.class = $%d", len(args)))
	}
	if input.MaxPrice > 0 {
		args = append(args, input.MaxPrice)
		where = append(where, fmt.Sprintf("f.price_amount <= $%d", len(args)))
	}
	if len(input.Periods) > 0 {
		clauses := []string{}
		for _, period := range input.Periods {
			switch period {
			case "morning":
				clauses = append(clauses, "EXTRACT(HOUR FROM t.departure_at AT TIME ZONE 'Asia/Jakarta') BETWEEN 6 AND 11")
			case "afternoon":
				clauses = append(clauses, "EXTRACT(HOUR FROM t.departure_at AT TIME ZONE 'Asia/Jakarta') BETWEEN 12 AND 17")
			case "evening":
				clauses = append(clauses, "(EXTRACT(HOUR FROM t.departure_at AT TIME ZONE 'Asia/Jakarta') >= 18 OR EXTRACT(HOUR FROM t.departure_at AT TIME ZONE 'Asia/Jakarta') < 6)")
			default:
				// Unknown values used to be dropped silently, so a mixed
				// valid/invalid list was partially honoured and read as a
				// narrower search instead of a bad request.
				return nil, invalid(map[string]string{"departure_period": "Departure period must be morning, afternoon, or evening."})
			}
		}
		if len(clauses) > 0 {
			where = append(where, "("+strings.Join(clauses, " OR ")+")")
		}
	}
	order := map[string]string{"price_asc": "f.price_amount ASC", "price_desc": "f.price_amount DESC", "duration_asc": "(t.arrival_at-t.departure_at) ASC", "departure_asc": "t.departure_at ASC"}[input.Sort]
	if order == "" {
		order = "t.departure_at ASC, f.price_amount ASC"
	}
	query := `SELECT f.id,t.id,oc.id,oc.name,dc.id,dc.name,t.departure_at,t.arrival_at,f.class,f.deck,f.price_amount,b.name,b.amenities,ot.name,dt.name,
	ARRAY(SELECT sx.bus_seat_id::text FROM trip_seats sx JOIN bus_seats bx ON bx.id=sx.bus_seat_id WHERE sx.trip_id=t.id AND bx.class=f.class AND sx.status='available')
	FROM trip_fares f JOIN trips t ON t.id=f.trip_id JOIN buses b ON b.id=t.bus_id JOIN routes r ON r.id=t.route_id JOIN terminals ot ON ot.id=r.origin_terminal_id JOIN terminals dt ON dt.id=r.destination_terminal_id JOIN cities oc ON oc.id=ot.city_id JOIN cities dc ON dc.id=dt.city_id WHERE ` + strings.Join(where, " AND ") + ` ORDER BY ` + order
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	offers := []model.TripOffer{}
	for rows.Next() {
		var offer model.TripOffer
		var amenities []byte
		var availableSeatIDs []string
		if err := rows.Scan(&offer.OfferID, &offer.TripID, &offer.OriginCityID, &offer.Origin, &offer.DestinationCityID, &offer.Destination, &offer.DepartureAt, &offer.ArrivalAt, &offer.Class, &offer.Deck, &offer.Price, &offer.BusName, &amenities, &offer.DepartureStation, &offer.ArrivalStation, &availableSeatIDs); err != nil {
			return nil, wrapInternal(err)
		}
		holders, err := s.cache.SeatHolders(ctx, offer.OfferID, availableSeatIDs)
		if err != nil {
			return nil, wrapInternal(err)
		}
		_ = json.Unmarshal(amenities, &offer.Amenities)
		offer.DurationMinutes = int(offer.ArrivalAt.Sub(offer.DepartureAt).Minutes())
		offer.SeatsLeft = len(availableSeatIDs) - len(holders)
		if offer.SeatsLeft < input.Passengers {
			continue
		}
		offers = append(offers, offer)
	}
	return offers, rows.Err()
}

// SeatMap returns the seat map for one offer. tripID is cross-checked against
// the offer: the route used to echo it straight back into the response without
// ever looking at it, so any trip id paired with any valid offer returned that
// offer's seats.
func (s *Service) SeatMap(ctx context.Context, tripID, offerID, sessionID string) ([]model.Seat, error) {
	if err := requireUUID("tripId", tripID); err != nil {
		return nil, err
	}
	id, err := pgUUID(offerID)
	if err != nil {
		return nil, invalid(map[string]string{"offer_id": "Invalid offer."})
	}
	offer, err := s.queries.GetTripOffer(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, problem(404, "OFFER_NOT_FOUND", "Trip offer not found.")
	}
	if err != nil {
		return nil, wrapInternal(err)
	}
	if uuidString(offer.TripID) != strings.ToLower(strings.TrimSpace(tripID)) {
		return nil, problem(404, "OFFER_NOT_FOUND", "The offer does not belong to this trip.")
	}
	rows, err := s.queries.GetTripSeats(ctx, id)
	if err != nil {
		return nil, wrapInternal(err)
	}
	ids := make([]string, len(rows))
	for i, row := range rows {
		ids[i] = uuidString(row.ID)
	}
	holders, err := s.cache.SeatHolders(ctx, offerID, ids)
	if err != nil {
		return nil, wrapInternal(err)
	}
	out := make([]model.Seat, len(rows))
	for i, row := range rows {
		status := row.Status
		heldByMe := false
		if row.Class != offer.Class {
			status = "unavailable_for_offer"
		} else if owner := holders[ids[i]]; owner != "" {
			status = "held"
			heldByMe = owner == sessionID
		}
		out[i] = model.Seat{ID: ids[i], Code: row.Code, Deck: row.Deck, Class: row.Class, Row: int(row.PositionRow), Column: int(row.PositionCol), Status: status, HeldByMe: heldByMe}
	}
	return out, nil
}

func (s *Service) ReplaceHold(ctx context.Context, holdID, offerID, sessionID string, seatIDs []string) (model.SeatHold, error) {
	if len(seatIDs) < 1 || len(seatIDs) > 6 {
		return model.SeatHold{}, invalid(map[string]string{"seat_ids": "Select between 1 and 6 seats."})
	}
	offerUUID, err := pgUUID(offerID)
	if err != nil {
		return model.SeatHold{}, invalid(map[string]string{"offer_id": "Invalid offer."})
	}
	offer, err := s.queries.GetTripOffer(ctx, offerUUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.SeatHold{}, problem(404, "OFFER_NOT_FOUND", "Offer not found.")
	}
	if err != nil {
		return model.SeatHold{}, wrapInternal(err)
	}
	unique := map[string]bool{}
	args := []any{uuidString(offer.TripID)}
	placeholders := []string{}
	for _, seatID := range seatIDs {
		if unique[seatID] {
			return model.SeatHold{}, invalid(map[string]string{"seat_ids": "Seats must be unique."})
		}
		unique[seatID] = true
		if _, err := uuid.Parse(seatID); err != nil {
			return model.SeatHold{}, invalid(map[string]string{"seat_ids": "Invalid seat ID."})
		}
		args = append(args, seatID)
		placeholders = append(placeholders, fmt.Sprintf("$%d::uuid", len(args)))
	}
	query := `SELECT bs.id FROM trip_seats ts JOIN bus_seats bs ON bs.id=ts.bus_seat_id WHERE ts.trip_id=$1::uuid AND bs.id IN (` + strings.Join(placeholders, ",") + `) AND bs.class=$` + strconv.Itoa(len(args)+1) + ` AND ts.status='available'`
	args = append(args, offer.Class)
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return model.SeatHold{}, wrapInternal(err)
	}
	count := 0
	for rows.Next() {
		count++
	}
	rows.Close()
	if count != len(seatIDs) {
		return model.SeatHold{}, problem(409, "SEAT_UNAVAILABLE", "One or more seats are not available for this fare.")
	}
	if holdID == "" {
		holdID = offerID + "." + uuid.NewString()
	}
	hold := model.SeatHold{ID: holdID, OfferID: offerID, SessionID: sessionID, SeatIDs: seatIDs}
	hold, err = s.cache.ReplaceHold(ctx, hold, s.cfg.SeatHoldTTL)
	if errors.Is(err, cache.ErrSeatConflict) {
		return model.SeatHold{}, problem(409, "SEAT_UNAVAILABLE", "Seats are being selected by another user.")
	}
	// Both cache implementations raise ErrHoldNotFound when the hold id exists
	// but belongs to a different session. Unhandled, that was a 500 on someone
	// else's hold.
	if errors.Is(err, cache.ErrHoldNotFound) {
		return model.SeatHold{}, problem(403, "HOLD_FORBIDDEN", "Seat hold does not belong to this session.")
	}
	if err != nil {
		return model.SeatHold{}, wrapInternal(err)
	}
	return hold, nil
}
func (s *Service) DeleteHold(ctx context.Context, holdID, sessionID string) error {
	if err := s.cache.DeleteHold(ctx, holdID, sessionID); errors.Is(err, cache.ErrHoldNotFound) {
		return problem(404, "HOLD_NOT_FOUND", "Seat hold not found.")
	} else if err != nil {
		return wrapInternal(err)
	}
	return nil
}

func bookingCode() string {
	return "ELY-" + strings.ToUpper(strings.ReplaceAll(uuid.NewString()[:13], "-", ""))
}

func bookingTransitionAllowed(from, to string) bool {
	transitions := map[string]map[string]bool{
		"draft":           {"pending_payment": true, "expired": true, "cancelled": true},
		"pending_payment": {"paid": true, "expired": true, "cancelled": true},
		"paid":            {"ticketed": true},
	}
	return transitions[from][to]
}

func calculateBookingTotals(unitPrice int64, seats int, taxRate float64) (int64, int64, int64) {
	subtotal := unitPrice * int64(seats)
	tax := int64(math.Round(float64(subtotal) * taxRate))
	return subtotal, tax, subtotal + tax
}

func (s *Service) CreateBooking(ctx context.Context, holdID, sessionID, idempotencyKey string) (model.Booking, error) {
	if message := idempotencyKeyError(idempotencyKey); message != "" {
		return model.Booking{}, invalid(map[string]string{"idempotency_key": message})
	}
	if !ValidHoldID(holdID) {
		return model.Booking{}, invalid(map[string]string{"hold_id": "Invalid seat hold id."})
	}
	hold, err := s.cache.GetHold(ctx, holdID)
	if errors.Is(err, cache.ErrHoldNotFound) {
		return model.Booking{}, problem(410, "HOLD_EXPIRED", "Seat selection time has expired.")
	}
	if err != nil {
		return model.Booking{}, wrapInternal(err)
	}
	if hold.SessionID != sessionID {
		return model.Booking{}, problem(403, "HOLD_FORBIDDEN", "Seat hold does not belong to this session.")
	}
	if !s.now().Before(hold.ExpiresAt) {
		return model.Booking{}, problem(410, "HOLD_EXPIRED", "Seat selection time has expired.")
	}
	// The transaction is replayed on 40001, so it must not touch anything outside
	// the database: the seat hold is only released once the retry has committed.
	var createdID, replayID string
	err = s.runSerializable(ctx, func(tx pgx.Tx) error {
		replayID = ""
		var existingID string
		err := tx.QueryRow(ctx, `SELECT resource_id::text FROM idempotency_keys WHERE session_id=$1::uuid AND key=$2 AND operation='create_booking'`, sessionID, idempotencyKey).Scan(&existingID)
		if err == nil {
			replayID = existingID
			return errAbortTx
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return wrapInternal(err)
		}
		var tripID, class string
		var price int64
		if err = tx.QueryRow(ctx, `SELECT trip_id::text,class,price_amount FROM trip_fares WHERE id=$1::uuid`, hold.OfferID).Scan(&tripID, &class, &price); err != nil {
			return lookupErr(err, "OFFER_NOT_FOUND", "Offer not found.")
		}
		rows, err := tx.Query(ctx, `SELECT ts.bus_seat_id::text,bs.code,bs.class,ts.status FROM trip_seats ts JOIN bus_seats bs ON bs.id=ts.bus_seat_id WHERE ts.trip_id=$1::uuid AND ts.bus_seat_id=ANY($2::uuid[]) FOR UPDATE`, tripID, hold.SeatIDs)
		if err != nil {
			return wrapInternal(err)
		}
		type seatRow struct{ id, code, class, status string }
		selected := []seatRow{}
		for rows.Next() {
			var x seatRow
			if err := rows.Scan(&x.id, &x.code, &x.class, &x.status); err != nil {
				rows.Close()
				return wrapInternal(err)
			}
			selected = append(selected, x)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return wrapInternal(err)
		}
		if len(selected) != len(hold.SeatIDs) {
			return problem(409, "SEAT_UNAVAILABLE", "Seat inventory changed.")
		}
		for _, x := range selected {
			if x.status != "available" || x.class != class {
				return problem(409, "SEAT_UNAVAILABLE", "One or more seats are no longer available.")
			}
		}
		bookingID := uuid.NewString()
		subtotal, tax, total := calculateBookingTotals(price, len(selected), s.cfg.TaxRate)
		expires := hold.ExpiresAt
		if _, err = tx.Exec(ctx, `INSERT INTO bookings(id,code,session_id,trip_id,offer_id,status,subtotal_amount,tax_amount,total_amount,expires_at) VALUES($1,$2,$3,$4,$5,'draft',$6,$7,$8,$9)`, bookingID, bookingCode(), sessionID, tripID, hold.OfferID, subtotal, tax, total, expires); err != nil {
			return wrapInternal(err)
		}
		for _, x := range selected {
			if _, err = tx.Exec(ctx, `INSERT INTO booking_items(booking_id,trip_seat_id,seat_code,class,unit_price) VALUES($1,$2,$3,$4,$5)`, bookingID, x.id, x.code, x.class, price); err != nil {
				return wrapInternal(err)
			}
			if _, err = tx.Exec(ctx, `UPDATE trip_seats SET status='reserved',booking_id=$1,reserved_until=$2 WHERE trip_id=$3 AND bus_seat_id=$4`, bookingID, expires, tripID, x.id); err != nil {
				return wrapInternal(err)
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO idempotency_keys(session_id,key,operation,resource_id) VALUES($1,$2,'create_booking',$3) ON CONFLICT DO NOTHING`, sessionID, idempotencyKey, bookingID)
		if err != nil {
			return wrapInternal(err)
		}
		if tag.RowsAffected() == 0 {
			// A concurrent request with the same key committed first: return its
			// booking rather than creating a second one.
			if err = tx.QueryRow(ctx, `SELECT resource_id::text FROM idempotency_keys WHERE session_id=$1::uuid AND key=$2 AND operation='create_booking'`, sessionID, idempotencyKey).Scan(&existingID); err != nil {
				return wrapInternal(err)
			}
			replayID = existingID
			return errAbortTx
		}
		createdID = bookingID
		return nil
	})
	if err != nil {
		return model.Booking{}, err
	}
	if replayID != "" {
		return s.GetBooking(ctx, replayID, sessionID)
	}
	_ = s.cache.DeleteHold(ctx, holdID, sessionID)
	return s.GetBooking(ctx, createdID, sessionID)
}

func (s *Service) GetBooking(ctx context.Context, id, sessionID string) (model.Booking, error) {
	if err := requireUUID("bookingId", id); err != nil {
		return model.Booking{}, err
	}
	var b model.Booking
	var seats, codes []string
	err := s.pool.QueryRow(ctx, `SELECT b.id::text,b.code,b.status,b.trip_id::text,b.offer_id::text,b.subtotal_amount,b.tax_amount,b.total_amount,b.expires_at,COALESCE(array_agg(i.trip_seat_id::text ORDER BY i.seat_code) FILTER(WHERE i.id IS NOT NULL),'{}'),COALESCE(array_agg(i.seat_code ORDER BY i.seat_code) FILTER(WHERE i.id IS NOT NULL),'{}') FROM bookings b LEFT JOIN booking_items i ON i.booking_id=b.id WHERE b.id=$1::uuid AND b.session_id=$2::uuid GROUP BY b.id`, id, sessionID).Scan(&b.ID, &b.Code, &b.Status, &b.TripID, &b.OfferID, &b.Subtotal, &b.Tax, &b.Total, &b.ExpiresAt, &seats, &codes)
	if err != nil {
		return model.Booking{}, lookupErr(err, "BOOKING_NOT_FOUND", "Booking not found.")
	}
	b.SeatIDs = seats
	b.SeatCodes = codes
	return b, nil
}

type CheckoutInput struct {
	Contact       model.Contact          `json:"contact"`
	Passengers    []model.PassengerInput `json:"passengers"`
	PaymentMethod string                 `json:"payment_method"`
}

func (s *Service) Checkout(ctx context.Context, bookingID, sessionID, idempotencyKey string, input CheckoutInput) (model.Payment, error) {
	// Bounded before anything else: the passenger array arrives in the request
	// body, and a 10k-element list used to cost a full SERIALIZABLE setup and a
	// FOR UPDATE lock on the booking row before it was rejected.
	if len(input.Passengers) < 1 || len(input.Passengers) > maxPassengersPerBooking {
		return model.Payment{}, invalid(map[string]string{"passengers": "Passenger count must be between 1 and 6."})
	}
	if err := requireUUID("bookingId", bookingID); err != nil {
		return model.Payment{}, err
	}
	fields := map[string]string{}
	phone := security.NormalizeIndonesianPhone(input.Contact.Phone)
	if !security.ValidName(input.Contact.Name) {
		fields["contact.name"] = "Contact name must be at least three characters."
	}
	if phone == "" {
		fields["contact.phone"] = "Invalid Indonesian WhatsApp number."
	}
	if input.Contact.Email != "" && !security.ValidEmail(input.Contact.Email) {
		fields["contact.email"] = "Invalid email address."
	}
	if input.PaymentMethod != "va" && input.PaymentMethod != "qris" && input.PaymentMethod != "wallet" {
		fields["payment_method"] = "Unsupported payment method."
	}
	if message := idempotencyKeyError(idempotencyKey); message != "" {
		fields["idempotency_key"] = message
	}
	for i, p := range input.Passengers {
		prefix := fmt.Sprintf("passengers.%d.", i)
		if !security.ValidName(p.FullName) {
			fields[prefix+"full_name"] = "Name must be at least three characters."
		}
		if !security.ValidIdentity(p.IdentityType, p.IdentityNumber) {
			fields[prefix+"identity_number"] = "Invalid NIK or passport number."
		}
		if !security.ValidDateOfBirth(p.DateOfBirth, s.now()) {
			fields[prefix+"date_of_birth"] = "Invalid date of birth."
		}
		if !security.ValidGender(p.Gender) {
			fields[prefix+"gender"] = "Invalid gender."
		}
	}
	if len(fields) > 0 {
		return model.Payment{}, invalid(fields)
	}
	// Replayed on 40001, so every step below has to be a pure function of the
	// database plus its arguments: no cache writes, no outbound calls whose
	// result escapes the transaction.
	var createdID, replayID string
	err := s.runSerializable(ctx, func(tx pgx.Tx) error {
		replayID = ""
		var existingPaymentID string
		err := tx.QueryRow(ctx, `SELECT resource_id::text FROM idempotency_keys WHERE session_id=$1::uuid AND key=$2 AND operation='checkout'`, sessionID, idempotencyKey).Scan(&existingPaymentID)
		if err == nil {
			replayID = existingPaymentID
			return errAbortTx
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return wrapInternal(err)
		}
		var status string
		var expires time.Time
		var total int64
		if err = tx.QueryRow(ctx, `SELECT status,expires_at,total_amount FROM bookings WHERE id=$1::uuid AND session_id=$2::uuid FOR UPDATE`, bookingID, sessionID).Scan(&status, &expires, &total); err != nil {
			return lookupErr(err, "BOOKING_NOT_FOUND", "Booking not found.")
		}
		if status == "pending_payment" || status == "paid" || status == "ticketed" {
			// Resolved inside the transaction: a second connection would block on
			// the FOR UPDATE lock this transaction still holds.
			if err = tx.QueryRow(ctx, `SELECT p.id::text FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE p.booking_id=$1::uuid AND b.session_id=$2::uuid`, bookingID, sessionID).Scan(&existingPaymentID); err != nil {
				return lookupErr(err, "PAYMENT_NOT_FOUND", "Payment not found.")
			}
			replayID = existingPaymentID
			return errAbortTx
		}
		if !bookingTransitionAllowed(status, "pending_payment") {
			return problem(409, "BOOKING_STATE_INVALID", "Booking cannot be continued.")
		}
		if !s.now().Before(expires) {
			return problem(410, "BOOKING_EXPIRED", "Booking time has expired.")
		}
		items, err := tx.Query(ctx, `SELECT id::text,trip_seat_id::text FROM booking_items WHERE booking_id=$1::uuid ORDER BY seat_code`, bookingID)
		if err != nil {
			return wrapInternal(err)
		}
		itemBySeat := map[string]string{}
		for items.Next() {
			var itemID, seatID string
			// A failed scan used to be dropped, which silently shortened the map
			// and turned the next check into a bogus "Passenger count must match
			// the seat count."
			if err = items.Scan(&itemID, &seatID); err != nil {
				items.Close()
				return wrapInternal(err)
			}
			itemBySeat[seatID] = itemID
		}
		items.Close()
		if err = items.Err(); err != nil {
			return wrapInternal(err)
		}
		if len(input.Passengers) != len(itemBySeat) {
			return invalid(map[string]string{"passengers": "Passenger count must match the seat count."})
		}
		contactPhone, err := s.vault.Encrypt(phone)
		if err != nil {
			return wrapInternal(err)
		}
		var contactEmail []byte
		if input.Contact.Email != "" {
			if contactEmail, err = s.vault.Encrypt(strings.ToLower(strings.TrimSpace(input.Contact.Email))); err != nil {
				return wrapInternal(err)
			}
		}
		seen := map[string]bool{}
		for _, p := range input.Passengers {
			itemID := itemBySeat[p.SeatID]
			if itemID == "" || seen[p.SeatID] {
				return invalid(map[string]string{"passengers": "Each seat must have exactly one passenger."})
			}
			seen[p.SeatID] = true
			cipher, err := s.vault.Encrypt(strings.TrimSpace(p.IdentityNumber))
			if err != nil {
				return wrapInternal(err)
			}
			if _, err = tx.Exec(ctx, `INSERT INTO passengers(booking_item_id,full_name,identity_type,identity_ciphertext,identity_hash,date_of_birth,gender) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(booking_item_id) DO UPDATE SET full_name=EXCLUDED.full_name,identity_type=EXCLUDED.identity_type,identity_ciphertext=EXCLUDED.identity_ciphertext,identity_hash=EXCLUDED.identity_hash,date_of_birth=EXCLUDED.date_of_birth,gender=EXCLUDED.gender`, itemID, strings.TrimSpace(p.FullName), p.IdentityType, cipher, s.vault.Hash(strings.ToUpper(strings.TrimSpace(p.IdentityNumber))), p.DateOfBirth, p.Gender); err != nil {
				return wrapInternal(err)
			}
		}
		if _, err = tx.Exec(ctx, `UPDATE bookings SET contact_name=$1,contact_phone_ciphertext=$2,contact_phone_hash=$3,contact_email_ciphertext=$4,status='pending_payment',updated_at=now() WHERE id=$5`, strings.TrimSpace(input.Contact.Name), contactPhone, s.vault.Hash(phone), contactEmail, bookingID); err != nil {
			return wrapInternal(err)
		}
		paymentID := uuid.NewString()
		reference := "SIM-" + strings.ToUpper(uuid.NewString()[:8])
		// The gateway call sits inside the SERIALIZABLE transaction. That is
		// harmless while the provider is the local simulator, but it is the seam
		// where a real PSP would add network I/O to a transaction that holds a
		// FOR UPDATE lock on the booking row and a serializable snapshot open.
		// A production integration must move this out (reserve the payment row
		// first, then call the gateway, then finish in a second transaction).
		createdPayment, err := s.paymentProvider.Create(ctx, provider.PaymentRequest{Reference: reference, Method: input.PaymentMethod, Phone: phone, Amount: total})
		if err != nil {
			return wrapInternal(err)
		}
		raw, err := json.Marshal(createdPayment.Fields)
		if err != nil {
			return wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO payments(id,booking_id,provider,provider_reference,method,amount,status,instruction,expires_at) VALUES($1,$2,$3,$4,$5,$6,'pending',$7,$8)`, paymentID, bookingID, createdPayment.Provider, reference, input.PaymentMethod, total, raw, expires); err != nil {
			return wrapInternal(err)
		}
		tag, err := tx.Exec(ctx, `INSERT INTO idempotency_keys(session_id,key,operation,resource_id) VALUES($1,$2,'checkout',$3) ON CONFLICT DO NOTHING`, sessionID, idempotencyKey, paymentID)
		if err != nil {
			return wrapInternal(err)
		}
		if tag.RowsAffected() == 0 {
			if err = tx.QueryRow(ctx, `SELECT resource_id::text FROM idempotency_keys WHERE session_id=$1::uuid AND key=$2 AND operation='checkout'`, sessionID, idempotencyKey).Scan(&existingPaymentID); err != nil {
				return wrapInternal(err)
			}
			replayID = existingPaymentID
			return errAbortTx
		}
		createdID = paymentID
		return nil
	})
	if err != nil {
		return model.Payment{}, err
	}
	if replayID != "" {
		return s.GetPayment(ctx, replayID, sessionID)
	}
	return s.GetPayment(ctx, createdID, sessionID)
}
func (s *Service) GetPayment(ctx context.Context, id, sessionID string) (model.Payment, error) {
	if err := requireUUID("paymentId", id); err != nil {
		return model.Payment{}, err
	}
	var p model.Payment
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT p.id::text,p.booking_id::text,p.provider,p.provider_reference,p.method,p.amount,p.status,p.instruction,p.expires_at FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE p.id=$1::uuid AND b.session_id=$2::uuid`, id, sessionID).Scan(&p.ID, &p.BookingID, &p.Provider, &p.Reference, &p.Method, &p.Amount, &p.Status, &raw, &p.ExpiresAt)
	if err != nil {
		return model.Payment{}, lookupErr(err, "PAYMENT_NOT_FOUND", "Payment not found.")
	}
	_ = json.Unmarshal(raw, &p.Instruction)
	p.CanSimulate = s.cfg.IsDevelopment() && p.Provider == "simulator"
	return p, nil
}

func (s *Service) MarkPaymentPaid(ctx context.Context, paymentID, sessionID, eventID string) (model.Payment, error) {
	if err := requireUUID("paymentId", paymentID); err != nil {
		return model.Payment{}, err
	}
	err := s.runSerializable(ctx, func(tx pgx.Tx) error {
		var status, bookingID, tripID string
		var expires time.Time
		if err := tx.QueryRow(ctx, `SELECT p.status,p.booking_id::text,b.trip_id::text,p.expires_at FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE p.id=$1::uuid AND b.session_id=$2::uuid FOR UPDATE`, paymentID, sessionID).Scan(&status, &bookingID, &tripID, &expires); err != nil {
			return lookupErr(err, "PAYMENT_NOT_FOUND", "Payment not found.")
		}
		if status == "paid" {
			// Already captured: the FOR UPDATE row lock plus the status read make
			// the answer idempotent without a second write.
			return errAbortTx
		}
		if status != "pending" || !s.now().Before(expires) {
			return problem(410, "PAYMENT_EXPIRED", "Payment has expired.")
		}
		if eventID == "" {
			eventID = "sim-" + uuid.NewString()
		}
		tag, err := tx.Exec(ctx, `INSERT INTO payment_events(provider,event_id,payment_id,payload) VALUES('simulator',$1,$2,'{}') ON CONFLICT DO NOTHING`, eventID, paymentID)
		if err != nil {
			return wrapInternal(err)
		}
		if tag.RowsAffected() == 0 {
			// A duplicate provider event: the payment is already settled.
			return errAbortTx
		}
		if _, err = tx.Exec(ctx, `UPDATE payments SET status='paid',paid_at=now(),updated_at=now() WHERE id=$1`, paymentID); err != nil {
			return wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE bookings SET status='paid',updated_at=now() WHERE id=$1`, bookingID); err != nil {
			return wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE trip_seats SET status='booked',reserved_until=NULL WHERE trip_id=$1 AND booking_id=$2 AND status='reserved'`, tripID, bookingID); err != nil {
			return wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tickets(booking_id,booking_item_id,code) SELECT $1,i.id,'ELY-TKT-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)) FROM booking_items i WHERE i.booking_id=$1 ON CONFLICT(booking_item_id) DO NOTHING`, bookingID); err != nil {
			return wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE bookings SET status='ticketed',updated_at=now() WHERE id=$1`, bookingID); err != nil {
			return wrapInternal(err)
		}
		return nil
	})
	if err != nil {
		return model.Payment{}, err
	}
	return s.GetPayment(ctx, paymentID, sessionID)
}

func (s *Service) MarkPaymentPaidWebhook(ctx context.Context, paymentID, eventID string) error {
	if err := requireUUID("payment_id", paymentID); err != nil {
		return err
	}
	var sessionID string
	err := s.pool.QueryRow(ctx, `SELECT b.session_id::text FROM payments p JOIN bookings b ON b.id=p.booking_id WHERE p.id=$1::uuid`, paymentID).Scan(&sessionID)
	if err != nil {
		return lookupErr(err, "PAYMENT_NOT_FOUND", "Payment not found.")
	}
	_, err = s.MarkPaymentPaid(ctx, paymentID, sessionID, eventID)
	return err
}

func randomOTP() (string, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
func (s *Service) RequestOTP(ctx context.Context, phone string) (string, error) {
	normalized := security.NormalizeIndonesianPhone(phone)
	if normalized == "" {
		return "", invalid(map[string]string{"phone": "Invalid Indonesian WhatsApp number."})
	}
	code, err := randomOTP()
	if err != nil {
		return "", wrapInternal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(s.vault.Hash(normalized))
	allowed, err := s.cache.Allow(ctx, "otp-phone:"+key, 5, time.Minute)
	if err != nil {
		return "", wrapInternal(err)
	}
	if !allowed {
		return "", problem(429, "OTP_RATE_LIMITED", "Wait before requesting another OTP.")
	}
	digest := base64.RawURLEncoding.EncodeToString(s.vault.Hash(code + "|" + key))
	if err = s.cache.SaveOTP(ctx, key, digest, s.cfg.OTPTTL, s.cfg.OTPMaxAttempts); err != nil {
		return "", wrapInternal(err)
	}
	if err = s.notification.SendOTP(ctx, normalized, code); err != nil {
		return "", wrapInternal(err)
	}
	// The code is only echoed back in development. Every other environment,
	// staging included, keeps the OTP in the notification channel alone.
	if s.cfg.IsDevelopment() {
		return code, nil
	}
	return "", nil
}
func (s *Service) VerifyOTP(ctx context.Context, phone, code string) (string, error) {
	normalized := security.NormalizeIndonesianPhone(phone)
	if normalized == "" || !security.ValidOTPCode(code) {
		return "", problem(401, "OTP_INVALID", "OTP code is invalid or expired.")
	}
	key := base64.RawURLEncoding.EncodeToString(s.vault.Hash(normalized))
	digest := base64.RawURLEncoding.EncodeToString(s.vault.Hash(code + "|" + key))
	if err := s.cache.VerifyOTP(ctx, key, digest); err != nil {
		// A cache outage is not a wrong code. Reporting it as 401 told the user
		// their OTP was bad and hid an infrastructure failure from monitoring.
		if errors.Is(err, cache.ErrOTPInvalid) || errors.Is(err, cache.ErrOTPAttempts) {
			return "", problem(401, "OTP_INVALID", "OTP code is invalid or expired.")
		}
		return "", wrapInternal(err)
	}
	return normalized, nil
}

func (s *Service) ProtectTicketAccess(phone string) (string, error) {
	ciphertext, err := s.vault.Encrypt(phone)
	if err != nil {
		return "", wrapInternal(err)
	}
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (s *Service) UnprotectTicketAccess(subject string) (string, error) {
	ciphertext, err := base64.RawURLEncoding.DecodeString(subject)
	if err != nil {
		return "", problem(401, "TICKET_ACCESS_REQUIRED", "OTP verification is required.")
	}
	phone, err := s.vault.Decrypt(ciphertext)
	if err != nil {
		return "", problem(401, "TICKET_ACCESS_REQUIRED", "OTP verification is required.")
	}
	return phone, nil
}

func (s *Service) ListTickets(ctx context.Context, phone string) ([]model.Ticket, error) {
	rows, err := s.pool.Query(ctx, `SELECT t.id::text,t.code,p.full_name,i.seat_code,bus.name,f.class,oc.name,dc.name,tr.departure_at,ot.name,dt.name,t.status FROM tickets t JOIN booking_items i ON i.id=t.booking_item_id JOIN passengers p ON p.booking_item_id=i.id JOIN bookings b ON b.id=t.booking_id JOIN trips tr ON tr.id=b.trip_id JOIN buses bus ON bus.id=tr.bus_id JOIN trip_fares f ON f.id=b.offer_id JOIN routes r ON r.id=tr.route_id JOIN terminals ot ON ot.id=r.origin_terminal_id JOIN terminals dt ON dt.id=r.destination_terminal_id JOIN cities oc ON oc.id=ot.city_id JOIN cities dc ON dc.id=dt.city_id WHERE b.contact_phone_hash=$1 AND t.status<>'cancelled' ORDER BY tr.departure_at DESC`, s.vault.Hash(phone))
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	out := []model.Ticket{}
	for rows.Next() {
		var t model.Ticket
		if err := rows.Scan(&t.ID, &t.TicketID, &t.PassengerName, &t.Seat, &t.TripName, &t.ClassType, &t.Origin, &t.Destination, &t.DepartureAt, &t.DepartureStation, &t.ArrivalStation, &t.Status); err != nil {
			return nil, wrapInternal(err)
		}
		t.QRURL = "/api/v1/tickets/" + t.ID + "/qr.svg"
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Service) TicketQRPayload(ctx context.Context, ticketID, phone string) (string, error) {
	if err := requireUUID("ticketId", ticketID); err != nil {
		return "", err
	}
	var nonce string
	err := s.pool.QueryRow(ctx, `SELECT t.qr_nonce::text FROM tickets t JOIN bookings b ON b.id=t.booking_id WHERE t.id=$1::uuid AND b.contact_phone_hash=$2`, ticketID, s.vault.Hash(phone)).Scan(&nonce)
	if err != nil {
		return "", lookupErr(err, "TICKET_NOT_FOUND", "Ticket not found.")
	}
	value := ticketID + "." + nonce
	return value + "." + security.SignToken(s.cfg.QRSigningKey, value), nil
}
func (s *Service) ScanTicket(ctx context.Context, token, adminID string) (map[string]any, error) {
	var ticketID string
	trimmed := strings.TrimSpace(token)
	parts := strings.Split(trimmed, ".")
	if len(parts) == 3 {
		if !security.VerifyToken(s.cfg.QRSigningKey, parts[0]+"."+parts[1], parts[2]) {
			return nil, problem(422, "QR_INVALID", "Invalid ticket QR code.")
		}
		// The payload is signed, but the ticket id inside it is still cast to
		// uuid, so it is checked before it reaches Postgres.
		if !security.ValidUUID(parts[0]) {
			return nil, problem(422, "QR_INVALID", "Invalid QR token or ticket code format.")
		}
		ticketID = parts[0]
	} else {
		// Support scanning or manual entry of ticket code (e.g. TKT-DEMO-001) or UUID
		err := s.pool.QueryRow(ctx, `SELECT id::text FROM tickets WHERE code = $1 OR id::text = $1`, trimmed).Scan(&ticketID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, problem(422, "QR_INVALID", "Invalid QR token or ticket code format.")
		}
		if err != nil {
			return nil, wrapInternal(err)
		}
	}

	var currentStatus string
	err := s.pool.QueryRow(ctx, `SELECT status FROM tickets WHERE id=$1::uuid`, ticketID).Scan(&currentStatus)
	if err != nil {
		return nil, lookupErr(err, "TICKET_NOT_FOUND", "Ticket not found.")
	}

	finalStatus := currentStatus
	if currentStatus == "active" {
		tag, err := s.pool.Exec(ctx, `UPDATE tickets SET status='boarded', boarded_at=now() WHERE id=$1::uuid AND status='active'`, ticketID)
		if err != nil {
			return nil, wrapInternal(err)
		}
		if tag.RowsAffected() == 1 {
			finalStatus = "boarded"
		} else {
			finalStatus = "already_boarded"
		}
	} else if currentStatus == "boarded" {
		finalStatus = "already_boarded"
	}

	var code, fullName, seatCode, busName, origin, destination string
	var departureAt time.Time
	query := `
		SELECT t.code, p.full_name, bi.seat_code, b.name, c1.name, c2.name, tr.departure_at
		FROM tickets t
		JOIN booking_items bi ON bi.id = t.booking_item_id
		JOIN passengers p ON p.booking_item_id = bi.id
		JOIN bookings bk ON bk.id = t.booking_id
		JOIN trips tr ON tr.id = bk.trip_id
		JOIN buses b ON b.id = tr.bus_id
		JOIN routes r ON r.id = tr.route_id
		JOIN terminals s1 ON s1.id = r.origin_terminal_id
		JOIN terminals s2 ON s2.id = r.destination_terminal_id
		JOIN cities c1 ON c1.id = s1.city_id
		JOIN cities c2 ON c2.id = s2.city_id
		WHERE t.id = $1::uuid
	`
	// Discarding this error produced HTTP 200 with an empty route and a zero
	// departure time, which a gate agent reads as a valid scan of nothing.
	if err = s.pool.QueryRow(ctx, query, ticketID).Scan(&code, &fullName, &seatCode, &busName, &origin, &destination, &departureAt); err != nil {
		return nil, lookupErr(err, "TICKET_NOT_FOUND", "Ticket not found.")
	}

	if _, err = s.pool.Exec(ctx, `INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id) VALUES($1,'scan','ticket',$2)`, adminID, ticketID); err != nil {
		// The boarding status is already decided, so failing the request would be
		// worse than the missing row. A scan with no audit trail is still an
		// audit failure and has to be visible in the logs.
		log.Printf("warning: audit insert for ticket scan failed admin=%s ticket=%s: %v", adminID, ticketID, err)
	}

	return map[string]any{
		"ticket_id":      ticketID,
		"ticket_code":    code,
		"status":         finalStatus,
		"passenger_name": fullName,
		"seat":           seatCode,
		"bus_name":       busName,
		"route":          origin + " → " + destination,
		"departure_at":   departureAt.Format(time.RFC3339),
	}, nil
}

func (s *Service) ExpireBookings(ctx context.Context) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, wrapInternal(err)
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT id::text,trip_id::text FROM bookings WHERE status IN ('draft','pending_payment') AND expires_at<=now() FOR UPDATE SKIP LOCKED LIMIT 100`)
	if err != nil {
		return 0, wrapInternal(err)
	}
	type item struct{ id, trip string }
	items := []item{}
	for rows.Next() {
		var x item
		if err = rows.Scan(&x.id, &x.trip); err != nil {
			rows.Close()
			return 0, wrapInternal(err)
		}
		items = append(items, x)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return 0, wrapInternal(err)
	}
	for _, x := range items {
		// Every statement is checked. These three used to discard their errors
		// and commit anyway, so a failed seat release permanently stranded the
		// seat in 'reserved' with no booking left able to reclaim it.
		if _, err = tx.Exec(ctx, `UPDATE bookings SET status='expired',updated_at=now() WHERE id=$1`, x.id); err != nil {
			return 0, wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE payments SET status='expired',updated_at=now() WHERE booking_id=$1 AND status='pending'`, x.id); err != nil {
			return 0, wrapInternal(err)
		}
		if _, err = tx.Exec(ctx, `UPDATE trip_seats SET status='available',booking_id=NULL,reserved_until=NULL WHERE trip_id=$1 AND booking_id=$2 AND status='reserved'`, x.trip, x.id); err != nil {
			return 0, wrapInternal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, wrapInternal(err)
	}
	return int64(len(items)), nil
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// dummyPasswordHash is a bcrypt hash of a value nobody knows, generated once.
// The unknown-email branch of AdminLogin compares against it so a missing
// account costs the same CPU as a wrong password; short-circuiting on
// `err != nil` skipped bcrypt entirely and turned login into an
// account-enumeration oracle.
func dummyPasswordHash() []byte {
	dummyHashOnce.Do(func() {
		// Random input at the default cost always hashes successfully.
		hash, _ := bcrypt.GenerateFromPassword([]byte(uuid.NewString()), bcrypt.DefaultCost)
		dummyHash = hash
	})
	return dummyHash
}

func (s *Service) AdminLogin(ctx context.Context, email, password string) (string, string, error) {
	var id, hash, role string
	var active bool
	err := s.pool.QueryRow(ctx, `SELECT id::text,password_hash,role,active FROM admin_users WHERE lower(email)=lower($1)`, strings.TrimSpace(email)).Scan(&id, &hash, &role, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(password))
		return "", "", problem(401, "ADMIN_LOGIN_FAILED", "Invalid email or password.")
	}
	if err != nil {
		return "", "", wrapInternal(err)
	}
	if !active {
		// Same work as a wrong password, so a deactivated account is not
		// distinguishable from a deleted one.
		_ = bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
		return "", "", problem(401, "ADMIN_LOGIN_FAILED", "Invalid email or password.")
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", "", problem(401, "ADMIN_LOGIN_FAILED", "Invalid email or password.")
	}
	return id, role, nil
}

// AdminAccount re-reads an administrator's role and active flag. adminAuth calls
// it on every request, so deactivating or demoting an account takes effect on
// the next call rather than at the end of the token's one-hour life.
func (s *Service) AdminAccount(ctx context.Context, id string) (string, bool, error) {
	if !security.ValidUUID(id) {
		return "", false, problem(401, "ADMIN_TOKEN_INVALID", "Admin token is invalid.")
	}
	var role string
	var active bool
	err := s.pool.QueryRow(ctx, `SELECT role,active FROM admin_users WHERE id=$1::uuid`, id).Scan(&role, &active)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, problem(401, "ADMIN_TOKEN_REVOKED", "This admin account no longer exists.")
	}
	if err != nil {
		return "", false, wrapInternal(err)
	}
	return role, active, nil
}
