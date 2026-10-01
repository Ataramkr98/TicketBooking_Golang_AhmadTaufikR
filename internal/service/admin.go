package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/google/uuid"
)

var adminListQueries = map[string]string{
	"cities":    `SELECT id::text,name,slug,active,created_at FROM cities ORDER BY name`,
	"terminals": `SELECT t.id::text,t.city_id::text,c.name,t.name,t.active,t.created_at FROM terminals t JOIN cities c ON c.id=t.city_id ORDER BY c.name,t.name`,
	"routes":    `SELECT r.id::text,r.origin_terminal_id::text,ot.name,r.destination_terminal_id::text,dt.name,r.distance_km,r.estimated_duration_minutes,r.active FROM routes r JOIN terminals ot ON ot.id=r.origin_terminal_id JOIN terminals dt ON dt.id=r.destination_terminal_id ORDER BY ot.name,dt.name`,
	"buses":     `SELECT id::text,code,name,amenities,active,created_at FROM buses ORDER BY code`,
	"trips":     `SELECT t.id::text,t.route_id::text,t.bus_id::text,t.departure_at,t.arrival_at,t.status,oc.name AS origin_city,ot.name AS origin_terminal,dc.name AS destination_city,dt.name AS destination_terminal,b.name AS bus_name,b.code AS bus_code FROM trips t JOIN routes r ON r.id=t.route_id JOIN terminals ot ON ot.id=r.origin_terminal_id JOIN cities oc ON oc.id=ot.city_id JOIN terminals dt ON dt.id=r.destination_terminal_id JOIN cities dc ON dc.id=dt.city_id JOIN buses b ON b.id=t.bus_id ORDER BY t.departure_at DESC LIMIT 500`,
	"fares":     `SELECT id::text,trip_id::text,class,deck,price_amount,currency FROM trip_fares ORDER BY trip_id,class`,
}

// Numeric bounds for the admin write path. distance_km and
// estimated_duration_minutes are plain integers with CHECK constraints, so an
// out-of-range value used to overflow on the cast and come back as a generic
// "Data is invalid or already in use."
const (
	maxRouteDistanceKm     = 200000
	maxRouteDurationMinute = 20160
	maxFarePriceAmount     = 1000000000000
	// maxTextLength caps every string written through the admin API. No master
	// data field is anywhere near this long, and an unbounded value would be
	// stored as-is.
	maxTextLength = 200
)

var validTripStatuses = map[string]bool{"scheduled": true, "boarding": true, "departed": true, "arrived": true, "cancelled": true}

var validBookingStatuses = map[string]bool{
	"draft": true, "pending_payment": true, "paid": true, "ticketed": true, "expired": true, "cancelled": true,
}

func (s *Service) AdminList(ctx context.Context, resource string) ([]map[string]any, error) {
	query, ok := adminListQueries[resource]
	if !ok {
		return nil, problem(404, "ADMIN_RESOURCE_NOT_FOUND", "Admin resource not found.")
	}
	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	out := []map[string]any{}
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			return nil, wrapInternal(err)
		}
		item := map[string]any{}
		for i, value := range values {
			if raw, ok := value.([]byte); ok && json.Valid(raw) {
				var parsed any
				_ = json.Unmarshal(raw, &parsed)
				value = parsed
			}
			item[string(fields[i].Name)] = value
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// text extracts a required, trimmed string field. It used to accept anything
// fmt.Sprint could render, so a JSON number 42 became the name "42" and a
// non-UUID "1234" was carried into a $n::uuid cast and failed as a 500.
func text(body map[string]any, key string) (string, error) {
	raw, ok := body[key]
	if !ok || raw == nil {
		return "", fmt.Errorf("%s is required", key)
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	if len(value) > maxTextLength {
		return "", fmt.Errorf("%s must be at most %d characters", key, maxTextLength)
	}
	return value, nil
}

// optionalText reads a string field that may be absent, falling back to a
// default. A present-but-non-string value is an error rather than a silent
// fallback.
func optionalText(body map[string]any, key, fallback string) (string, error) {
	raw, ok := body[key]
	if !ok || raw == nil {
		return fallback, nil
	}
	value, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	if len(value) > maxTextLength {
		return "", fmt.Errorf("%s must be at most %d characters", key, maxTextLength)
	}
	return value, nil
}

// uuidText is text() plus a UUID check, for every foreign-key column.
func uuidText(body map[string]any, key string) (string, error) {
	value, err := text(body, key)
	if err != nil {
		return "", err
	}
	if !security.ValidUUID(value) {
		return "", fmt.Errorf("%s must be a UUID", key)
	}
	return value, nil
}

// number extracts a whole number within [min, max]. The previous version
// truncated a float silently and applied no range check at all, so
// distance_km: 1e18 overflowed the integer column.
func number(body map[string]any, key string, min, max float64) (int64, error) {
	value, ok := body[key].(float64)
	if !ok {
		return 0, fmt.Errorf("%s must be a number", key)
	}
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, fmt.Errorf("%s must be a finite number", key)
	}
	if value != math.Trunc(value) {
		return 0, fmt.Errorf("%s must be a whole number", key)
	}
	if value < min || value > max {
		return 0, fmt.Errorf("%s must be between %g and %g", key, min, max)
	}
	return int64(value), nil
}

// adminWriteError separates a rejected payload from a broken database. A unique
// or foreign-key violation is a 422 the operator can act on; a connection
// failure is an internal error and must not be reported as bad data.
func adminWriteError(err error, field, detail string) error {
	if err == nil {
		return nil
	}
	if isConstraintViolation(err) {
		return invalid(map[string]string{field: detail})
	}
	return wrapInternal(err)
}

func (s *Service) audit(ctx context.Context, adminID, action, resource, id string) {
	if _, err := s.pool.Exec(ctx, `INSERT INTO admin_audit_logs(admin_user_id,action,entity_type,entity_id) VALUES($1,$2,$3,$4)`, adminID, action, resource, id); err != nil {
		// The mutation already committed; the audit row is what makes it
		// attributable, so a silent loss here is a real gap, not a nuisance.
		log.Printf("warning: admin audit insert failed admin=%s action=%s resource=%s id=%s: %v", adminID, action, resource, id, err)
	}
}

func (s *Service) AdminCreate(ctx context.Context, resource, adminID string, body map[string]any) (map[string]any, error) {
	id := uuid.NewString()
	var err error
	switch resource {
	case "cities":
		name, e := text(body, "name")
		if e != nil {
			return nil, invalid(map[string]string{"name": e.Error()})
		}
		slug, e := text(body, "slug")
		if e != nil {
			return nil, invalid(map[string]string{"slug": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO cities(id,name,slug) VALUES($1,$2,$3)`, id, name, slug)
	case "terminals":
		city, e := uuidText(body, "city_id")
		if e != nil {
			return nil, invalid(map[string]string{"city_id": e.Error()})
		}
		name, e := text(body, "name")
		if e != nil {
			return nil, invalid(map[string]string{"name": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO terminals(id,city_id,name) VALUES($1,$2,$3)`, id, city, name)
	case "routes":
		origin, e := uuidText(body, "origin_terminal_id")
		if e != nil {
			return nil, invalid(map[string]string{"origin_terminal_id": e.Error()})
		}
		destination, e := uuidText(body, "destination_terminal_id")
		if e != nil {
			return nil, invalid(map[string]string{"destination_terminal_id": e.Error()})
		}
		distance, e := number(body, "distance_km", 1, maxRouteDistanceKm)
		if e != nil {
			return nil, invalid(map[string]string{"distance_km": e.Error()})
		}
		duration, e := number(body, "estimated_duration_minutes", 1, maxRouteDurationMinute)
		if e != nil {
			return nil, invalid(map[string]string{"estimated_duration_minutes": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO routes(id,origin_terminal_id,destination_terminal_id,distance_km,estimated_duration_minutes) VALUES($1,$2,$3,$4,$5)`, id, origin, destination, distance, duration)
	case "buses":
		code, e := text(body, "code")
		if e != nil {
			return nil, invalid(map[string]string{"code": e.Error()})
		}
		name, e := text(body, "name")
		if e != nil {
			return nil, invalid(map[string]string{"name": e.Error()})
		}
		amenities, _ := json.Marshal(body["amenities"])
		if string(amenities) == "null" {
			amenities = []byte("[]")
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO buses(id,code,name,amenities) VALUES($1,$2,$3,$4)`, id, code, name, amenities)
	case "trips":
		route, e := uuidText(body, "route_id")
		if e != nil {
			return nil, invalid(map[string]string{"route_id": e.Error()})
		}
		bus, e := uuidText(body, "bus_id")
		if e != nil {
			return nil, invalid(map[string]string{"bus_id": e.Error()})
		}
		departure, e := text(body, "departure_at")
		if e != nil {
			return nil, invalid(map[string]string{"departure_at": e.Error()})
		}
		arrival, e := text(body, "arrival_at")
		if e != nil {
			return nil, invalid(map[string]string{"arrival_at": e.Error()})
		}
		status, e := optionalText(body, "status", "scheduled")
		if e != nil {
			return nil, invalid(map[string]string{"status": e.Error()})
		}
		if !validTripStatuses[status] {
			return nil, invalid(map[string]string{"status": "Invalid trip status."})
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO trips(id,route_id,bus_id,departure_at,arrival_at,status) VALUES($1,$2,$3,$4,$5,$6)`, id, route, bus, departure, arrival, status)
		if err == nil {
			_, err = s.pool.Exec(ctx, `INSERT INTO trip_seats(trip_id,bus_seat_id) SELECT $1,id FROM bus_seats WHERE bus_id=$2`, id, bus)
		}
	case "fares":
		trip, e := uuidText(body, "trip_id")
		if e != nil {
			return nil, invalid(map[string]string{"trip_id": e.Error()})
		}
		class, e := text(body, "class")
		if e != nil {
			return nil, invalid(map[string]string{"class": e.Error()})
		}
		deck, e := text(body, "deck")
		if e != nil {
			return nil, invalid(map[string]string{"deck": e.Error()})
		}
		price, e := number(body, "price_amount", 0, maxFarePriceAmount)
		if e != nil {
			return nil, invalid(map[string]string{"price_amount": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `INSERT INTO trip_fares(id,trip_id,class,deck,price_amount) VALUES($1,$2,$3,$4,$5)`, id, trip, class, deck, price)
	default:
		return nil, problem(404, "ADMIN_RESOURCE_NOT_FOUND", "Admin resource not found.")
	}
	if err != nil {
		return nil, adminWriteError(err, "resource", "Data is invalid or already in use.")
	}
	s.audit(ctx, adminID, "create", resource, id)
	return map[string]any{"id": id}, nil
}

func optionalActive(body map[string]any) (any, error) {
	raw, ok := body["active"]
	if !ok || raw == nil {
		return nil, nil
	}
	value, ok := raw.(bool)
	if !ok {
		return nil, fmt.Errorf("active must be a boolean")
	}
	return value, nil
}

func (s *Service) AdminUpdate(ctx context.Context, resource, id, adminID string, body map[string]any) error {
	if err := requireUUID("id", id); err != nil {
		return err
	}
	active, activeErr := optionalActive(body)
	if activeErr != nil {
		return invalid(map[string]string{"active": activeErr.Error()})
	}
	var err error
	switch resource {
	case "cities":
		name, e := text(body, "name")
		if e != nil {
			return invalid(map[string]string{"name": e.Error()})
		}
		slug, e := text(body, "slug")
		if e != nil {
			return invalid(map[string]string{"slug": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `UPDATE cities SET name=$1,slug=$2,active=COALESCE($3,active),updated_at=now() WHERE id=$4`, name, slug, active, id)
	case "terminals":
		city, e := uuidText(body, "city_id")
		if e != nil {
			return invalid(map[string]string{"city_id": e.Error()})
		}
		name, e := text(body, "name")
		if e != nil {
			return invalid(map[string]string{"name": e.Error()})
		}
		_, err = s.pool.Exec(ctx, `UPDATE terminals SET city_id=$1,name=$2,active=COALESCE($3,active),updated_at=now() WHERE id=$4`, city, name, active, id)
	case "routes":
		fields := map[string]string{}
		origin, e := uuidText(body, "origin_terminal_id")
		if e != nil {
			fields["origin_terminal_id"] = e.Error()
		}
		destination, e := uuidText(body, "destination_terminal_id")
		if e != nil {
			fields["destination_terminal_id"] = e.Error()
		}
		distance, e := number(body, "distance_km", 1, maxRouteDistanceKm)
		if e != nil {
			fields["distance_km"] = e.Error()
		}
		duration, e := number(body, "estimated_duration_minutes", 1, maxRouteDurationMinute)
		if e != nil {
			fields["estimated_duration_minutes"] = e.Error()
		}
		if len(fields) > 0 {
			return invalid(fields)
		}
		_, err = s.pool.Exec(ctx, `UPDATE routes SET origin_terminal_id=$1,destination_terminal_id=$2,distance_km=$3,estimated_duration_minutes=$4,active=COALESCE($5,active),updated_at=now() WHERE id=$6`, origin, destination, distance, duration, active, id)
	case "buses":
		fields := map[string]string{}
		code, e := text(body, "code")
		if e != nil {
			fields["code"] = e.Error()
		}
		name, e := text(body, "name")
		if e != nil {
			fields["name"] = e.Error()
		}
		if len(fields) > 0 {
			return invalid(fields)
		}
		if _, ok := body["amenities"]; ok {
			amenities, _ := json.Marshal(body["amenities"])
			if string(amenities) == "null" {
				amenities = []byte("[]")
			}
			_, err = s.pool.Exec(ctx, `UPDATE buses SET code=$1,name=$2,amenities=$3,active=COALESCE($4,active),updated_at=now() WHERE id=$5`, code, name, amenities, active, id)
		} else {
			_, err = s.pool.Exec(ctx, `UPDATE buses SET code=$1,name=$2,active=COALESCE($3,active),updated_at=now() WHERE id=$4`, code, name, active, id)
		}
	case "trips":
		fields := map[string]string{}
		route, e := uuidText(body, "route_id")
		if e != nil {
			fields["route_id"] = e.Error()
		}
		bus, e := uuidText(body, "bus_id")
		if e != nil {
			fields["bus_id"] = e.Error()
		}
		departure, e := text(body, "departure_at")
		if e != nil {
			fields["departure_at"] = e.Error()
		}
		arrival, e := text(body, "arrival_at")
		if e != nil {
			fields["arrival_at"] = e.Error()
		}
		status, hasStatus := body["status"].(string)
		if raw, present := body["status"]; present && !hasStatus && raw != nil {
			fields["status"] = "Status must be a string."
		} else if hasStatus {
			if !validTripStatuses[status] {
				fields["status"] = "Invalid trip status."
			}
		}
		if len(fields) > 0 {
			return invalid(fields)
		}
		if hasStatus {
			_, err = s.pool.Exec(ctx, `UPDATE trips SET route_id=$1,bus_id=$2,departure_at=$3,arrival_at=$4,status=$5,updated_at=now() WHERE id=$6`, route, bus, departure, arrival, status, id)
		} else {
			_, err = s.pool.Exec(ctx, `UPDATE trips SET route_id=$1,bus_id=$2,departure_at=$3,arrival_at=$4,updated_at=now() WHERE id=$5`, route, bus, departure, arrival, id)
		}
	case "fares":
		// trip_fares has no active column (001_init.up.sql). Accepting and
		// discarding it let an operator believe a fare had been deactivated.
		if _, present := body["active"]; present {
			return invalid(map[string]string{"active": "Fares have no active flag; delete the fare instead."})
		}
		fields := map[string]string{}
		class, e := text(body, "class")
		if e != nil {
			fields["class"] = e.Error()
		}
		deck, e := text(body, "deck")
		if e != nil {
			fields["deck"] = e.Error()
		}
		price, e := number(body, "price_amount", 0, maxFarePriceAmount)
		if e != nil {
			fields["price_amount"] = e.Error()
		}
		if len(fields) > 0 {
			return invalid(fields)
		}
		_, err = s.pool.Exec(ctx, `UPDATE trip_fares SET class=$1,deck=$2,price_amount=$3 WHERE id=$4`, class, deck, price, id)
	default:
		return problem(404, "ADMIN_RESOURCE_NOT_FOUND", "Admin resource not found.")
	}
	if err != nil {
		return adminWriteError(err, "resource", "Update data is invalid or already in use.")
	}
	s.audit(ctx, adminID, "update", resource, id)
	return nil
}

func (s *Service) AdminUpdateTripStatus(ctx context.Context, id, adminID, status string) error {
	if err := requireUUID("id", id); err != nil {
		return err
	}
	if !validTripStatuses[status] {
		return invalid(map[string]string{"status": "Invalid trip status."})
	}
	tag, err := s.pool.Exec(ctx, `UPDATE trips SET status=$1,updated_at=now() WHERE id=$2`, status, id)
	if err != nil {
		return wrapInternal(err)
	}
	if tag.RowsAffected() == 0 {
		return problem(404, "TRIP_NOT_FOUND", "Trip not found.")
	}
	s.audit(ctx, adminID, "update_status", "trips", id)
	return nil
}

func (s *Service) AdminDelete(ctx context.Context, resource, id, adminID string) error {
	if err := requireUUID("id", id); err != nil {
		return err
	}
	var query string
	switch resource {
	case "cities":
		query = `UPDATE cities SET active=false,updated_at=now() WHERE id=$1`
	case "terminals":
		query = `UPDATE terminals SET active=false,updated_at=now() WHERE id=$1`
	case "routes":
		query = `UPDATE routes SET active=false,updated_at=now() WHERE id=$1`
	case "buses":
		query = `UPDATE buses SET active=false,updated_at=now() WHERE id=$1`
	case "trips":
		query = `UPDATE trips SET status='cancelled',updated_at=now() WHERE id=$1`
	case "fares":
		query = `DELETE FROM trip_fares WHERE id=$1`
	default:
		return problem(404, "ADMIN_RESOURCE_NOT_FOUND", "Admin resource not found.")
	}
	if _, err := s.pool.Exec(ctx, query, id); err != nil {
		return adminWriteError(err, "resource", "Resource is still in use and cannot be deleted.")
	}
	s.audit(ctx, adminID, "delete", resource, id)
	return nil
}

type AdminSeatInput struct {
	Code   string `json:"code"`
	Deck   string `json:"deck"`
	Class  string `json:"class"`
	Row    int    `json:"row"`
	Column int    `json:"column"`
}

func (s *Service) AdminReplaceBusSeats(ctx context.Context, busID, adminID string, seats []AdminSeatInput) error {
	if err := requireUUID("id", busID); err != nil {
		return err
	}
	if len(seats) == 0 {
		return invalid(map[string]string{"seats": "Seat layout cannot be empty."})
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return wrapInternal(err)
	}
	defer tx.Rollback(ctx)
	var tripCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM trips WHERE bus_id=$1 AND departure_at>now()`, busID).Scan(&tripCount); err != nil {
		return wrapInternal(err)
	}
	if tripCount > 0 {
		return problem(409, "BUS_LAYOUT_IN_USE", "Layout cannot be changed because the bus has upcoming trips.")
	}
	if _, err = tx.Exec(ctx, `DELETE FROM bus_seats WHERE bus_id=$1`, busID); err != nil {
		return wrapInternal(err)
	}
	seen := map[string]bool{}
	for _, seat := range seats {
		if seen[seat.Code] || seat.Code == "" {
			return invalid(map[string]string{"seats": "Seat codes must be unique."})
		}
		seen[seat.Code] = true
		if seat.Deck != "sleeper" && seat.Deck != "executive" {
			return invalid(map[string]string{"seats": "Invalid deck."})
		}
		if _, err = tx.Exec(ctx, `INSERT INTO bus_seats(bus_id,code,deck,class,position_row,position_col) VALUES($1,$2,$3,$4,$5,$6)`, busID, seat.Code, seat.Deck, seat.Class, seat.Row, seat.Column); err != nil {
			return adminWriteError(err, "seats", "Invalid seat layout.")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapInternal(err)
	}
	s.audit(ctx, adminID, "replace_layout", "buses", busID)
	return nil
}

func (s *Service) AdminBookings(ctx context.Context, status string) ([]map[string]any, error) {
	args := []any{}
	where := ""
	if status != "" {
		// An unknown status used to return an empty list, indistinguishable from
		// "no bookings in that state".
		if !validBookingStatuses[status] {
			return nil, invalid(map[string]string{"status": "Unknown booking status filter."})
		}
		where = " WHERE b.status=$1"
		args = append(args, status)
	}
	rows, err := s.pool.Query(ctx, `SELECT b.id::text,b.code,b.status,b.contact_name,b.subtotal_amount,b.tax_amount,b.total_amount,b.expires_at,b.created_at,t.departure_at,oc.name,dc.name FROM bookings b JOIN trips t ON t.id=b.trip_id JOIN routes r ON r.id=t.route_id JOIN terminals ot ON ot.id=r.origin_terminal_id JOIN terminals dt ON dt.id=r.destination_terminal_id JOIN cities oc ON oc.id=ot.city_id JOIN cities dc ON dc.id=dt.city_id`+where+` ORDER BY b.created_at DESC LIMIT 500`, args...)
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, code, state, name, origin, destination string
		var sub, tax, total int64
		var exp, created, departure time.Time
		// A failed scan used to be served to the client as a row of zeroes with
		// HTTP 200.
		if err = rows.Scan(&id, &code, &state, &name, &sub, &tax, &total, &exp, &created, &departure, &origin, &destination); err != nil {
			return nil, wrapInternal(err)
		}
		out = append(out, map[string]any{"id": id, "code": code, "status": state, "contact_name": name, "subtotal": sub, "tax": tax, "total": total, "expires_at": exp, "created_at": created, "departure_at": departure, "origin": origin, "destination": destination})
	}
	return out, rows.Err()
}

// decryptedOrMarker decrypts a PII blob for the admin manifest. An absent value
// is genuinely absent and renders as "". A value that fails to decrypt is a
// problem with the encryption key, and returning "" for it looked exactly like
// a booking with no contact details, so the failure is logged and marked
// instead of silently blank.
func (s *Service) decryptedOrMarker(field string, bookingID string, ciphertext []byte) string {
	if len(ciphertext) == 0 {
		return ""
	}
	value, err := s.vault.Decrypt(ciphertext)
	if err != nil {
		log.Printf("warning: decrypt failed booking=%s field=%s: %v", bookingID, field, err)
		return "[unavailable: decryption failed]"
	}
	return value
}

func (s *Service) AdminBookingDetail(ctx context.Context, id string) (map[string]any, error) {
	if err := requireUUID("id", id); err != nil {
		return nil, err
	}
	var code, status, contactName, tripID string
	var phoneCipher, emailCipher []byte
	var subtotal, tax, total int64
	var expires, created time.Time
	err := s.pool.QueryRow(ctx, `SELECT code,status,contact_name,contact_phone_ciphertext,contact_email_ciphertext,trip_id::text,subtotal_amount,tax_amount,total_amount,expires_at,created_at FROM bookings WHERE id=$1::uuid`, id).Scan(&code, &status, &contactName, &phoneCipher, &emailCipher, &tripID, &subtotal, &tax, &total, &expires, &created)
	if err != nil {
		return nil, lookupErr(err, "BOOKING_NOT_FOUND", "Booking not found.")
	}
	phone := s.decryptedOrMarker("contact_phone", id, phoneCipher)
	email := s.decryptedOrMarker("contact_email", id, emailCipher)
	rows, err := s.pool.Query(ctx, `SELECT i.seat_code,COALESCE(p.full_name,''),COALESCE(p.identity_type,''),COALESCE(p.identity_ciphertext,''::bytea),p.date_of_birth,COALESCE(p.gender,'') FROM booking_items i LEFT JOIN passengers p ON p.booking_item_id=i.id WHERE i.booking_id=$1::uuid ORDER BY i.seat_code`, id)
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	passengers := []map[string]any{}
	for rows.Next() {
		var seat, fullName, identityType, gender string
		var cipher []byte
		var dob *time.Time
		if err = rows.Scan(&seat, &fullName, &identityType, &cipher, &dob, &gender); err != nil {
			return nil, wrapInternal(err)
		}
		passengers = append(passengers, map[string]any{"seat": seat, "full_name": fullName, "identity_type": identityType, "identity_number": s.decryptedOrMarker("identity_number", id, cipher), "date_of_birth": dob, "gender": gender})
	}
	if err = rows.Err(); err != nil {
		return nil, wrapInternal(err)
	}
	return map[string]any{"id": id, "code": code, "status": status, "trip_id": tripID, "contact": map[string]any{"name": contactName, "phone": phone, "email": email}, "passengers": passengers, "subtotal": subtotal, "tax": tax, "total": total, "expires_at": expires, "created_at": created}, nil
}

func (s *Service) AdminCancelBooking(ctx context.Context, id, adminID string) error {
	if err := requireUUID("id", id); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return wrapInternal(err)
	}
	defer tx.Rollback(ctx)
	var tripID, status string
	if err = tx.QueryRow(ctx, `SELECT trip_id::text,status FROM bookings WHERE id=$1 FOR UPDATE`, id).Scan(&tripID, &status); err != nil {
		return lookupErr(err, "BOOKING_NOT_FOUND", "Booking not found.")
	}
	if status == "ticketed" || status == "paid" {
		return problem(409, "BOOKING_ALREADY_PAID", "Paid bookings require a refund process.")
	}
	if !bookingTransitionAllowed(status, "cancelled") {
		return problem(409, "BOOKING_STATE_INVALID", "Booking cannot be cancelled.")
	}
	// Checked, unlike the previous version: a swallowed error here committed the
	// cancellation while leaving the seats stuck in 'reserved' with no booking
	// left able to release them.
	if _, err = tx.Exec(ctx, `UPDATE bookings SET status='cancelled',updated_at=now() WHERE id=$1`, id); err != nil {
		return wrapInternal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE payments SET status='failed',updated_at=now() WHERE booking_id=$1 AND status='pending'`, id); err != nil {
		return wrapInternal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE trip_seats SET status='available',booking_id=NULL,reserved_until=NULL WHERE trip_id=$1 AND booking_id=$2 AND status='reserved'`, tripID, id); err != nil {
		return wrapInternal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapInternal(err)
	}
	s.audit(ctx, adminID, "cancel", "booking", id)
	return nil
}

func (s *Service) AdminDashboardStats(ctx context.Context) (map[string]any, error) {
	// Counters whose query failed are named in unavailable_metrics instead of
	// being rendered as 0. A dropped connection used to produce HTTP 200 with
	// every KPI reading zero, which is indistinguishable from an empty system.
	unavailable := []string{}
	count := func(label, query string) int64 {
		var value int64
		if err := s.pool.QueryRow(ctx, query).Scan(&value); err != nil {
			log.Printf("warning: dashboard counter %s failed: %v", label, err)
			unavailable = append(unavailable, label)
			return 0
		}
		return value
	}
	totalRevenue := count("total_revenue", `SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'paid'`)
	totalBookings := count("total_bookings", `SELECT count(*) FROM bookings`)
	paidBookings := count("paid_bookings", `SELECT count(*) FROM bookings WHERE status IN ('paid', 'ticketed')`)
	pendingBookings := count("pending_bookings", `SELECT count(*) FROM bookings WHERE status = 'pending_payment'`)
	activeTrips := count("active_trips", `SELECT count(*) FROM trips WHERE status IN ('scheduled', 'boarding')`)
	totalTickets := count("total_tickets", `SELECT count(*) FROM tickets`)
	boardedTickets := count("boarded_tickets", `SELECT count(*) FROM tickets WHERE status = 'boarded'`)

	// Occupancy is scoped to departures within the next 7 days: a fleet-wide
	// 30-day horizon dilutes the ratio into a meaningless single-digit number
	// and is not what an operations dashboard reads as "how full are we".
	const seatWindow = `FROM trip_seats ts JOIN trips t ON t.id = ts.trip_id
		WHERE t.status IN ('scheduled', 'boarding') AND t.departure_at >= now() AND t.departure_at < now() + interval '7 days'`
	totalSeats := count("total_seats", `SELECT count(*) `+seatWindow)
	occupiedSeats := count("occupied_seats", `SELECT count(*) `+seatWindow+` AND ts.status IN ('reserved', 'booked')`)

	var occupancyRate float64
	if totalSeats > 0 {
		occupancyRate = float64(occupiedSeats) / float64(totalSeats) * 100
	}

	// Revenue by day (last 7 days)
	var chartData []map[string]any
	revenueRows, err := s.pool.Query(ctx, `
		SELECT (created_at AT TIME ZONE 'Asia/Jakarta')::date AS day,
		       COALESCE(SUM(amount), 0) AS revenue,
		       COUNT(*) AS count
		FROM payments
		WHERE status = 'paid' AND created_at >= now() - interval '7 days'
		GROUP BY (created_at AT TIME ZONE 'Asia/Jakarta')::date
		ORDER BY day ASC
	`)
	if err != nil {
		log.Printf("warning: dashboard revenue series failed: %v", err)
		unavailable = append(unavailable, "chart_data")
	} else {
		defer revenueRows.Close()
		for revenueRows.Next() {
			var day time.Time
			var rev, cnt int64
			if err = revenueRows.Scan(&day, &rev, &cnt); err != nil {
				log.Printf("warning: dashboard revenue row failed: %v", err)
				unavailable = append(unavailable, "chart_data")
				break
			}
			chartData = append(chartData, map[string]any{
				"date":     day.Format("2006-01-02"),
				"revenue":  rev,
				"bookings": cnt,
			})
		}
		if err = revenueRows.Err(); err != nil {
			log.Printf("warning: dashboard revenue series iteration failed: %v", err)
			unavailable = append(unavailable, "chart_data")
		}
	}

	// Recent 5 bookings
	recent, err := s.AdminBookings(ctx, "")
	if err != nil {
		log.Printf("warning: dashboard recent bookings failed: %v", err)
		unavailable = append(unavailable, "recent_bookings")
	} else if len(recent) > 5 {
		recent = recent[:5]
	}

	return map[string]any{
		"total_revenue":       totalRevenue,
		"total_bookings":      totalBookings,
		"paid_bookings":       paidBookings,
		"pending_bookings":    pendingBookings,
		"active_trips":        activeTrips,
		"total_tickets":       totalTickets,
		"boarded_tickets":     boardedTickets,
		"occupancy_rate":      occupancyRate,
		"chart_data":          chartData,
		"recent_bookings":     recent,
		"unavailable_metrics": unavailable,
	}, nil
}

func (s *Service) AdminListAuditLogs(ctx context.Context, limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT l.id, COALESCE(u.name, 'System'), COALESCE(u.email, 'system@elysian.local'), l.action, l.entity_type, l.entity_id, l.metadata, l.created_at
		FROM admin_audit_logs l
		LEFT JOIN admin_users u ON u.id = l.admin_user_id
		ORDER BY l.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, wrapInternal(err)
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var name, email, action, entityType, entityID string
		var metadata []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &email, &action, &entityType, &entityID, &metadata, &createdAt); err != nil {
			return nil, wrapInternal(err)
		}
		var parsedMetadata any
		if len(metadata) > 0 {
			_ = json.Unmarshal(metadata, &parsedMetadata)
		}
		out = append(out, map[string]any{
			"id":          id,
			"admin_name":  name,
			"admin_email": email,
			"action":      action,
			"entity_type": entityType,
			"entity_id":   entityID,
			"metadata":    parsedMetadata,
			"created_at":  createdAt,
		})
	}
	return out, rows.Err()
}
