-- Exact mirror of 003_query_indexes.up.sql.

DROP INDEX IF EXISTS idempotency_keys_created_at_idx;
DROP INDEX IF EXISTS payments_status_idx;
DROP INDEX IF EXISTS tickets_status_idx;
DROP INDEX IF EXISTS tickets_booking_id_idx;
DROP INDEX IF EXISTS trip_seats_booking_id_idx;
DROP INDEX IF EXISTS trips_bus_id_idx;

CREATE INDEX IF NOT EXISTS tickets_issued_at_idx ON tickets(issued_at DESC);
CREATE INDEX IF NOT EXISTS bookings_code_idx ON bookings(code);