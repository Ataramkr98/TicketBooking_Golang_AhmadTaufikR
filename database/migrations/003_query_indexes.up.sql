-- Indexes for the queries the application actually issues, plus removal of the
-- two indexes added by 002_performance_indexes that no query can use.

-- trips (bus_id): admin.go AdminList("trips") joins trips to buses.
CREATE INDEX IF NOT EXISTS trips_bus_id_idx ON trips(bus_id);

-- trip_seats (booking_id): the seat-release path in ExpireBookings and
-- AdminCancelBooking filters on booking_id AND status='reserved', and the
-- column had no index at all.
CREATE INDEX IF NOT EXISTS trip_seats_booking_id_idx ON trip_seats(booking_id);

-- tickets (booking_id): ListTickets joins bookings to tickets.
CREATE INDEX IF NOT EXISTS tickets_booking_id_idx ON tickets(booking_id);

-- tickets (status): the boarded-ticket dashboard counter.
CREATE INDEX IF NOT EXISTS tickets_status_idx ON tickets(status);

-- payments (status): the paid-revenue dashboard counter.
CREATE INDEX IF NOT EXISTS payments_status_idx ON payments(status);

-- idempotency_keys (created_at): the table is append-only with a
-- (session_id, key, operation) primary key, so it had no time index and no
-- pruning path.
CREATE INDEX IF NOT EXISTS idempotency_keys_created_at_idx ON idempotency_keys(created_at);

-- Redundant: bookings.code is already UNIQUE (001_init.up.sql), which creates
-- bookings_code_key. A second index on the same column only costs write time.
DROP INDEX IF EXISTS bookings_code_idx;

-- Redundant: no query filters or orders by tickets.issued_at; the column is
-- only written by the seed.
DROP INDEX IF EXISTS tickets_issued_at_idx;