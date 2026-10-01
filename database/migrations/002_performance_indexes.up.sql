CREATE INDEX IF NOT EXISTS bookings_code_idx ON bookings(code);
CREATE INDEX IF NOT EXISTS bookings_created_at_idx ON bookings(created_at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_logs_created_at_idx ON admin_audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS tickets_issued_at_idx ON tickets(issued_at DESC);
CREATE INDEX IF NOT EXISTS trips_status_departure_idx ON trips(status, departure_at);
