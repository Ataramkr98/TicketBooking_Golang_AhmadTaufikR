CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE cities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    slug text NOT NULL UNIQUE,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE terminals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    city_id uuid NOT NULL REFERENCES cities(id),
    name text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(city_id, name)
);

CREATE TABLE routes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    origin_terminal_id uuid NOT NULL REFERENCES terminals(id),
    destination_terminal_id uuid NOT NULL REFERENCES terminals(id),
    distance_km integer NOT NULL CHECK (distance_km > 0),
    estimated_duration_minutes integer NOT NULL CHECK (estimated_duration_minutes > 0),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (origin_terminal_id <> destination_terminal_id),
    UNIQUE(origin_terminal_id, destination_terminal_id)
);

CREATE TABLE buses (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL UNIQUE,
    name text NOT NULL,
    amenities jsonb NOT NULL DEFAULT '[]'::jsonb,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE bus_seats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    bus_id uuid NOT NULL REFERENCES buses(id) ON DELETE CASCADE,
    code text NOT NULL,
    deck text NOT NULL CHECK (deck IN ('sleeper', 'executive')),
    class text NOT NULL CHECK (class IN ('sleeper', 'executive')),
    position_row integer NOT NULL CHECK (position_row >= 0),
    position_col integer NOT NULL CHECK (position_col >= 0),
    active boolean NOT NULL DEFAULT true,
    UNIQUE(bus_id, code)
);

CREATE TABLE trips (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    route_id uuid NOT NULL REFERENCES routes(id),
    bus_id uuid NOT NULL REFERENCES buses(id),
    departure_at timestamptz NOT NULL,
    arrival_at timestamptz NOT NULL,
    status text NOT NULL DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'boarding', 'departed', 'arrived', 'cancelled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (arrival_at > departure_at)
);
CREATE INDEX trips_departure_idx ON trips(departure_at, status);
CREATE UNIQUE INDEX trips_schedule_unique_idx ON trips(route_id, bus_id, departure_at);

CREATE TABLE trip_fares (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    trip_id uuid NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    class text NOT NULL CHECK (class IN ('sleeper', 'executive')),
    deck text NOT NULL CHECK (deck IN ('sleeper', 'executive')),
    price_amount bigint NOT NULL CHECK (price_amount >= 0),
    currency char(3) NOT NULL DEFAULT 'IDR',
    UNIQUE(trip_id, class)
);

CREATE TABLE bookings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    code text NOT NULL UNIQUE,
    session_id uuid NOT NULL,
    trip_id uuid NOT NULL REFERENCES trips(id),
    offer_id uuid NOT NULL REFERENCES trip_fares(id),
    status text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'pending_payment', 'paid', 'ticketed', 'expired', 'cancelled')),
    contact_name text,
    contact_phone_ciphertext bytea,
    contact_phone_hash bytea,
    contact_email_ciphertext bytea,
    subtotal_amount bigint NOT NULL DEFAULT 0,
    tax_amount bigint NOT NULL DEFAULT 0,
    total_amount bigint NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX bookings_expiry_idx ON bookings(status, expires_at);
CREATE INDEX bookings_phone_hash_idx ON bookings(contact_phone_hash) WHERE contact_phone_hash IS NOT NULL;

CREATE TABLE trip_seats (
    trip_id uuid NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    bus_seat_id uuid NOT NULL REFERENCES bus_seats(id),
    status text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'reserved', 'booked')),
    booking_id uuid REFERENCES bookings(id),
    reserved_until timestamptz,
    PRIMARY KEY(trip_id, bus_seat_id)
);

CREATE TABLE booking_items (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id uuid NOT NULL REFERENCES bookings(id) ON DELETE CASCADE,
    trip_seat_id uuid NOT NULL REFERENCES bus_seats(id),
    seat_code text NOT NULL,
    class text NOT NULL CHECK (class IN ('sleeper', 'executive')),
    unit_price bigint NOT NULL CHECK (unit_price >= 0),
    UNIQUE(booking_id, trip_seat_id),
    UNIQUE(booking_id, seat_code)
);

CREATE TABLE passengers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_item_id uuid NOT NULL UNIQUE REFERENCES booking_items(id) ON DELETE CASCADE,
    full_name text NOT NULL,
    identity_type text NOT NULL CHECK (identity_type IN ('nik', 'passport')),
    identity_ciphertext bytea NOT NULL,
    identity_hash bytea NOT NULL,
    date_of_birth date NOT NULL,
    gender text NOT NULL CHECK (gender IN ('male', 'female')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id uuid NOT NULL UNIQUE REFERENCES bookings(id),
    provider text NOT NULL,
    provider_reference text NOT NULL UNIQUE,
    method text NOT NULL CHECK (method IN ('va', 'qris', 'wallet')),
    amount bigint NOT NULL CHECK (amount >= 0),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'paid', 'failed', 'expired', 'refunded')),
    instruction jsonb NOT NULL DEFAULT '{}'::jsonb,
    paid_at timestamptz,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE payment_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider text NOT NULL,
    event_id text NOT NULL,
    payment_id uuid REFERENCES payments(id),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(provider, event_id)
);

CREATE TABLE tickets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    booking_id uuid NOT NULL REFERENCES bookings(id),
    booking_item_id uuid NOT NULL UNIQUE REFERENCES booking_items(id),
    code text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'boarded', 'cancelled')),
    qr_nonce uuid NOT NULL DEFAULT gen_random_uuid(),
    issued_at timestamptz NOT NULL DEFAULT now(),
    boarded_at timestamptz
);

CREATE TABLE admin_users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role text NOT NULL CHECK (role IN ('admin', 'operator')),
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE admin_audit_logs (
    id bigserial PRIMARY KEY,
    admin_user_id uuid REFERENCES admin_users(id),
    action text NOT NULL,
    entity_type text NOT NULL,
    entity_id text NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE idempotency_keys (
    session_id uuid NOT NULL,
    key text NOT NULL,
    operation text NOT NULL,
    resource_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(session_id, key, operation)
);
