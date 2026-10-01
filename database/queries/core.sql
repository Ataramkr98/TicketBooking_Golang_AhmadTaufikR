-- name: Ping :one
SELECT 1::int;

-- name: ListCities :many
SELECT id, name, slug
FROM cities
WHERE active = true
  AND (sqlc.arg(query)::text = '' OR name ILIKE '%' || sqlc.arg(query)::text || '%')
ORDER BY name;

-- name: ListDestinationCities :many
SELECT DISTINCT c.id, c.name, c.slug
FROM routes r
JOIN terminals ot ON ot.id = r.origin_terminal_id
JOIN terminals dt ON dt.id = r.destination_terminal_id
JOIN cities c ON c.id = dt.city_id
WHERE r.active = true AND ot.city_id = sqlc.arg(origin_city_id)::uuid
ORDER BY c.name;

-- name: GetTripOffer :one
SELECT f.id AS offer_id, f.trip_id, f.class, f.deck, f.price_amount,
       t.departure_at, t.arrival_at, t.status,
       b.id AS bus_id, b.name AS bus_name, b.amenities,
       oc.id AS origin_city_id, oc.name AS origin_city,
       dc.id AS destination_city_id, dc.name AS destination_city,
       ot.name AS departure_station, dt.name AS arrival_station
FROM trip_fares f
JOIN trips t ON t.id = f.trip_id
JOIN buses b ON b.id = t.bus_id
JOIN routes r ON r.id = t.route_id
JOIN terminals ot ON ot.id = r.origin_terminal_id
JOIN terminals dt ON dt.id = r.destination_terminal_id
JOIN cities oc ON oc.id = ot.city_id
JOIN cities dc ON dc.id = dt.city_id
WHERE f.id = sqlc.arg(offer_id)::uuid AND t.status = 'scheduled';

-- name: GetTripSeats :many
SELECT bs.id, bs.code, bs.deck, bs.class, bs.position_row, bs.position_col,
       ts.status, ts.reserved_until
FROM trip_fares f
JOIN trips t ON t.id = f.trip_id
JOIN bus_seats bs ON bs.bus_id = t.bus_id
JOIN trip_seats ts ON ts.trip_id = t.id AND ts.bus_seat_id = bs.id
WHERE f.id = sqlc.arg(offer_id)::uuid
ORDER BY bs.deck, bs.position_row, bs.position_col;

