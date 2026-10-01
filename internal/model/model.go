package model

import "time"

type City struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type TripOffer struct {
	OfferID           string    `json:"offer_id"`
	TripID            string    `json:"trip_id"`
	OriginCityID      string    `json:"origin_city_id"`
	Origin            string    `json:"origin"`
	DestinationCityID string    `json:"destination_city_id"`
	Destination       string    `json:"destination"`
	DepartureAt       time.Time `json:"departure_at"`
	ArrivalAt         time.Time `json:"arrival_at"`
	DurationMinutes   int       `json:"duration_minutes"`
	Class             string    `json:"class"`
	Deck              string    `json:"deck"`
	Price             int64     `json:"price"`
	SeatsLeft         int       `json:"seats_left"`
	BusName           string    `json:"bus_name"`
	Amenities         []string  `json:"amenities"`
	DepartureStation  string    `json:"departure_station"`
	ArrivalStation    string    `json:"arrival_station"`
}

type Seat struct {
	ID       string `json:"id"`
	Code     string `json:"code"`
	Deck     string `json:"deck"`
	Class    string `json:"class"`
	Row      int    `json:"row"`
	Column   int    `json:"column"`
	Status   string `json:"status"`
	HeldByMe bool   `json:"held_by_me"`
}

type SeatHold struct {
	ID        string    `json:"id"`
	OfferID   string    `json:"offer_id"`
	SessionID string    `json:"session_id"`
	SeatIDs   []string  `json:"seat_ids"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Contact struct {
	Name  string `json:"name"`
	Phone string `json:"phone"`
	Email string `json:"email,omitempty"`
}
type PassengerInput struct {
	SeatID         string `json:"seat_id"`
	FullName       string `json:"full_name"`
	IdentityType   string `json:"identity_type"`
	IdentityNumber string `json:"identity_number"`
	DateOfBirth    string `json:"date_of_birth"`
	Gender         string `json:"gender"`
}

type Booking struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Status    string    `json:"status"`
	TripID    string    `json:"trip_id"`
	OfferID   string    `json:"offer_id"`
	SeatIDs   []string  `json:"seat_ids"`
	SeatCodes []string  `json:"seat_codes"`
	Subtotal  int64     `json:"subtotal"`
	Tax       int64     `json:"tax"`
	Total     int64     `json:"total"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Payment struct {
	ID          string         `json:"id"`
	BookingID   string         `json:"booking_id"`
	Provider    string         `json:"provider"`
	Reference   string         `json:"reference"`
	Method      string         `json:"method"`
	Amount      int64          `json:"amount"`
	Status      string         `json:"status"`
	Instruction map[string]any `json:"instruction"`
	ExpiresAt   time.Time      `json:"expires_at"`
	CanSimulate bool           `json:"can_simulate"`
}

type Ticket struct {
	ID               string    `json:"id"`
	TicketID         string    `json:"ticket_id"`
	PassengerName    string    `json:"passenger_name"`
	Seat             string    `json:"seat"`
	TripName         string    `json:"trip_name"`
	ClassType        string    `json:"class_type"`
	Origin           string    `json:"origin"`
	Destination      string    `json:"destination"`
	DepartureAt      time.Time `json:"departure_at"`
	DepartureStation string    `json:"departure_station"`
	ArrivalStation   string    `json:"arrival_station"`
	Status           string    `json:"status"`
	QRURL            string    `json:"qr_url"`
}
