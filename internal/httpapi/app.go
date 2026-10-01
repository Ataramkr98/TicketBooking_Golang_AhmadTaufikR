package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/model"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/elysian-premium-lines/backend/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/google/uuid"
	"github.com/skip2/go-qrcode"
)

const sessionCookie = "elysian_guest"
const csrfCookie = "elysian_csrf"
const ticketCookie = "elysian_ticket_access"

// requestTimeout bounds a single API request. It is layered on top of the
// request context so a client disconnect still cancels the work.
const requestTimeout = 10 * time.Second

type API struct {
	cfg      config.Config
	service  *service.Service
	sessions *security.SessionSigner
	// adminAccount re-reads the administrator behind a bearer token so a
	// deactivated or demoted account loses access immediately. It is a field so
	// the authorization tests can run the real middleware chain without a
	// database.
	adminAccount func(ctx context.Context, id string) (role string, active bool, err error)
}

func New(cfg config.Config, svc *service.Service) *fiber.App {
	api := &API{cfg: cfg, service: svc, sessions: security.NewSessionSigner(cfg.SessionSecret, 30*24*time.Hour), adminAccount: svc.AdminAccount}
	app := fiber.New(fiber.Config{AppName: "Elysian Premium Lines API", ErrorHandler: api.fiberError, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second})
	app.Use(recover.New())
	app.Use(api.requestID)
	app.Use(cors.New(cors.Config{AllowOrigins: strings.Join(cfg.CORSOrigins, ","), AllowMethods: "GET,POST,PUT,PATCH,DELETE,OPTIONS", AllowHeaders: "Content-Type,Authorization,X-CSRF-Token,Idempotency-Key,X-Request-ID", AllowCredentials: true, MaxAge: 600}))
	app.Use(api.rateLimit("global", 180, time.Minute))
	app.Get("/health/live", func(c *fiber.Ctx) error { return c.JSON(fiber.Map{"status": "ok"}) })
	app.Get("/health/ready", func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
		defer cancel()
		if err := svc.Ping(ctx); err != nil {
			return api.fail(c, 503, "NOT_READY", "Database is not ready.", nil)
		}
		return c.JSON(fiber.Map{"status": "ready"})
	})
	api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))
	app.Use(func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead || c.Method() == fiber.MethodOptions {
			return api.fail(c, fiber.StatusNotFound, "NOT_FOUND", "The requested resource was not found.", nil)
		}
		return api.fail(c, fiber.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed for this resource.", nil)
	})
	return app
}

// registerRoutes mounts the whole /api/v1 surface. It is a method rather than an
// inline block so route wiring can be exercised by tests without booting the
// health endpoints.
func (a *API) registerRoutes(v1 fiber.Router) {
	v1.Get("/cities", a.listCities)
	v1.Get("/cities/:originId/destinations", a.listDestinations)
	v1.Get("/trips/search", a.searchTrips)
	v1.Get("/trips/:tripId/seats", a.seatMap)
	v1.Post("/seat-holds", a.csrf, a.createHold)
	v1.Put("/seat-holds/:holdId", a.csrf, a.updateHold)
	v1.Delete("/seat-holds/:holdId", a.csrf, a.deleteHold)
	v1.Post("/bookings", a.csrf, a.createBooking)
	v1.Get("/bookings/:bookingId", a.getBooking)
	v1.Put("/bookings/:bookingId/checkout", a.csrf, a.checkout)
	v1.Get("/payments/:paymentId", a.getPayment)
	v1.Post("/payments/:paymentId/simulate-success", a.csrf, a.simulatePayment)
	v1.Post("/webhooks/payments/:provider", a.paymentWebhook)
	otpLimiter := a.rateLimit("otp", 5, time.Minute)
	v1.Post("/ticket-access/otp", a.csrf, otpLimiter, a.requestOTP)
	v1.Post("/ticket-access/otp/verify", a.csrf, otpLimiter, a.verifyOTP)
	v1.Get("/tickets", a.ticketAccess, a.listTickets)
	v1.Get("/tickets/:ticketId", a.ticketAccess, a.getTicket)
	v1.Get("/tickets/:ticketId/qr.svg", a.ticketAccess, a.ticketQR)
	admin := v1.Group("/admin")
	// Admin login gets a far tighter per-IP budget than the global limiter:
	// it is the only credential-checking endpoint in the system.
	admin.Post("/auth/login", a.rateLimit("admin-login", 10, 5*time.Minute), a.adminLogin)
	secured := admin.Group("", a.adminAuth)
	secured.Get("/dashboard/stats", a.adminDashboardStats)
	// The audit trail names every administrator and every mutation they made, so
	// it is a supervisory record rather than day-to-day station work.
	secured.Get("/audit-logs", a.restrictToAdmin(a.adminAuditLogs)...)
	secured.Get("/bookings", a.adminBookings)
	// Booking detail returns the decrypted passenger manifest, so it requires the
	// admin role. Without this guard an operator token received contact phone,
	// contact email, and every passenger's NIK or passport number.
	secured.Get("/bookings/:id", a.restrictToAdmin(a.adminBookingDetail)...)
	secured.Post("/bookings/:id/cancel", a.csrf, a.adminCancelBooking)
	secured.Post("/tickets/scan", a.csrf, a.adminScanTicket)
	for _, resource := range []string{"cities", "terminals", "routes", "buses", "trips", "fares"} {
		secured.Get("/"+resource, a.adminList(resource))
		secured.Post("/"+resource, a.csrf, a.adminMutate(resource, "create"))
		secured.Put("/"+resource+"/:id", a.csrf, a.adminMutate(resource, "update"))
		secured.Delete("/"+resource+"/:id", a.csrf, a.adminMutate(resource, "delete"))
	}
	secured.Put("/buses/:id/seats", a.csrf, a.adminBusSeats)
}

func (a *API) requestID(c *fiber.Ctx) error {
	id := c.Get("X-Request-ID")
	if id == "" {
		id = uuid.NewString()
	}
	c.Locals("request_id", id)
	c.Set("X-Request-ID", id)
	started := time.Now()
	err := c.Next()
	log.Printf("request_id=%s method=%s path=%s status=%d duration_ms=%d", id, c.Method(), c.Path(), c.Response().StatusCode(), time.Since(started).Milliseconds())
	return err
}
func (a *API) rateLimit(scope string, limit int, window time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		allowed, err := a.service.Allow(c.UserContext(), scope+":"+c.IP(), limit, window)
		if err != nil {
			return a.handle(c, err)
		}
		if !allowed {
			return a.fail(c, 429, "RATE_LIMITED", "Too many requests.", nil)
		}
		return c.Next()
	}
}
func (a *API) timeout(c *fiber.Ctx) error {
	// Built on the request context, not context.Background(): fasthttp cancels
	// the user context when the client goes away, so an abandoned request now
	// releases its Postgres connection instead of holding one for the full
	// timeout.
	ctx, cancel := context.WithTimeout(c.UserContext(), requestTimeout)
	defer cancel()
	c.SetUserContext(ctx)
	return c.Next()
}

// randomValue returns a URL-safe random string. It reports failure rather than
// returning a fixed buffer: a silent crypto/rand failure would hand every client
// the same CSRF token.
func randomValue(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func (a *API) session(c *fiber.Ctx) error {
	id, ok := a.sessions.Verify(c.Cookies(sessionCookie))
	if !ok {
		var signed string
		id, signed = a.sessions.New()
		c.Cookie(&fiber.Cookie{Name: sessionCookie, Value: signed, Path: "/", HTTPOnly: true, Secure: a.cfg.IsProduction(), SameSite: fiber.CookieSameSiteLaxMode, Expires: time.Now().Add(30 * 24 * time.Hour)})
	}
	c.Locals("session_id", id)
	if c.Cookies(csrfCookie) == "" {
		token, err := randomValue(24)
		if err != nil {
			return a.handle(c, fmt.Errorf("csrf token: %w", err))
		}
		c.Cookie(&fiber.Cookie{Name: csrfCookie, Value: token, Path: "/", HTTPOnly: false, Secure: a.cfg.IsProduction(), SameSite: fiber.CookieSameSiteLaxMode, Expires: time.Now().Add(24 * time.Hour)})
	}
	return c.Next()
}
func (a *API) csrf(c *fiber.Ctx) error {
	if c.Get("X-CSRF-Token") == "" || c.Get("X-CSRF-Token") != c.Cookies(csrfCookie) {
		return a.fail(c, 403, "CSRF_INVALID", "Invalid CSRF token.", nil)
	}
	origin := c.Get("Origin")
	if origin != "" {
		allowed := false
		for _, candidate := range a.cfg.CORSOrigins {
			if origin == candidate {
				allowed = true
				break
			}
		}
		if !allowed {
			return a.fail(c, 403, "ORIGIN_FORBIDDEN", "Origin is not allowed.", nil)
		}
	}
	return c.Next()
}

// localString reads a Fiber local that may be unset. fmt.Sprint(nil) yields the
// literal string "<nil>", which is not empty, so it would sail past a
// emptiness check and then fail a $n::uuid cast.
func localString(c *fiber.Ctx, key string) string {
	if value, ok := c.Locals(key).(string); ok {
		return value
	}
	return ""
}
func (a *API) sessionID(c *fiber.Ctx) string { return localString(c, "session_id") }

// uuidParam validates a UUID path parameter at the handler boundary. Without it
// a malformed id becomes a Postgres 22P02 invalid_input_syntax error, which is
// not pgx.ErrNoRows and therefore surfaces as a 500. The returned error is
// routed through handle like every other service problem.
func (a *API) uuidParam(c *fiber.Ctx, name string) (string, error) {
	value := strings.TrimSpace(c.Params(name))
	if !security.ValidUUID(value) {
		return "", &service.Error{
			Status: fiber.StatusBadRequest,
			Code:   "INVALID_IDENTIFIER",
			Detail: "The " + name + " path parameter must be a UUID.",
			Fields: map[string]string{name: "Must be a UUID."},
		}
	}
	return value, nil
}
func (a *API) holdParam(c *fiber.Ctx) (string, error) {
	value := strings.TrimSpace(c.Params("holdId"))
	if !security.ValidHoldID(value) {
		return "", &service.Error{
			Status: fiber.StatusBadRequest,
			Code:   "INVALID_IDENTIFIER",
			Detail: "The holdId path parameter must be <offer_uuid>.<hold_uuid>.",
			Fields: map[string]string{"holdId": "Must be <offer_uuid>.<hold_uuid>."},
		}
	}
	return value, nil
}
func (a *API) ok(c *fiber.Ctx, status int, data any) error {
	return c.Status(status).JSON(fiber.Map{
		"success": true,
		"data":    data,
		"message": "Operation successful",
	})
}
func (a *API) fail(c *fiber.Ctx, status int, code, detail string, fields map[string]string) error {
	body := fiber.Map{
		"success":      false,
		"type":         "https://elysian.local/problems/" + strings.ToLower(code),
		"title":        code,
		"status":       status,
		"code":         code,
		"detail":       detail,
		"message":      detail,
		"field_errors": fields,
		"request_id":   localString(c, "request_id"),
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, "application/problem+json")
	c.Status(status)
	return c.Send(encoded)
}
func (a *API) handle(c *fiber.Ctx, err error) error {
	var problem *service.Error
	if errors.As(err, &problem) {
		return a.fail(c, problem.Status, problem.Code, problem.Detail, problem.Fields)
	}
	log.Printf("request_id=%s error=%v", localString(c, "request_id"), err)
	return a.fail(c, 500, "INTERNAL_ERROR", "An internal error occurred.", nil)
}
func fiberCode(status int) string {
	switch status {
	case fiber.StatusNotFound:
		return "NOT_FOUND"
	case fiber.StatusMethodNotAllowed:
		return "METHOD_NOT_ALLOWED"
	case fiber.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case fiber.StatusTooManyRequests:
		return "RATE_LIMITED"
	case fiber.StatusBadRequest:
		return "BAD_REQUEST"
	case fiber.StatusUnauthorized:
		return "UNAUTHORIZED"
	case fiber.StatusForbidden:
		return "FORBIDDEN"
	default:
		return "HTTP_ERROR"
	}
}
func (a *API) fiberError(c *fiber.Ctx, err error) error {
	var fiberErr *fiber.Error
	if errors.As(err, &fiberErr) {
		return a.fail(c, fiberErr.Code, fiberCode(fiberErr.Code), fiberErr.Message, nil)
	}
	return a.handle(c, err)
}
func decode(c *fiber.Ctx, target any) error {
	if err := json.Unmarshal(c.Body(), target); err != nil {
		return &service.Error{Status: 400, Code: "INVALID_JSON", Detail: "Request body must be valid JSON."}
	}
	return nil
}

// noContent sends a 204 with no body and no content type. Fiber's SendStatus
// would attach `text/plain` to the empty body, which RFC 9110 forbids.
func noContent(c *fiber.Ctx) error {
	c.Status(fiber.StatusNoContent)
	return c.Send(nil)
}

func (a *API) listCities(c *fiber.Ctx) error {
	data, err := a.service.ListCities(c.UserContext(), c.Query("query"))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) listDestinations(c *fiber.Ctx) error {
	originID, err := a.uuidParam(c, "originId")
	if err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.ListDestinations(c.UserContext(), originID)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) searchTrips(c *fiber.Ctx) error {
	passengers, err := queryInt(c, "passengers", 1)
	if err != nil {
		return a.handle(c, err)
	}
	maxPrice, err := queryInt64(c, "max_price", 0)
	if err != nil {
		return a.handle(c, err)
	}
	raw := c.Context().QueryArgs().PeekMulti("departure_period")
	periods := make([]string, len(raw))
	for i, value := range raw {
		periods[i] = string(value)
	}
	input := service.SearchInput{OriginCityID: c.Query("origin_city_id"), DestinationCityID: c.Query("destination_city_id"), Date: c.Query("departure_date"), Class: c.Query("class"), Sort: c.Query("sort"), Periods: periods, Passengers: passengers, MaxPrice: maxPrice}
	data, err := a.service.SearchTrips(c.UserContext(), input)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}

// queryInt parses an integer query parameter. A malformed value is rejected
// rather than silently replaced by the default: max_price=abc used to become 0,
// which means "no price filter" instead of an error.
func queryInt(c *fiber.Ctx, name string, fallback int) (int, error) {
	raw := c.Query(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, &service.Error{Status: 422, Code: "VALIDATION_FAILED", Detail: "Check the data you sent.", Fields: map[string]string{name: "Must be a whole number."}}
	}
	return value, nil
}

func queryInt64(c *fiber.Ctx, name string, fallback int64) (int64, error) {
	raw := c.Query(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, &service.Error{Status: 422, Code: "VALIDATION_FAILED", Detail: "Check the data you sent.", Fields: map[string]string{name: "Must be a whole number."}}
	}
	return value, nil
}

func (a *API) seatMap(c *fiber.Ctx) error {
	tripID, err := a.uuidParam(c, "tripId")
	if err != nil {
		return a.handle(c, err)
	}
	offerID := c.Query("offer_id")
	data, err := a.service.SeatMap(c.UserContext(), tripID, offerID, a.sessionID(c))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, fiber.Map{"trip_id": tripID, "offer_id": offerID, "seats": data})
}

type holdRequest struct {
	OfferID string   `json:"offer_id"`
	SeatIDs []string `json:"seat_ids"`
}

func holdResponse(hold model.SeatHold) fiber.Map {
	return fiber.Map{"id": hold.ID, "offer_id": hold.OfferID, "seat_ids": hold.SeatIDs, "expires_at": hold.ExpiresAt}
}
func (a *API) createHold(c *fiber.Ctx) error {
	var body holdRequest
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	hold, err := a.service.ReplaceHold(c.UserContext(), "", body.OfferID, a.sessionID(c), body.SeatIDs)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 201, holdResponse(hold))
}
func (a *API) updateHold(c *fiber.Ctx) error {
	holdID, err := a.holdParam(c)
	if err != nil {
		return a.handle(c, err)
	}
	var body holdRequest
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	if body.OfferID == "" {
		body.OfferID = strings.SplitN(holdID, ".", 2)[0]
	}
	hold, err := a.service.ReplaceHold(c.UserContext(), holdID, body.OfferID, a.sessionID(c), body.SeatIDs)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, holdResponse(hold))
}
func (a *API) deleteHold(c *fiber.Ctx) error {
	holdID, err := a.holdParam(c)
	if err != nil {
		return a.handle(c, err)
	}
	if err := a.service.DeleteHold(c.UserContext(), holdID, a.sessionID(c)); err != nil {
		return a.handle(c, err)
	}
	return noContent(c)
}
func (a *API) createBooking(c *fiber.Ctx) error {
	var body struct {
		HoldID string `json:"hold_id"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	if !service.ValidHoldID(body.HoldID) {
		return a.fail(c, fiber.StatusBadRequest, "INVALID_IDENTIFIER", "The hold_id must be <offer_uuid>.<hold_uuid>.", map[string]string{"hold_id": "Must be <offer_uuid>.<hold_uuid>."})
	}
	data, err := a.service.CreateBooking(c.UserContext(), body.HoldID, a.sessionID(c), c.Get("Idempotency-Key"))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 201, data)
}
func (a *API) getBooking(c *fiber.Ctx) error {
	bookingID, err := a.uuidParam(c, "bookingId")
	if err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.GetBooking(c.UserContext(), bookingID, a.sessionID(c))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) checkout(c *fiber.Ctx) error {
	bookingID, err := a.uuidParam(c, "bookingId")
	if err != nil {
		return a.handle(c, err)
	}
	var body service.CheckoutInput
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.Checkout(c.UserContext(), bookingID, a.sessionID(c), c.Get("Idempotency-Key"), body)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) getPayment(c *fiber.Ctx) error {
	paymentID, err := a.uuidParam(c, "paymentId")
	if err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.GetPayment(c.UserContext(), paymentID, a.sessionID(c))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) simulatePayment(c *fiber.Ctx) error {
	if a.cfg.IsProduction() {
		return a.fail(c, 404, "NOT_FOUND", "The requested resource was not found.", nil)
	}
	paymentID, err := a.uuidParam(c, "paymentId")
	if err != nil {
		return a.handle(c, err)
	}
	eventID := c.Get("Idempotency-Key")
	data, err := a.service.MarkPaymentPaid(c.UserContext(), paymentID, a.sessionID(c), eventID)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) paymentWebhook(c *fiber.Ctx) error {
	if c.Params("provider") != "simulator" || a.cfg.IsProduction() {
		return a.fail(c, 501, "PROVIDER_NOT_CONFIGURED", "Payment provider is not configured.", nil)
	}
	var body struct {
		PaymentID string `json:"payment_id"`
		EventID   string `json:"event_id"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	if err := a.service.MarkPaymentPaidWebhook(c.UserContext(), body.PaymentID, body.EventID); err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, fiber.Map{"accepted": true})
}
func (a *API) requestOTP(c *fiber.Ctx) error {
	var body struct {
		Phone string `json:"phone"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	code, err := a.service.RequestOTP(c.UserContext(), body.Phone)
	if err != nil {
		return a.handle(c, err)
	}
	response := fiber.Map{"message": "If this number is linked to a ticket, an OTP code has been sent."}
	if code != "" {
		response["debug_code"] = code
	}
	return a.ok(c, 202, response)
}
func (a *API) verifyOTP(c *fiber.Ctx) error {
	var body struct {
		Phone string `json:"phone"`
		Code  string `json:"code"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	phone, err := a.service.VerifyOTP(c.UserContext(), body.Phone, body.Code)
	if err != nil {
		return a.handle(c, err)
	}
	if err = a.setTicketCookie(c, phone); err != nil {
		return a.handle(c, err)
	}
	tickets, err := a.service.ListTickets(c.UserContext(), phone)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, tickets)
}
func (a *API) setTicketCookie(c *fiber.Ctx, phone string) error {
	subject, err := a.service.ProtectTicketAccess(phone)
	if err != nil {
		return err
	}
	exp := time.Now().Add(15 * time.Minute).Unix()
	payload := subject + "." + strconv.FormatInt(exp, 10)
	value := payload + "." + security.SignToken(a.cfg.SessionSecret, payload)
	c.Cookie(&fiber.Cookie{Name: ticketCookie, Value: value, Path: "/api/v1/tickets", HTTPOnly: true, Secure: a.cfg.IsProduction(), SameSite: fiber.CookieSameSiteLaxMode, Expires: time.Unix(exp, 0)})
	return nil
}
func (a *API) ticketAccess(c *fiber.Ctx) error {
	parts := strings.Split(c.Cookies(ticketCookie), ".")
	if len(parts) != 3 || !security.VerifyToken(a.cfg.SessionSecret, parts[0]+"."+parts[1], parts[2]) {
		return a.fail(c, 401, "TICKET_ACCESS_REQUIRED", "OTP verification is required.", nil)
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return a.fail(c, 401, "TICKET_ACCESS_EXPIRED", "Ticket access has expired.", nil)
	}
	phone, err := a.service.UnprotectTicketAccess(parts[0])
	if err != nil {
		return a.fail(c, 401, "TICKET_ACCESS_REQUIRED", "OTP verification is required.", nil)
	}
	c.Locals("ticket_phone", phone)
	return c.Next()
}
func (a *API) listTickets(c *fiber.Ctx) error {
	data, err := a.service.ListTickets(c.UserContext(), localString(c, "ticket_phone"))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) getTicket(c *fiber.Ctx) error {
	ticketID, err := a.uuidParam(c, "ticketId")
	if err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.ListTickets(c.UserContext(), localString(c, "ticket_phone"))
	if err != nil {
		return a.handle(c, err)
	}
	for _, ticket := range data {
		if ticket.ID == ticketID {
			return a.ok(c, 200, ticket)
		}
	}
	return a.fail(c, 404, "TICKET_NOT_FOUND", "Ticket not found.", nil)
}
func (a *API) ticketQR(c *fiber.Ctx) error {
	ticketID, err := a.uuidParam(c, "ticketId")
	if err != nil {
		return a.handle(c, err)
	}
	payload, err := a.service.TicketQRPayload(c.UserContext(), ticketID, localString(c, "ticket_phone"))
	if err != nil {
		return a.handle(c, err)
	}
	code, err := qrcode.New(payload, qrcode.Medium)
	if err != nil {
		return a.handle(c, err)
	}
	bitmap := code.Bitmap()
	scale := 4
	size := len(bitmap) * scale
	var svg strings.Builder
	fmt.Fprintf(&svg, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="white"/>`, size, size)
	for y, row := range bitmap {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&svg, `<rect x="%d" y="%d" width="%d" height="%d" fill="#124559"/>`, x*scale, y*scale, scale, scale)
			}
		}
	}
	svg.WriteString("</svg>")
	c.Set(fiber.HeaderContentType, "image/svg+xml; charset=utf-8")
	c.Set("Cache-Control", "private, max-age=300")
	return c.SendString(svg.String())
}
