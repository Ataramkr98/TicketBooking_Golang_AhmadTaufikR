package httpapi

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elysian-premium-lines/backend/internal/cache"
	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/elysian-premium-lines/backend/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	testSessionSecret = "test-session-secret-with-enough-bytes-here"
	testJWTSecret     = "test-jwt-secret-with-enough-bytes-here-xx"
	testVaultKey      = "0123456789abcdef0123456789abcdef"
)

// testAPI builds a real API whose session and rate-limit middleware work,
// backed by the in-memory cache. The database pool is nil, which is fine for
// every test answered by a middleware rather than by SQL.
func testAPI(t *testing.T, env string) *API {
	t.Helper()
	cfg := config.Config{
		Environment:    env,
		CORSOrigins:    []string{"http://localhost:5173"},
		SessionSecret:  []byte(testSessionSecret),
		JWTSecret:      []byte(testJWTSecret),
		QRSigningKey:   []byte("test-qr-signing-key-with-enough-bytes-xx"),
		TaxRate:        0.11,
		SeatHoldTTL:    10 * time.Minute,
		OTPTTL:         5 * time.Minute,
		OTPMaxAttempts: 5,
	}
	vault, err := security.NewVault([]byte(testVaultKey), []byte(testVaultKey))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(cfg, nil, cache.NewMemoryStore(), vault)
	api := &API{cfg: cfg, service: svc, sessions: security.NewSessionSigner(cfg.SessionSecret, time.Hour)}
	// Stands in for svc.AdminAccount, which needs Postgres. The stub resolves by
	// email so a token's role can be changed per test.
	api.adminAccount = func(_ context.Context, id string) (string, bool, error) {
		if role, ok := testAccountRoles[id]; ok {
			return role, true, nil
		}
		return "admin", true, nil
	}
	return api
}

// testAccountRoles lets a test register an account whose role adminAuth should
// resolve to. Keyed by the token subject.
var testAccountRoles = map[string]string{}

func signedAdminToken(t *testing.T, api *API, id, role string) string {
	t.Helper()
	// The stubbed admin_account lookup mirrors the row the token claims.
	testAccountRoles[id] = role
	claims := adminClaims{Role: role, RegisteredClaims: jwt.RegisteredClaims{
		Subject:   id,
		Issuer:    "elysian-api",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(api.cfg.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func get(t *testing.T, app *fiber.App, path, bearer string) (*http.Response, string) {
	t.Helper()
	request := httptest.NewRequest("GET", path, nil)
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := app.Test(request, 5000)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

// The core authorization fix: an operator token must not reach the handler for
// GET /api/v1/admin/bookings/:id, which returns the decrypted passenger
// manifest. Asserted on the real route table, before any SQL runs.
func TestOperatorIsForbiddenOnAdminBookingDetail(t *testing.T) {
	api := testAPI(t, "development")
	app := fiber.New()
	api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))
	bookingID := uuid.NewString()

	response, body := get(t, app, "/api/v1/admin/bookings/"+bookingID, signedAdminToken(t, api, uuid.NewString(), "operator"))
	if response.StatusCode != fiber.StatusForbidden {
		t.Fatalf("operator status=%d want 403; body=%s", response.StatusCode, body)
	}
	if !strings.Contains(body, "ADMIN_ROLE_FORBIDDEN") {
		t.Fatalf("operator body=%s", body)
	}
	if strings.Contains(body, "identity_number") || strings.Contains(body, "contact") {
		t.Fatalf("operator response leaked PII: %s", body)
	}
}

// The same guard covers the audit trail, which names every administrator and
// every mutation they made.
func TestOperatorIsForbiddenOnAuditLogs(t *testing.T) {
	api := testAPI(t, "development")
	app := fiber.New()
	api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))

	response, body := get(t, app, "/api/v1/admin/audit-logs", signedAdminToken(t, api, uuid.NewString(), "operator"))
	if response.StatusCode != fiber.StatusForbidden {
		t.Fatalf("operator status=%d want 403; body=%s", response.StatusCode, body)
	}
	if !strings.Contains(body, "ADMIN_ROLE_FORBIDDEN") {
		t.Fatalf("operator body=%s", body)
	}
}

// The guard must let an admin through. The real handler needs Postgres, so the
// 200 is asserted against the same guard composition used on the route with a
// stub terminal handler.
func TestAdminRoleGuardPassesAdminThrough(t *testing.T) {
	api := testAPI(t, "development")
	ok := func(c *fiber.Ctx) error { return c.SendStatus(200) }
	paths := []string{"/admin/bookings/11111111-1111-1111-1111-111111111111", "/admin/audit-logs"}
	for _, path := range paths {
		app := fiber.New()
		chain := append([]fiber.Handler{api.adminAuth}, api.restrictToAdmin(ok)...)
		app.Get(path, chain...)
		response, body := get(t, app, path, signedAdminToken(t, api, uuid.NewString(), "admin"))
		if response.StatusCode != fiber.StatusOK {
			t.Fatalf("%s admin status=%d want 200; body=%s", path, response.StatusCode, body)
		}
		if strings.Contains(body, "ADMIN_ROLE_FORBIDDEN") {
			t.Fatalf("%s admin was blocked by the role guard: %s", path, body)
		}
	}
}

func TestRequireAdminRejectsMissingAndNonAdminRoles(t *testing.T) {
	api := &API{}
	for _, role := range []any{nil, "", "operator", "superadmin", 42} {
		app := fiber.New()
		app.Get("/x", func(c *fiber.Ctx) error {
			c.Locals("admin_role", role)
			return c.Next()
		}, api.requireAdminRoute, func(c *fiber.Ctx) error { return c.SendString("reached") })
		response, body := get(t, app, "/x", "")
		if response.StatusCode != fiber.StatusForbidden {
			t.Fatalf("role %#v produced %d want 403; body=%s", role, response.StatusCode, body)
		}
		if body == "reached" {
			t.Fatalf("role %#v reached the handler behind the guard", role)
		}
	}
	app := fiber.New()
	app.Get("/x", func(c *fiber.Ctx) error {
		c.Locals("admin_role", "admin")
		return c.Next()
	}, api.requireAdminRoute, func(c *fiber.Ctx) error { return c.SendString("reached") })
	response, body := get(t, app, "/x", "")
	if response.StatusCode != fiber.StatusOK {
		t.Fatalf("admin produced %d want 200", response.StatusCode)
	}
	if body != "reached" {
		t.Fatalf("the guard stopped the chain for an admin: %q", body)
	}
}

// A malformed path id used to become a Postgres 22P02 and a 500. It is now a
// 400 with the standard problem envelope, checked at the handler boundary.
func TestMalformedUUIDPathParamsReturn400(t *testing.T) {
	api := testAPI(t, "development")
	app := fiber.New()
	api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))
	adminToken := signedAdminToken(t, api, uuid.NewString(), "admin")

	// Only the admin collection is readable with GET; the item routes are
	// PUT/DELETE (and the booking detail GET), so the method is per case.
	cases := []struct {
		method string
		path   string
		bearer string
	}{
		{"GET", "/api/v1/trips/garbage/seats?offer_id=" + uuid.NewString(), ""},
		{"GET", "/api/v1/bookings/garbage", ""},
		{"GET", "/api/v1/payments/garbage", ""},
		{"POST", "/api/v1/payments/garbage/simulate-success", ""},
		{"GET", "/api/v1/admin/bookings/garbage", adminToken},
		{"POST", "/api/v1/admin/bookings/garbage/cancel", adminToken},
		{"PUT", "/api/v1/admin/cities/garbage", adminToken},
		{"PUT", "/api/v1/admin/buses/garbage/seats", adminToken},
	}
	csrfToken := primeCSRF(t, app)
	for _, tc := range cases {
		request := httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString("{}"))
		request.Header.Set("Authorization", "Bearer "+tc.bearer)
		request.Header.Set("X-CSRF-Token", csrfToken)
		request.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrfToken})
		response, err := app.Test(request, 5000)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != fiber.StatusBadRequest {
			t.Fatalf("%s %s status=%d want 400; body=%s", tc.method, tc.path, response.StatusCode, body)
		}
		if !strings.Contains(string(body), "INVALID_IDENTIFIER") {
			t.Fatalf("%s %s body=%s", tc.method, tc.path, body)
		}
		if ct := response.Header.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
			t.Fatalf("%s %s content-type=%s", tc.method, tc.path, ct)
		}
	}
}

// The session middleware must not read an absent local as the literal "<nil>".
func TestLocalStringReturnsEmptyForMissingLocals(t *testing.T) {
	app := fiber.New()
	var seen string
	app.Get("/x", func(c *fiber.Ctx) error {
		seen = localString(c, "absent")
		return c.SendStatus(200)
	})
	if _, err := app.Test(httptest.NewRequest("GET", "/x", nil)); err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Fatalf("localString=%q want empty", seen)
	}
}

func TestRandomValueIsNotConstant(t *testing.T) {
	first, err := randomValue(24)
	if err != nil {
		t.Fatal(err)
	}
	second, err := randomValue(24)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("two CSRF tokens were identical")
	}
	if strings.Trim(first, "A") == "" {
		t.Fatalf("token looks like a constant fill: %q", first)
	}
}

// RFC 9110 forbids a content type on a 204. Fiber's SendStatus attaches
// text/plain to the empty body.
func TestNoContentOmitsContentType(t *testing.T) {
	app := fiber.New()
	app.Delete("/x", func(c *fiber.Ctx) error { return noContent(c) })
	response, err := app.Test(httptest.NewRequest("DELETE", "/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusNoContent {
		t.Fatalf("status=%d", response.StatusCode)
	}
	if ct := response.Header.Get("Content-Type"); ct != "" {
		t.Fatalf("204 carried Content-Type %q", ct)
	}
}

func TestQueryIntRejectsMalformedNumbers(t *testing.T) {
	api := testAPI(t, "development")
	app := fiber.New()
	app.Get("/search", func(c *fiber.Ctx) error {
		if _, err := queryInt(c, "passengers", 1); err != nil {
			return api.handle(c, err)
		}
		if _, err := queryInt64(c, "max_price", 0); err != nil {
			return api.handle(c, err)
		}
		return c.SendStatus(200)
	})
	// max_price=abc used to become 0, which the service read as "no price
	// filter" instead of an error.
	response, body := get(t, app, "/search?max_price=abc", "")
	if response.StatusCode != fiber.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422; body=%s", response.StatusCode, body)
	}
	if !strings.Contains(body, "max_price") {
		t.Fatalf("body=%s", body)
	}
	if response, body = get(t, app, "/search?passengers=1.5", ""); response.StatusCode != fiber.StatusUnprocessableEntity {
		t.Fatalf("status=%d want 422; body=%s", response.StatusCode, body)
	}
	if response, _ = get(t, app, "/search", ""); response.StatusCode != fiber.StatusOK {
		t.Fatalf("empty query status=%d want 200", response.StatusCode)
	}
	if response, _ = get(t, app, "/search?max_price=500000", ""); response.StatusCode != fiber.StatusOK {
		t.Fatalf("valid query status=%d want 200", response.StatusCode)
	}
}

// primeCSRF performs the priming GET the session middleware answers the CSRF
// cookie on, and returns the token the follow-up request must echo.
func primeCSRF(t *testing.T, app *fiber.App) string {
	t.Helper()
	response, err := app.Test(httptest.NewRequest("GET", "/api/v1/tickets/not-a-uuid", nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == csrfCookie {
			return cookie.Value
		}
	}
	t.Fatal("the session middleware did not issue a CSRF cookie")
	return ""
}

// The ticket routes sit behind the OTP cookie, so the malformed-id rejection is
// asserted on the handler itself.
func TestTicketHandlersRejectMalformedTicketIDs(t *testing.T) {
	api := testAPI(t, "development")
	for _, handler := range []fiber.Handler{api.getTicket, api.ticketQR} {
		app := fiber.New()
		app.Get("/tickets/:ticketId", func(c *fiber.Ctx) error {
			c.Locals("ticket_phone", "6281234567890")
			return c.Next()
		}, handler)
		response, body := get(t, app, "/tickets/garbage", "")
		if response.StatusCode != fiber.StatusBadRequest {
			t.Fatalf("status=%d want 400; body=%s", response.StatusCode, body)
		}
		if !strings.Contains(body, "INVALID_IDENTIFIER") {
			t.Fatalf("body=%s", body)
		}
	}
}

func TestUUIDParamAndHoldParamValidation(t *testing.T) {
	api := testAPI(t, "development")
	app := fiber.New()
	app.Get("/x/:holdId", func(c *fiber.Ctx) error {
		if _, err := api.holdParam(c); err != nil {
			return api.handle(c, err)
		}
		return c.SendStatus(200)
	})
	good := "/x/11111111-1111-1111-1111-111111111111.22222222-2222-2222-2222-222222222222"
	if response, body := get(t, app, good, ""); response.StatusCode != fiber.StatusOK {
		t.Fatalf("well-formed hold id status=%d body=%s", response.StatusCode, body)
	}
	for _, bad := range []string{"/x/garbage", "/x/11111111-1111-1111-1111-111111111111", "/x/11111111-1111-1111-1111-111111111111.", "/x/.22222222-2222-2222-2222-222222222222"} {
		response, body := get(t, app, bad, "")
		if response.StatusCode != fiber.StatusBadRequest {
			t.Fatalf("%s status=%d want 400; body=%s", bad, response.StatusCode, body)
		}
	}
}

// The simulate-success endpoint must disappear for every production-equivalent
// environment, including the aliases that used to slip through.
func TestSimulateSuccessIsHiddenOutsideDevelopment(t *testing.T) {
	for _, env := range []string{"production", "Production", "prod", "staging", "Staging"} {
		api := testAPI(t, env)
		if !api.cfg.IsProduction() {
			t.Fatalf("env %q did not resolve to a production-guarded environment", env)
		}
		app := fiber.New()
		api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))
		csrfToken := primeCSRF(t, app)
		request := httptest.NewRequest("POST", "/api/v1/payments/"+uuid.NewString()+"/simulate-success", bytes.NewBufferString("{}"))
		request.Header.Set("X-CSRF-Token", csrfToken)
		request.AddCookie(&http.Cookie{Name: csrfCookie, Value: csrfToken})
		response, err := app.Test(request, 5000)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != fiber.StatusNotFound {
			t.Fatalf("env %q simulate-success status=%d want 404", env, response.StatusCode)
		}
	}
}

func TestPaymentWebhookIsNotConfiguredOutsideDevelopment(t *testing.T) {
	for _, env := range []string{"production", "prod", "staging"} {
		api := testAPI(t, env)
		app := fiber.New()
		api.registerRoutes(app.Group("/api/v1", api.session, api.timeout))
		request := httptest.NewRequest("POST", "/api/v1/webhooks/payments/simulator", bytes.NewBufferString("{}"))
		response, err := app.Test(request, 5000)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != fiber.StatusNotImplemented {
			t.Fatalf("env %q webhook status=%d want 501", env, response.StatusCode)
		}
	}
}

// The timeout middleware used to build its context from context.Background(),
// which discarded the request context: a client disconnect could not cancel
// in-flight database work and every abandoned request held a connection for the
// full timeout. A value planted on the request context must survive the layer.
func TestTimeoutPreservesTheRequestContext(t *testing.T) {
	api := testAPI(t, "development")
	type ctxKey struct{}
	app := fiber.New()
	var carried string
	var deadline time.Time
	app.Use(func(c *fiber.Ctx) error {
		c.SetUserContext(context.WithValue(c.UserContext(), ctxKey{}, "from-request"))
		return c.Next()
	})
	app.Use(api.timeout)
	app.Get("/x", func(c *fiber.Ctx) error {
		if value, ok := c.UserContext().Value(ctxKey{}).(string); ok {
			carried = value
		}
		deadline, _ = c.UserContext().Deadline()
		return c.SendString("ok")
	})
	if _, err := app.Test(httptest.NewRequest("GET", "/x", nil)); err != nil {
		t.Fatal(err)
	}
	if carried != "from-request" {
		t.Fatalf("request context value was lost: carried=%q", carried)
	}
	if !deadline.After(time.Now()) {
		t.Fatal("the timeout layer did not apply a deadline")
	}
}
