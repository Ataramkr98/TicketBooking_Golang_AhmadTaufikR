package httpapi

import (
	"bytes"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/elysian-premium-lines/backend/internal/config"
	"github.com/gofiber/fiber/v2"
)

func TestOperatorCannotEditTripMasterFields(t *testing.T) {
	api := &API{}
	app := fiber.New()
	app.Put("/trips/:id", func(c *fiber.Ctx) error {
		c.Locals("admin_role", "operator")
		c.Locals("admin_id", "operator-id")
		return c.Next()
	}, api.adminMutate("trips", "update"))

	request := httptest.NewRequest("PUT", "/trips/11111111-1111-1111-1111-111111111111", bytes.NewBufferString(`{"status":"boarding","bus_id":"another-bus"}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestAdminUpdateRouteMissingBodyReturnsValidationError(t *testing.T) {
	api := &API{}
	app := fiber.New()
	app.Put("/cities/:id", func(c *fiber.Ctx) error {
		c.Locals("admin_role", "admin")
		c.Locals("admin_id", "admin-id")
		return c.Next()
	}, api.adminMutate("cities", "update"))

	request := httptest.NewRequest("PUT", "/cities/11111111-1111-1111-1111-111111111111", bytes.NewBufferString(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	// After fix, AdminUpdate returns 422 field_errors before any SQL.
	if response.StatusCode != fiber.StatusUnprocessableEntity {
		t.Fatalf("status=%d", response.StatusCode)
	}
}

func TestGuestMutationRequiresCSRFDespiteBearerHeader(t *testing.T) {
	api := &API{cfg: config.Config{CORSOrigins: []string{"http://localhost:5173"}}}
	app := fiber.New()
	app.Post("/seat-holds", api.csrf, func(c *fiber.Ctx) error { return c.SendString("ok") })

	request := httptest.NewRequest("POST", "/seat-holds", bytes.NewBufferString(`{}`))
	request.Header.Set("Authorization", "Bearer garbage-token")
	request.Header.Set("Content-Type", "application/json")
	response, err := app.Test(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != fiber.StatusForbidden {
		t.Fatalf("status=%d want 403", response.StatusCode)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "CSRF_INVALID") {
		t.Fatalf("body=%s", body)
	}
}
