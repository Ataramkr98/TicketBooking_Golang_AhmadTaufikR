package httpapi

import (
	"errors"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func TestFailBodyHasEnglishAndSuccessFalse(t *testing.T) {
	app := fiber.New()
	var a API
	app.Post("/x", func(c *fiber.Ctx) error {
		return a.fail(c, fiber.StatusBadRequest, "INVALID_JSON", "Request body must be valid JSON.", nil)
	})
	req := httptest.NewRequest("POST", "/x", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusBadRequest {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, `"success":false`) {
		t.Fatalf("missing success:false: %s", s)
	}
	if !strings.Contains(s, "Request body must be valid JSON.") {
		t.Fatalf("detail not English: %s", s)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
		t.Fatalf("content-type %s", ct)
	}
}

func TestHandleInternalErrorIsEnglish(t *testing.T) {
	app := fiber.New()
	var a API
	app.Get("/boom", func(c *fiber.Ctx) error {
		return a.handle(c, errors.New("db exploded"))
	})
	resp, err := app.Test(httptest.NewRequest("GET", "/boom", nil))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, "An internal error occurred.") {
		t.Fatalf("internal detail not English: %s", s)
	}
	if strings.Contains(s, "Terjadi kesalahan") {
		t.Fatalf("still Indonesian: %s", s)
	}
}

func TestCatchAllReturnsMethodNotAllowedForNonGET(t *testing.T) {
	app := fiber.New()
	var a API
	app.Use(func(c *fiber.Ctx) error {
		if c.Method() == fiber.MethodGet || c.Method() == fiber.MethodHead {
			return a.fail(c, fiber.StatusNotFound, "NOT_FOUND", "The requested resource was not found.", nil)
		}
		return a.fail(c, fiber.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed for this resource.", nil)
	})
	resp, err := app.Test(httptest.NewRequest("PUT", "/nope", nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusMethodNotAllowed {
		t.Fatalf("status %d want 405", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "METHOD_NOT_ALLOWED") {
		t.Fatalf("body %s", body)
	}
}
