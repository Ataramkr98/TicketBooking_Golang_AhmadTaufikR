package httpapi

import (
	"fmt"
	"strings"
	"time"

	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/elysian-premium-lines/backend/internal/service"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type adminClaims struct {
	Role string `json:"role"`
	jwt.RegisteredClaims
}

func (a *API) adminLogin(c *fiber.Ctx) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	id, role, err := a.service.AdminLogin(c.UserContext(), body.Email, body.Password)
	if err != nil {
		return a.handle(c, err)
	}
	claims := adminClaims{Role: role, RegisteredClaims: jwt.RegisteredClaims{Subject: id, Issuer: "elysian-api", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), IssuedAt: jwt.NewNumericDate(time.Now())}}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.cfg.JWTSecret)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, fiber.Map{"access_token": token, "token_type": "Bearer", "expires_in": 3600, "role": role})
}

func (a *API) adminAuth(c *fiber.Ctx) error {
	raw := strings.TrimSpace(strings.TrimPrefix(c.Get("Authorization"), "Bearer "))
	if raw == "" {
		return a.fail(c, 401, "ADMIN_AUTH_REQUIRED", "Admin token is required.", nil)
	}
	claims := &adminClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return a.cfg.JWTSecret, nil
	}, jwt.WithIssuer("elysian-api"))
	if err != nil || !token.Valid {
		return a.fail(c, 401, "ADMIN_TOKEN_INVALID", "Admin token is invalid.", nil)
	}
	if !security.ValidUUID(claims.Subject) {
		return a.fail(c, 401, "ADMIN_TOKEN_INVALID", "Admin token is invalid.", nil)
	}
	// The signature only proves the token was minted by us. Without this lookup a
	// deactivated account, or one demoted from admin to operator, keeps its old
	// privileges for the full hour. The read is a primary-key hit on a table with
	// a handful of rows, which is a fair price for revoking access immediately.
	role, active, err := a.adminAccount(c.UserContext(), claims.Subject)
	if err != nil {
		return a.handle(c, err)
	}
	if !active {
		return a.fail(c, 401, "ADMIN_TOKEN_REVOKED", "This admin account is no longer active.", nil)
	}
	if role != claims.Role {
		return a.fail(c, 401, "ADMIN_TOKEN_STALE", "Admin permissions changed. Sign in again.", nil)
	}
	c.Locals("admin_id", claims.Subject)
	c.Locals("admin_role", role)
	return c.Next()
}

func (a *API) adminID(c *fiber.Ctx) string { return localString(c, "admin_id") }

// requireAdmin checks the role and returns a problem instead of writing the
// response itself. The caller renders it, because a.fail returns nil once the
// 403 is on the wire, and a caller that treats nil as "allowed" would walk
// straight past the guard.
func (a *API) requireAdmin(c *fiber.Ctx) error {
	if localString(c, "admin_role") != "admin" {
		return &service.Error{Status: 403, Code: "ADMIN_ROLE_FORBIDDEN", Detail: "This action requires the admin role."}
	}
	return nil
}

// requireAdminRoute is requireAdmin wired as a route middleware, for the routes
// whose handler must not run at all for an operator.
func (a *API) requireAdminRoute(c *fiber.Ctx) error {
	if err := a.requireAdmin(c); err != nil {
		return a.handle(c, err)
	}
	return c.Next()
}

// restrictToAdmin composes the role guard with a handler. It is used for the
// admin routes that disclose passenger PII or the administrator audit trail:
// operators scan tickets and move trips, they do not read manifests.
func (a *API) restrictToAdmin(handler fiber.Handler) []fiber.Handler {
	return []fiber.Handler{a.requireAdminRoute, handler}
}

func (a *API) adminList(resource string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		data, err := a.service.AdminList(c.UserContext(), resource)
		if err != nil {
			return a.handle(c, err)
		}
		return a.ok(c, 200, data)
	}
}
func (a *API) adminMutate(resource, action string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var body map[string]any
		if action != "delete" {
			if err := decode(c, &body); err != nil {
				return a.handle(c, err)
			}
		}
		if action != "create" {
			if _, err := a.uuidParam(c, "id"); err != nil {
				return a.handle(c, err)
			}
		}
		if action == "update" && resource == "trips" {
			status, hasStatus := body["status"].(string)
			if localString(c, "admin_role") == "operator" {
				if !hasStatus || len(body) != 1 {
					return a.fail(c, 403, "OPERATOR_TRIP_STATUS_ONLY", "Operators can only change trip status.", nil)
				}
				if err := a.service.AdminUpdateTripStatus(c.UserContext(), c.Params("id"), a.adminID(c), status); err != nil {
					return a.handle(c, err)
				}
				return a.ok(c, 200, fiber.Map{"id": c.Params("id"), "status": status})
			}
			if hasStatus && len(body) == 1 {
				if err := a.service.AdminUpdateTripStatus(c.UserContext(), c.Params("id"), a.adminID(c), status); err != nil {
					return a.handle(c, err)
				}
				return a.ok(c, 200, fiber.Map{"id": c.Params("id"), "status": status})
			}
		}
		if err := a.requireAdmin(c); err != nil {
			return a.handle(c, err)
		}
		switch action {
		case "create":
			data, err := a.service.AdminCreate(c.UserContext(), resource, a.adminID(c), body)
			if err != nil {
				return a.handle(c, err)
			}
			return a.ok(c, 201, data)
		case "update":
			if err := a.service.AdminUpdate(c.UserContext(), resource, c.Params("id"), a.adminID(c), body); err != nil {
				return a.handle(c, err)
			}
			return a.ok(c, 200, fiber.Map{"id": c.Params("id")})
		default:
			if err := a.service.AdminDelete(c.UserContext(), resource, c.Params("id"), a.adminID(c)); err != nil {
				return a.handle(c, err)
			}
			return noContent(c)
		}
	}
}
func (a *API) adminBusSeats(c *fiber.Ctx) error {
	if _, err := a.uuidParam(c, "id"); err != nil {
		return a.handle(c, err)
	}
	if err := a.requireAdmin(c); err != nil {
		return a.handle(c, err)
	}
	var body struct {
		Seats []service.AdminSeatInput `json:"seats"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	if err := a.service.AdminReplaceBusSeats(c.UserContext(), c.Params("id"), a.adminID(c), body.Seats); err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, fiber.Map{"id": c.Params("id"), "seat_count": len(body.Seats)})
}
func (a *API) adminBookings(c *fiber.Ctx) error {
	data, err := a.service.AdminBookings(c.UserContext(), c.Query("status"))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) adminBookingDetail(c *fiber.Ctx) error {
	if _, err := a.uuidParam(c, "id"); err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.AdminBookingDetail(c.UserContext(), c.Params("id"))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) adminCancelBooking(c *fiber.Ctx) error {
	if _, err := a.uuidParam(c, "id"); err != nil {
		return a.handle(c, err)
	}
	if err := a.service.AdminCancelBooking(c.UserContext(), c.Params("id"), a.adminID(c)); err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, fiber.Map{"id": c.Params("id"), "status": "cancelled"})
}
func (a *API) adminScanTicket(c *fiber.Ctx) error {
	var body struct {
		Token string `json:"token"`
	}
	if err := decode(c, &body); err != nil {
		return a.handle(c, err)
	}
	data, err := a.service.ScanTicket(c.UserContext(), body.Token, a.adminID(c))
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) adminDashboardStats(c *fiber.Ctx) error {
	data, err := a.service.AdminDashboardStats(c.UserContext())
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
func (a *API) adminAuditLogs(c *fiber.Ctx) error {
	limit, err := queryInt(c, "limit", 50)
	if err != nil {
		return a.handle(c, err)
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	data, err := a.service.AdminListAuditLogs(c.UserContext(), limit)
	if err != nil {
		return a.handle(c, err)
	}
	return a.ok(c, 200, data)
}
