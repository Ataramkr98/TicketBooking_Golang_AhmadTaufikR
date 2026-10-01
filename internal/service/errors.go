package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/elysian-premium-lines/backend/internal/security"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Error struct {
	Status       int
	Code, Detail string
	Fields       map[string]string
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }
func problem(status int, code, detail string) error {
	return &Error{Status: status, Code: code, Detail: detail}
}
func invalid(fields map[string]string) error {
	return &Error{Status: 422, Code: "VALIDATION_FAILED", Detail: "Check the data you sent.", Fields: fields}
}
func wrapInternal(err error) error { return fmt.Errorf("internal service error: %w", err) }

// Postgres SQLSTATE classes and codes the service layer needs to tell apart.
// A driver error or a cancelled context has no code at all, which is exactly
// what keeps "not found" distinguishable from "the database went away".
const (
	sqlStateSerializationFailure = "40001"
	sqlStateDeadlockDetected     = "40P01"
)

// sqlState returns the SQLSTATE of a Postgres server error, or "" when err did
// not come from the server.
func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// isSerializationFailure reports whether a SERIALIZABLE transaction was aborted
// by the concurrency detector and is therefore safe to replay. 40001 and 40P01
// are the only two outcomes where retrying the whole transaction is correct;
// every other error is deterministic and must reach the caller.
func isSerializationFailure(err error) bool {
	switch sqlState(err) {
	case sqlStateSerializationFailure, sqlStateDeadlockDetected:
		return true
	}
	return false
}

// isConstraintViolation reports whether err is a data-integrity error (unique,
// foreign key, check, not-null) as opposed to a connection, permission, or
// syntax failure. Admin handlers use it to answer 422 for a bad payload and 500
// for a broken database instead of mapping every error to "invalid data".
func isConstraintViolation(err error) bool {
	switch sqlState(err) {
	case "23000", "23001", "23502", "23503", "23505", "23514":
		return true
	}
	return false
}

// lookupErr converts a single-row read into either "not found" or an internal
// error. Returning 404 for a context deadline or a dropped connection tells the
// caller the booking does not exist when in fact the server never asked.
func lookupErr(err error, code, detail string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return problem(404, code, detail)
	}
	return wrapInternal(err)
}

// requireUUID rejects a malformed identifier before it is interpolated into a
// `$n::uuid` cast, where it would become a 22P02 syntax error and a 500.
func requireUUID(field, value string) error {
	if !security.ValidUUID(strings.TrimSpace(value)) {
		return &Error{Status: 400, Code: "INVALID_IDENTIFIER", Detail: fmt.Sprintf("The %s must be a UUID.", field), Fields: map[string]string{field: "Must be a UUID."}}
	}
	return nil
}
