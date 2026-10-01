package service

import (
	"context"
	"errors"
	"testing"
)

func TestAdminUpdateRoutesValidatesBeforeSQL(t *testing.T) {
	s := &Service{}
	err := s.AdminUpdate(context.Background(), "routes", "11111111-1111-1111-1111-111111111111", "admin", map[string]any{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	var problem *Error
	if !errors.As(err, &problem) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if problem.Status != 422 || problem.Code != "VALIDATION_FAILED" {
		t.Fatalf("status=%d code=%s", problem.Status, problem.Code)
	}
	if problem.Fields["origin_terminal_id"] == "" {
		t.Fatalf("expected origin_terminal_id field error, fields=%v", problem.Fields)
	}
}

func TestAdminUpdateBusesValidatesBeforeSQL(t *testing.T) {
	s := &Service{}
	err := s.AdminUpdate(context.Background(), "buses", "11111111-1111-1111-1111-111111111111", "admin", map[string]any{"code": "", "name": ""})
	var problem *Error
	if !errors.As(err, &problem) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if problem.Status != 422 {
		t.Fatalf("status=%d", problem.Status)
	}
}

func TestAdminUpdateActiveCoercionRejectsWrongType(t *testing.T) {
	s := &Service{}
	err := s.AdminUpdate(context.Background(), "cities", "11111111-1111-1111-1111-111111111111", "admin", map[string]any{
		"name":   "Jakarta",
		"slug":   "jakarta",
		"active": "yes",
	})
	// Either field-level 422 for active type, or validation before SQL that
	// does not pass a string into a boolean column.
	if err == nil {
		t.Fatal("expected validation error for active type")
	}
	var problem *Error
	if !errors.As(err, &problem) {
		t.Fatalf("expected *Error, got %T: %v", err, err)
	}
	if problem.Status != 422 {
		t.Fatalf("status=%d", problem.Status)
	}
}
