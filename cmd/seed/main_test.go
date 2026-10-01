package main

import (
	"testing"

	"github.com/elysian-premium-lines/backend/internal/config"
)

// In development the seed still falls back to the published demo passwords so a
// fresh checkout works with no configuration.
func TestRequireSeedSecretsFallsBackInDevelopment(t *testing.T) {
	admin, operator := requireSeedSecrets(config.Config{Environment: config.EnvDevelopment})
	if admin != "AdminPassword123!" {
		t.Fatalf("admin=%q", admin)
	}
	if operator != "OperatorPassword123!" {
		t.Fatalf("operator=%q", operator)
	}
}

func TestRequireSeedSecretsPrefersConfiguredPasswords(t *testing.T) {
	admin, operator := requireSeedSecrets(config.Config{
		Environment:          config.EnvStaging,
		AdminSeedPassword:    "supplied-admin",
		OperatorSeedPassword: "supplied-operator",
	})
	if admin != "supplied-admin" || operator != "supplied-operator" {
		t.Fatalf("admin=%q operator=%q", admin, operator)
	}
}
