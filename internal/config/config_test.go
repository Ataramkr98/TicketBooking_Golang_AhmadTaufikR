package config

import "testing"

func TestNormalizeEnvironmentAcceptsKnownSpellings(t *testing.T) {
	cases := map[string]string{
		"":            EnvDevelopment,
		"dev":         EnvDevelopment,
		"development": EnvDevelopment,
		"local":       EnvDevelopment,
		"staging":     EnvStaging,
		"STAGING":     EnvStaging,
		" stage ":     EnvStaging,
		"prod":        EnvProduction,
		"Production":  EnvProduction,
		"PRODUCTION":  EnvProduction,
		" production": EnvProduction,
	}
	for raw, want := range cases {
		got, err := NormalizeEnvironment(raw)
		if err != nil {
			t.Fatalf("NormalizeEnvironment(%q): unexpected error %v", raw, err)
		}
		if got != want {
			t.Fatalf("NormalizeEnvironment(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestNormalizeEnvironmentRejectsUnknownValues(t *testing.T) {
	for _, raw := range []string{"prodction", "PRODUCTION!", "test", "1", "qa", "sandbox"} {
		if got, err := NormalizeEnvironment(raw); err == nil {
			t.Fatalf("NormalizeEnvironment(%q) accepted unknown value as %q", raw, got)
		}
	}
}

// The defect: APP_ENV=Production used to compare false against the literal
// "production" and switch off every production guard.
func TestIsProductionCoversEveryAliasOfProduction(t *testing.T) {
	for _, raw := range []string{"production", "Production", "PRODUCTION", "prod", "Prod", " prod "} {
		env, err := NormalizeEnvironment(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg := Config{Environment: env}
		if !cfg.IsProduction() {
			t.Fatalf("APP_ENV=%q resolved to %q and IsProduction() is false", raw, env)
		}
		if cfg.IsDevelopment() {
			t.Fatalf("APP_ENV=%q resolved to %q and IsDevelopment() is true", raw, env)
		}
	}
}

// Staging runs the production guards on purpose: it usually holds a copy of
// production PII and is reachable off-site.
func TestStagingRunsProductionGuards(t *testing.T) {
	cfg := Config{Environment: EnvStaging}
	if !cfg.IsProduction() {
		t.Fatal("staging must run the production guards")
	}
	if cfg.IsDevelopment() {
		t.Fatal("staging must not run in development mode")
	}
}

func TestDevelopmentIsTheOnlyRelaxedEnvironment(t *testing.T) {
	for _, env := range []string{EnvDevelopment, EnvStaging, EnvProduction} {
		cfg := Config{Environment: env}
		if cfg.IsProduction() == cfg.IsDevelopment() {
			t.Fatalf("env %q: IsProduction=%v IsDevelopment=%v", env, cfg.IsProduction(), cfg.IsDevelopment())
		}
	}
}

func TestLoadRejectsUnknownEnvironment(t *testing.T) {
	t.Setenv("APP_ENV", "prodction")
	if _, err := Load(); err == nil {
		t.Fatal("expected Load to fail on an unknown APP_ENV")
	}
}

func TestLoadAppliesProductionGuardsToAliases(t *testing.T) {
	for _, env := range []string{"Production", "prod", "staging"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("APP_ENV", env)
			t.Setenv("CACHE_DRIVER", "memory")
			// No secrets are set, so the secret-length guard must fire for each
			// alias rather than letting the process start relaxed.
			_, err := Load()
			if err == nil {
				t.Fatalf("APP_ENV=%q started without production guards", env)
			}
		})
	}
}

func TestLoadKeepsDevelopmentDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "dev")
	t.Setenv("CACHE_DRIVER", "memory")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("development Load: %v", err)
	}
	if !cfg.IsDevelopment() {
		t.Fatalf("environment=%q", cfg.Environment)
	}
	if len(cfg.SessionSecret) != 32 || len(cfg.JWTSecret) != 32 || len(cfg.EncryptionKey) != 32 {
		t.Fatalf("development secrets were not generated: session=%d jwt=%d key=%d", len(cfg.SessionSecret), len(cfg.JWTSecret), len(cfg.EncryptionKey))
	}
}

func TestLoadSeedsOperatorEmail(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("CACHE_DRIVER", "memory")
	t.Setenv("OPERATOR_SEED_EMAIL", "station.ops@example.test")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OperatorSeedEmail != "station.ops@example.test" {
		t.Fatalf("OperatorSeedEmail=%q", cfg.OperatorSeedEmail)
	}
}
