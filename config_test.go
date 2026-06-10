package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestEnvBool — not parallelized: t.Setenv panics if t.Parallel has been called.
//
//nolint:paralleltest // uses t.Setenv, which is incompatible with t.Parallel
func TestEnvBool(t *testing.T) {
	cases := []struct {
		val  string
		init bool
		want bool
	}{
		{"true", false, true},
		{"True", false, true},
		{"YES", false, true},
		{"1", false, true},
		{"false", true, false},
		{"FALSE", true, false},
		{"0", true, false},
		{"no", true, false},
		{testBogusValue, true, false},
		{"", true, true}, // unset → leave alone
	}
	for _, tc := range cases {
		t.Setenv("TESTKEY_BOOL", tc.val)

		got := tc.init
		envBool("TESTKEY_BOOL", &got)

		if got != tc.want {
			t.Errorf("envBool(%q) starting=%v: got %v want %v", tc.val, tc.init, got, tc.want)
		}
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("TESTKEY_INT", "42")

	got := 0
	envInt("TESTKEY_INT", &got)

	if got != 42 {
		t.Errorf("envInt: got %d want 42", got)
	}

	// invalid value: leave dst alone
	t.Setenv("TESTKEY_INT", "not-a-number")

	got = 7
	envInt("TESTKEY_INT", &got)

	if got != 7 {
		t.Errorf("envInt invalid: got %d want 7", got)
	}
}

func TestEnvString(t *testing.T) {
	t.Setenv("TESTKEY_STR", "env-value")

	got := "default"
	envString("TESTKEY_STR", &got)

	if got != "env-value" {
		t.Errorf("envString: got %q want %q", got, "env-value")
	}

	t.Setenv("TESTKEY_STR", "")
	envString("TESTKEY_STR", &got)

	if got != "env-value" { // unset/empty leaves the value
		t.Errorf("envString empty: got %q want %q", got, "env-value")
	}
}

func TestEnvJSONStringSlice(t *testing.T) {
	t.Setenv("TESTKEY_SLICE", `["a","b","c"]`)

	var dst []string

	envJSONStringSlice("TESTKEY_SLICE", &dst)

	if len(dst) != 3 || dst[0] != "a" || dst[2] != "c" {
		t.Errorf("envJSONStringSlice: got %#v", dst)
	}

	// invalid JSON: leave as-is
	dst = []string{"original"}

	t.Setenv("TESTKEY_SLICE", "not-json")
	envJSONStringSlice("TESTKEY_SLICE", &dst)

	if len(dst) != 1 || dst[0] != "original" {
		t.Errorf("envJSONStringSlice invalid JSON: got %#v", dst)
	}
}

func TestComputeBackoff(t *testing.T) {
	t.Parallel()

	base := time.Second

	const ceiling = 60 * time.Second

	cases := []struct {
		attempt int64
		want    time.Duration
	}{
		{0, base},
		{1, base},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 32 * time.Second},
		{7, 60 * time.Second}, // 64s clamped to 60s ceiling
		{1000, 60 * time.Second},
	}
	for _, tc := range cases {
		if got := computeBackoff(base, ceiling, tc.attempt); got != tc.want {
			t.Errorf("computeBackoff(attempt=%d) = %v, want %v", tc.attempt, got, tc.want)
		}
	}
}

// ----- buildConfig / defaultConfig -----

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	if cfg.Server.Port != "8088" {
		t.Errorf("Server.Port = %q", cfg.Server.Port)
	}

	if cfg.FreeSWITCH.DefaultDomain != defaultFreeSWITCHDomain {
		t.Errorf("DefaultDomain = %q", cfg.FreeSWITCH.DefaultDomain)
	}

	if !cfg.Security.Enabled || !cfg.Cache.Enabled || !cfg.Security.RateLimit.Enabled {
		t.Error("security, cache, and rate limiting must default to enabled")
	}

	if len(cfg.Security.TrustedNetworks) != 4 {
		t.Errorf("TrustedNetworks = %v", cfg.Security.TrustedNetworks)
	}
}

func TestBuildConfig_CreatesDefaultFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")

	cfg, err := buildConfig(path)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	if cfg.Server.Port != "8088" {
		t.Errorf("expected defaults, got port %q", cfg.Server.Port)
	}

	// The default file must have been written and be loadable.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("default config file not written: %v", err)
	}

	var roundTrip AppConfig

	err = json.Unmarshal(data, &roundTrip)
	if err != nil {
		t.Fatalf("written default config is not valid JSON: %v", err)
	}

	if roundTrip.Security.IPTablesChain != defaultIPTablesChain {
		t.Errorf("written config chain = %q", roundTrip.Security.IPTablesChain)
	}

	if roundTrip.Security.IPSetName != projectName {
		t.Errorf("written config ipset name = %q", roundTrip.Security.IPSetName)
	}
}

func TestBuildConfig_LoadsExistingFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")
	content := `{"server":{"host":"203.0.113.1","port":"9999"},"security":{"enabled":false}}`

	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig(path)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	if cfg.Server.Port != "9999" || cfg.Server.Host != "203.0.113.1" {
		t.Errorf("file overrides not applied: %s:%s", cfg.Server.Host, cfg.Server.Port)
	}

	if cfg.Security.Enabled {
		t.Error("security.enabled=false not applied")
	}

	// Fields absent from the file keep their defaults.
	if cfg.Cache.SecurityTTL != "5m" {
		t.Errorf("Cache.SecurityTTL = %q, want default", cfg.Cache.SecurityTTL)
	}
}

func TestBuildConfig_InvalidJSON(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.json")

	err := os.WriteFile(path, []byte("{not json"), 0o600)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := buildConfig(path)
	if err == nil {
		t.Fatal("expected decode error")
	}

	if cfg == nil || cfg.Server.Port != "8088" {
		t.Error("on decode error the defaults must be returned")
	}
}

func TestBuildConfig_CreateFails(t *testing.T) {
	t.Parallel()

	// A path inside a nonexistent directory cannot be created.
	path := filepath.Join(t.TempDir(), "missing-dir", "config.json")

	_, err := buildConfig(path)
	if err == nil {
		t.Error("expected create error for path in nonexistent directory")
	}
}

func TestBuildConfig_OpenFails(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("file permissions are not enforced for root")
	}

	path := filepath.Join(t.TempDir(), "config.json")

	err := os.WriteFile(path, []byte("{}"), 0o000)
	if err != nil {
		t.Fatal(err)
	}

	_, openAttemptErr := buildConfig(path)
	if openAttemptErr == nil {
		t.Error("expected open error for unreadable file")
	}
}

// TestBuildConfig_EnvOverrides — not parallel: t.Setenv forbids t.Parallel.
//

func TestBuildConfig_EnvOverrides(t *testing.T) {
	t.Setenv("SERVER_PORT", "7777")
	t.Setenv("SECURITY_RATE_LIMIT_CALL_LIMIT", "123")

	path := filepath.Join(t.TempDir(), "config.json")

	cfg, err := buildConfig(path)
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}

	if cfg.Server.Port != "7777" {
		t.Errorf("SERVER_PORT override not applied: %q", cfg.Server.Port)
	}

	if cfg.Security.RateLimit.CallRateLimit != 123 {
		t.Errorf("rate-limit override not applied: %d", cfg.Security.RateLimit.CallRateLimit)
	}
}
