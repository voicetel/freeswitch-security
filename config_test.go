package main

import (
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
		{"bogus", true, false},
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
	t.Setenv("TESTKEY_STR", "hello")

	got := "default"
	envString("TESTKEY_STR", &got)

	if got != "hello" {
		t.Errorf("envString: got %q want %q", got, "hello")
	}

	t.Setenv("TESTKEY_STR", "")
	envString("TESTKEY_STR", &got)

	if got != "hello" { // unset/empty leaves the value
		t.Errorf("envString empty: got %q want %q", got, "hello")
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
