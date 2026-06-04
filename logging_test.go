package main

import (
	"bytes"
	"log"
	"strings"
	"sync"
	"testing"
)

// captureLog replaces log output with a buffer for the duration of fn and
// returns whatever was written.
func captureLog(tb testing.TB, fn func()) string {
	tb.Helper()

	var buf bytes.Buffer

	oldOut := log.Writer()
	oldFlags := log.Flags()

	log.SetOutput(&buf)
	log.SetFlags(0)

	defer func() {
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
	}()

	fn()

	return buf.String()
}

// TestLogger_Levels — not parallel: captureLog swaps log.SetOutput globally,
// which races with any parallel test emitting log output.
//
//nolint:paralleltest // global log.SetOutput swap
func TestLogger_Levels(t *testing.T) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelInfo)

	out := captureLog(t, func() {
		logger.Error("e")
		logger.Info("i")
		logger.Debug("d")
		logger.Trace("t")
	})

	if !strings.Contains(out, "e") {
		t.Error("error must be logged at info level")
	}

	if !strings.Contains(out, "i") {
		t.Error("info must be logged at info level")
	}

	if strings.Contains(out, "[ESL DEBUG] d") {
		t.Errorf("debug must NOT be logged at info level: %q", out)
	}

	if strings.Contains(out, "[ESL TRACE] t") {
		t.Errorf("trace must NOT be logged at info level: %q", out)
	}
}

//nolint:paralleltest // captureLog swaps log.SetOutput globally
func TestLogger_TraceLevel(t *testing.T) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelTrace)

	out := captureLog(t, func() {
		logger.Error("a")
		logger.Info("b")
		logger.Debug("c")
		logger.Trace("d")
	})
	for _, s := range []string{"a", "b", "c", "d"} {
		if !strings.Contains(out, s) {
			t.Errorf("trace level must log %q", s)
		}
	}
}

func TestLogger_SetFromString(t *testing.T) {
	t.Parallel()

	logger := &Logger{}
	cases := []struct {
		input string
		want  EslLogLevel
	}{
		{logLevelErrorStr, LogLevelError},
		{logLevelInfoStr, LogLevelInfo},
		{logLevelDebugStr, LogLevelDebug},
		{logLevelTraceStr, LogLevelTrace},
		{"unknown", LogLevelInfo}, // default
	}

	for _, tc := range cases {
		logger.SetLogLevelFromString(tc.input)

		if got := logger.GetLogLevel(); got != tc.want {
			t.Errorf("SetLogLevelFromString(%q): got %d want %d", tc.input, got, tc.want)
		}
	}
}

func TestLogger_Concurrent(t *testing.T) {
	t.Parallel()

	logger := &Logger{}
	logger.SetLogLevel(LogLevelError)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := range 1000 {
				logger.SetLogLevel(LogLevelDebug)
				_ = logger.GetLogLevel()
				logger.Debug("test %d", j)
			}
		}()
	}

	wg.Wait()
}

// ----- Benchmarks -----

func BenchmarkLogger_Disabled(b *testing.B) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelError)
	// Discard log output so the call cost itself is measured.
	old := log.Writer()

	log.SetOutput(&bytes.Buffer{})
	b.Cleanup(func() { log.SetOutput(old) })

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		logger.Debug("ignored %d", i) // below threshold
	}
}

func BenchmarkLogger_Enabled(b *testing.B) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelDebug)

	old := log.Writer()

	log.SetOutput(&bytes.Buffer{})
	b.Cleanup(func() { log.SetOutput(old) })

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		logger.Debug("hit %d", i)
	}
}

func BenchmarkLogger_GetLevel(b *testing.B) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelInfo)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = logger.GetLogLevel()
	}
}

// TestLogger_Log — not parallel: captureLog swaps log.SetOutput globally.
//
//nolint:paralleltest // global log.SetOutput swap
func TestLogger_Log(t *testing.T) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelTrace)

	out := captureLog(t, func() {
		logger.Log(LogLevelError, "e%d", 1)
		logger.Log(LogLevelInfo, "i%d", 2)
		logger.Log(LogLevelDebug, "d%d", 3)
		logger.Log(LogLevelTrace, "t%d", 4)
		logger.Log(EslLogLevel(99), "x%d", 5) // unknown level → "?" prefix, but suppressed (99 > trace)
	})

	cases := []string{
		"[ESL ERROR] e1",
		"[ESL INFO] i2",
		"[ESL DEBUG] d3",
		"[ESL TRACE] t4",
	}
	for _, want := range cases {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, "x5") {
		t.Errorf("level above threshold must be suppressed:\n%s", out)
	}
}

//nolint:paralleltest // global log.SetOutput swap
func TestLogger_Log_UnknownLevelPrefix(t *testing.T) {
	logger := &Logger{}
	// Raise the threshold high enough that the unknown level is enabled.
	logger.level.Store(100)

	out := captureLog(t, func() {
		logger.Log(EslLogLevel(99), "weird")
	})

	if !strings.Contains(out, "[ESL ?] weird") {
		t.Errorf("expected fallback prefix, got:\n%s", out)
	}
}

//nolint:paralleltest // global log.SetOutput swap
func TestLogger_Log_SuppressedBelowThreshold(t *testing.T) {
	logger := &Logger{}
	logger.SetLogLevel(LogLevelError)

	out := captureLog(t, func() {
		logger.Log(LogLevelDebug, "hidden")
	})

	if strings.Contains(out, "hidden") {
		t.Errorf("debug message must be suppressed at error level:\n%s", out)
	}
}

func TestGetLogger_Singleton(t *testing.T) {
	t.Parallel()

	first := GetLogger()
	second := GetLogger()

	if first != second {
		t.Error("GetLogger must return the same instance")
	}
}
