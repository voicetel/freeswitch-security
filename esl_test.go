package main

import (
	"sync"
	"testing"
	"time"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// Test fixtures shared across the ESL test cases.
const (
	testUserAlice = "alice"
	testDomain    = defaultFreeSWITCHDomain
)

// makeEvent constructs a minimal *eventsocket.Event from a header map.
// eventsocket.EventHeader is map[string]interface{}; the .Get accessor expects
// string values, so we pass strings directly.
func makeEvent(headers map[string]string) *eventsocket.Event {
	hdr := make(eventsocket.EventHeader, len(headers))
	for k, v := range headers {
		hdr[k] = v
	}

	return &eventsocket.Event{Header: hdr}
}

func newTestWorker(tb testing.TB) *EventWorker {
	tb.Helper()

	sm := newTestSecurityManager(tb)
	rm := newTestRateManager(tb, sm, defaultTestRateConfig())
	em := &ESLManager{
		securityManager: sm,
		rateManager:     rm,
		eventPool:       NewEventPool(),
	}

	return &EventWorker{id: 1, manager: em, logger: GetLogger()}
}

func TestExtractRegistrationData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		"Network-Ip": "203.0.113.10",
		"From-User":  testUserAlice,
		"From-Host":  testDomain,
		"Status":     "Registered",
	})
	w.extractRegistrationData(ev, pe)

	if pe.IPAddress != "203.0.113.10" {
		t.Errorf("IPAddress = %q", pe.IPAddress)
	}

	if pe.UserID != testUserAlice {
		t.Errorf("UserID = %q", pe.UserID)
	}

	if pe.Domain != testDomain {
		t.Errorf("Domain = %q", pe.Domain)
	}

	if pe.Status != "Registered" {
		t.Errorf("Status = %q", pe.Status)
	}
}

func TestExtractRegistrationData_FallbackHeaders(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	// From-User missing → falls back to Username.
	ev := makeEvent(map[string]string{
		"Network-Ip":  "203.0.113.10",
		"Username":    "bob",
		"Domain_Name": "fallback.example",
	})
	w.extractRegistrationData(ev, pe)

	if pe.UserID != "bob" {
		t.Errorf("expected UserID fallback to Username; got %q", pe.UserID)
	}

	if pe.Domain != "fallback.example" {
		t.Errorf("expected Domain fallback to Domain_Name; got %q", pe.Domain)
	}
}

func TestExtractFailedRegistrationData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		"Network-Ip": "203.0.113.11",
		"To-User":    "victim",
		"To-Host":    "victim.example",
	})
	w.extractFailedRegistrationData(ev, pe)

	if pe.UserID != "victim" || pe.Domain != "victim.example" {
		t.Errorf("got UserID=%q Domain=%q", pe.UserID, pe.Domain)
	}
}

func TestExtractWrongCallStateData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		"Network_Ip": "203.0.113.12",
		"From_User":  "carol",
	})
	w.extractWrongCallStateData(ev, pe)

	if pe.IPAddress != "203.0.113.12" || pe.UserID != "carol" {
		t.Errorf("got IPAddress=%q UserID=%q", pe.IPAddress, pe.UserID)
	}
}

func TestExtractChannelCreateData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		"Variable_sip_network_ip": "203.0.113.13",
		"Variable_sip_from_user":  "dave",
		"Variable_sip_from_host":  "from.example",
		"Unique-ID":               "uuid-1234",
	})
	w.extractChannelCreateData(ev, pe)

	if pe.IPAddress != "203.0.113.13" {
		t.Errorf("IPAddress = %q", pe.IPAddress)
	}

	if pe.CallUUID != "uuid-1234" {
		t.Errorf("CallUUID = %q", pe.CallUUID)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()

	ev := makeEvent(map[string]string{
		"A": "",
		"B": "",
		"C": "found",
		"D": "later",
	})
	if got := firstNonEmpty(ev, "A", "B", "C", "D"); got != "found" {
		t.Errorf("firstNonEmpty = %q, want %q", got, "found")
	}

	if got := firstNonEmpty(ev, "X", "Y"); got != "" {
		t.Errorf("firstNonEmpty no match = %q, want empty", got)
	}
}

func TestEventPool_PutClears(t *testing.T) {
	t.Parallel()

	ep := NewEventPool()
	pe := ep.Get()
	pe.EventName = "CUSTOM"
	pe.EventSubclass = "sofia::register"
	pe.IPAddress = "203.0.113.30"
	pe.UserID = testUserAlice
	pe.Domain = "example"
	pe.Status = "Registered"
	pe.CallUUID = "uuid-x"
	pe.Headers["x"] = "y"
	ep.Put(pe)

	// Get returns a *ProcessedEvent. There's no guarantee it's the same one we
	// put back (sync.Pool may discard), but if the pool returns ours we expect
	// it cleared. We loop briefly to give Pool a chance to hand it back.
	for range 5 {
		got := ep.Get()
		if got.EventName != "" || got.UserID != "" || len(got.Headers) != 0 {
			t.Errorf("event from pool not cleared: %+v", got)
		}

		ep.Put(got)
	}
}

func TestHandleSuccessfulRegistration_AutoWhitelist(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	w.manager.securityManager.cfg.AutoWhitelistOnSuccess = true

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.IPAddress = "203.0.113.40"
	pe.UserID = testUserAlice
	pe.Domain = testDomain
	w.handleSuccessfulRegistration(pe)

	if !waitFor(func() bool {
		return w.manager.securityManager.IsIPWhitelisted("203.0.113.40")
	}) {
		t.Error("expected IP to be whitelisted after successful registration")
	}
}

func TestHandleSuccessfulRegistration_InvalidIP(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.IPAddress = "not-an-ip"
	pe.UserID = testUserAlice
	pe.Domain = testDomain
	// Should return without panicking and without enqueueing.
	w.handleSuccessfulRegistration(pe)
}

func TestHandleFailedRegistration_EnqueuesTracking(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.IPAddress = "203.0.113.41"
	pe.UserID = "victim"
	pe.Domain = testDomain
	w.handleFailedRegistration(pe)

	// The failed-attempt is enqueued; allow the worker time to drain.
	if !waitFor(func() bool {
		fa := w.manager.securityManager.GetFailedAttempts()
		_, ok := fa["203.0.113.41"]

		return ok
	}) {
		t.Error("expected failed-attempt record after handleFailedRegistration")
	}
}

func TestChooseWorkerCount(t *testing.T) {
	t.Parallel()
	// chooseWorkerCount uses runtime.NumCPU(); we can only verify bounds here.
	got := chooseWorkerCount()
	if got < eslMinWorkers || got > eslMaxWorkers {
		t.Errorf("chooseWorkerCount() = %d, expected in [%d, %d]", got, eslMinWorkers, eslMaxWorkers)
	}
}

// ----- Benchmarks -----

func BenchmarkEventPool_GetPut(b *testing.B) {
	ep := NewEventPool()

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		pe := ep.Get()
		ep.Put(pe)
	}
}

// BenchmarkEventPool_GetPut_Parallel measures the pool's behavior under
// concurrent use (the realistic case: N workers each Get/Put per event).
// sync.Pool has per-P caches, so contention should be minimal.
func BenchmarkEventPool_GetPut_Parallel(b *testing.B) {
	ep := NewEventPool()

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pe := ep.Get()
			ep.Put(pe)
		}
	})
}

func BenchmarkExtractRegistrationData(b *testing.B) {
	w := newTestWorker(b)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		"Network-Ip": "203.0.113.10",
		"From-User":  testUserAlice,
		"From-Host":  testDomain,
		"Status":     "Registered",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		w.extractRegistrationData(ev, pe)
	}
}

func BenchmarkFirstNonEmpty(b *testing.B) {
	ev := makeEvent(map[string]string{
		"A": "",
		"B": "",
		"C": "found",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = firstNonEmpty(ev, "A", "B", "C", "D")
	}
}

// BenchmarkProcessEventWithPool_Register exercises the full worker pipeline
// for a successful registration. Auto-whitelist and rate-limit-exceeded paths
// are disabled to isolate the dispatch cost.
func BenchmarkProcessEventWithPool_Register(b *testing.B) {
	silenceLogs(b)

	w := newTestWorker(b)
	w.manager.securityManager.cfg.AutoWhitelistOnSuccess = false
	w.manager.rateManager.cfg.RegistrationLimit = 1 << 30 // never exceed

	ev := makeEvent(map[string]string{
		"Event-Name":     "CUSTOM",
		"Event-Subclass": "sofia::register",
		"Network-Ip":     "203.0.113.50",
		"From-User":      testUserAlice,
		"From-Host":      testDomain,
		"Status":         "Registered",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		w.processEventWithPool(ev)
	}
}

// BenchmarkProcessEventWithPool_FailedRegister exercises the failed-
// registration path. Uses a fast drain on failedQueue (replacing the
// production batch worker) so the bench measures the producer side without
// queue-full noise.
func BenchmarkProcessEventWithPool_FailedRegister(b *testing.B) {
	silenceLogs(b)

	w := newTestWorker(b)
	stop := drainFailedQueue(w.manager.securityManager)
	b.Cleanup(stop)

	ev := makeEvent(map[string]string{
		"Event-Name":     "CUSTOM",
		"Event-Subclass": "sofia::register_failure",
		"Network-Ip":     "203.0.113.51",
		"To-User":        "victim",
		"To-Host":        "victim.example",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		w.processEventWithPool(ev)
	}
}

func BenchmarkProcessEventWithPool_ChannelCreate(b *testing.B) {
	silenceLogs(b)

	w := newTestWorker(b)
	w.manager.rateManager.cfg.CallRateLimit = 1 << 30

	ev := makeEvent(map[string]string{
		"Event-Name":              "CHANNEL_CREATE",
		"Variable_sip_network_ip": "203.0.113.52",
		"Variable_sip_from_user":  "caller",
		"Variable_sip_from_host":  "from.example",
		"Unique-ID":               "uuid-bench",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		w.processEventWithPool(ev)
	}
}

func BenchmarkComputeBackoff(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		_ = computeBackoff(time.Second, 60*time.Second, int64(i&7))
	}
}

func BenchmarkParseDurationOr(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = parseDurationOr("5m", 0)
	}
}

func BenchmarkCommandAllowed_Miss(b *testing.B) {
	allowed := []string{"status", "uptime", "version", "reload"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		_ = commandAllowed("hangup_call", allowed)
	}
}

// Concurrent EventPool to ensure hand-off works under contention.
func TestEventPool_Concurrent(t *testing.T) {
	t.Parallel()

	ep := NewEventPool()

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 1000 {
				pe := ep.Get()
				pe.IPAddress = "x"
				ep.Put(pe)
			}
		}()
	}

	wg.Wait()
}
