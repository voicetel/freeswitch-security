package main

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// Test fixtures shared across the ESL test cases.
const (
	testUserAlice = "alice"
	testUserBob   = "bob"
	testUserCarol = "carol"
	testUserDave  = "dave"

	// testInvalidIP is a deliberately unparsable address fixture.
	testInvalidIP = "not-an-ip"

	// testBogusValue fails any duration/level parsing on purpose.
	testBogusValue = "bogus"

	// testCmdStatus is the allowlisted ESL command used across tests.
	testCmdStatus  = "status"
	testCmdUptime  = "uptime"
	testCmdVersion = "version"

	// Victim/caller fixtures used by failed-registration and call tests.
	testUserVictim   = "victim"
	testDomainVictim = "victim.example"
	testDomainFrom   = "from.example"

	// Shared IP fixtures.
	testIPSample      = "203.0.113.10"
	testIPWhitelisted = "203.0.113.50"
	testIPBlacklisted = "203.0.113.51"

	// hdrStatus is the registration Status wire header.
	hdrStatus  = "Status"
	testDomain = defaultFreeSWITCHDomain

	// testESLPassword matches the default FreeSWITCH ESL password used by
	// the fake server and the managers wired against it.
	testESLPassword = "ClueCon"

	// testSpammer is the SIP From-user fixture used in channel-create events.
	testSpammer = "spammer"

	// statusRegistered is the registration Status header fixture.
	statusRegistered = "Registered"

	// evHeartbeat is an event type the workers deliberately ignore.
	evHeartbeat = "HEARTBEAT"

	// Wire header names used when composing fake FreeSWITCH events.
	hdrEventName     = "Event-Name"
	hdrEventSubclass = "Event-Subclass"
	hdrNetworkIP     = "Network-Ip"
	hdrFromUser      = "From-User"
	hdrFromHost      = "From-Host"
	hdrToUser        = "To-User"
	hdrToHost        = "To-Host"
	hdrWrongStateIP  = "Network_Ip"
	hdrWrongStateUsr = "From_User"
	hdrVarNetworkIP  = "Variable_sip_network_ip"
	hdrVarFromUser   = "Variable_sip_from_user"
	hdrVarFromHost   = "Variable_sip_from_host"
	hdrUniqueID      = "Unique-ID"
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
		hdrNetworkIP: testIPSample,
		hdrFromUser:  testUserAlice,
		hdrFromHost:  testDomain,
		hdrStatus:    statusRegistered,
	})
	w.extractRegistrationData(ev, pe)

	if pe.IPAddress != testIPSample {
		t.Errorf("IPAddress = %q", pe.IPAddress)
	}

	if pe.UserID != testUserAlice {
		t.Errorf("UserID = %q", pe.UserID)
	}

	if pe.Domain != testDomain {
		t.Errorf("Domain = %q", pe.Domain)
	}

	if pe.Status != statusRegistered {
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
		hdrNetworkIP:  testIPSample,
		"Username":    testUserBob,
		"Domain_Name": "fallback.example",
	})
	w.extractRegistrationData(ev, pe)

	if pe.UserID != testUserBob {
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
		hdrNetworkIP: "203.0.113.11",
		hdrToUser:    testUserVictim,
		hdrToHost:    testDomainVictim,
	})
	w.extractFailedRegistrationData(ev, pe)

	if pe.UserID != testUserVictim || pe.Domain != testDomainVictim {
		t.Errorf("got UserID=%q Domain=%q", pe.UserID, pe.Domain)
	}
}

func TestExtractWrongCallStateData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		hdrWrongStateIP:  "203.0.113.12",
		hdrWrongStateUsr: testUserCarol,
	})
	w.extractWrongCallStateData(ev, pe)

	if pe.IPAddress != "203.0.113.12" || pe.UserID != testUserCarol {
		t.Errorf("got IPAddress=%q UserID=%q", pe.IPAddress, pe.UserID)
	}
}

func TestExtractChannelCreateData(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	pe := w.manager.eventPool.Get()

	defer w.manager.eventPool.Put(pe)

	ev := makeEvent(map[string]string{
		hdrVarNetworkIP: "203.0.113.13",
		hdrVarFromUser:  testUserDave,
		hdrVarFromHost:  testDomainFrom,
		hdrUniqueID:     "uuid-1234",
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
	pe.EventName = eventNameCustom
	pe.EventSubclass = eventSubRegister
	pe.IPAddress = "203.0.113.30"
	pe.UserID = testUserAlice
	pe.Domain = "example"
	pe.Status = statusRegistered
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

	pe.IPAddress = testInvalidIP
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
	pe.UserID = testUserVictim
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
		hdrNetworkIP: testIPSample,
		hdrFromUser:  testUserAlice,
		hdrFromHost:  testDomain,
		hdrStatus:    statusRegistered,
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
		"C": "bench-hit",
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkString = firstNonEmpty(ev, "A", "B", "C", "D")
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
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: eventSubRegister,
		hdrNetworkIP:     testIPWhitelisted,
		hdrFromUser:      testUserAlice,
		hdrFromHost:      testDomain,
		hdrStatus:        statusRegistered,
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
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: eventSubRegisterFail,
		hdrNetworkIP:     testIPBlacklisted,
		hdrToUser:        testUserVictim,
		hdrToHost:        testDomainVictim,
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
		hdrEventName:    eventNameChannelCreate,
		hdrVarNetworkIP: "203.0.113.52",
		hdrVarFromUser:  "caller",
		hdrVarFromHost:  testDomainFrom,
		hdrUniqueID:     "uuid-bench",
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
		sinkDuration = computeBackoff(time.Second, 60*time.Second, int64(i&7))
	}
}

func BenchmarkParseDurationOr(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkDuration = parseDurationOr("5m", 0)
	}
}

func BenchmarkCommandAllowed_Miss(b *testing.B) {
	allowed := []string{testCmdStatus, testCmdUptime, testCmdVersion, "reload"}

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkBool = commandAllowed("hangup_call", allowed)
	}
}

// Concurrent EventPool to ensure hand-off works under contention.
func TestEventPool_Concurrent(t *testing.T) {
	t.Parallel()

	ep := NewEventPool()

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				pe := ep.Get()
				pe.IPAddress = "x"
				ep.Put(pe)
			}
		})
	}

	wg.Wait()
}

// ----- Handler edge cases -----

func TestHandleSuccessfulRegistration_EdgeCases(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	// Missing IP: early return.
	pe.IPAddress = ""
	w.handleSuccessfulRegistration(pe)

	// Empty user/domain fall back to defaults and the stats still update.
	pe.IPAddress = "203.0.113.140"
	pe.UserID = ""
	pe.Domain = ""
	w.handleSuccessfulRegistration(pe)

	if pe.UserID != unknownUser {
		t.Errorf("UserID = %q, want %q", pe.UserID, unknownUser)
	}

	if pe.Domain != GetConfig().FreeSWITCH.DefaultDomain {
		t.Errorf("Domain = %q, want default", pe.Domain)
	}

	if got := w.manager.securityManager.GetSecurityStats(); got.TotalRegistrations == 0 {
		t.Error("expected registration stats to be updated")
	}
}

func TestHandleSuccessfulRegistration_RateLimited(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	w.manager.rateManager.cfg.RegistrationLimit = 1
	// Auto-whitelist must stay off: whitelisting the IP on the first success
	// would let the second registration bypass the rate limit entirely.
	w.manager.securityManager.cfg.AutoWhitelistOnSuccess = false

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.IPAddress = "203.0.113.141"
	pe.UserID = testUserAlice
	pe.Domain = testDomain
	w.handleSuccessfulRegistration(pe)
	w.handleSuccessfulRegistration(pe) // second registration exceeds the limit

	// The rate-limited path returns before whitelisting; only the first
	// registration may have queued a whitelist entry.
	stats := w.manager.securityManager.GetSecurityStats()
	if stats.TotalRegistrations != 1 {
		t.Errorf("TotalRegistrations = %d, want 1 (second call rate-limited)", stats.TotalRegistrations)
	}
}

func TestHandleFailedRegistration_EdgeCases(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	// Missing IP: early return, nothing tracked.
	pe.IPAddress = ""
	w.handleFailedRegistration(pe)

	// Invalid IP: early return, nothing tracked.
	pe.IPAddress = "host.example"
	w.handleFailedRegistration(pe)

	if len(w.manager.securityManager.GetFailedAttempts()) != 0 {
		t.Error("invalid/missing IPs must not be tracked")
	}

	// Defaults applied for empty user and domain.
	pe.IPAddress = "203.0.113.142"
	pe.UserID = ""
	pe.Domain = ""
	w.handleFailedRegistration(pe)

	if pe.UserID != unknownUser || pe.Domain != GetConfig().FreeSWITCH.DefaultDomain {
		t.Errorf("defaults not applied: user=%q domain=%q", pe.UserID, pe.Domain)
	}
}

func TestHandleWrongCallState(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	// Missing and invalid IPs: early returns.
	pe.IPAddress = ""
	w.handleWrongCallState(pe)

	pe.IPAddress = testInvalidIP
	w.handleWrongCallState(pe)

	// Valid event with empty user gets the placeholder and is tracked.
	pe.IPAddress = "203.0.113.143"
	pe.UserID = ""
	w.handleWrongCallState(pe)

	if pe.UserID != unknownUser {
		t.Errorf("UserID = %q, want %q", pe.UserID, unknownUser)
	}

	if !waitFor(func() bool {
		_, ok := w.manager.securityManager.GetWrongCallStates()["203.0.113.143"]

		return ok
	}) {
		t.Error("expected wrong-call-state record")
	}
}

func TestHandleChannelCreate(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	w.manager.rateManager.cfg.CallRateLimit = 1

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	// Missing and invalid IPs: debug-and-return.
	pe.IPAddress = ""
	w.handleChannelCreate(pe)

	pe.IPAddress = testInvalidIP
	w.handleChannelCreate(pe)

	// First call allowed.
	pe.IPAddress = "203.0.113.144"
	pe.UserID = testUserAlice
	pe.Domain = testDomain
	pe.CallUUID = ""
	w.handleChannelCreate(pe)

	// Second call exceeds the limit; without a UUID nothing can be killed.
	w.handleChannelCreate(pe)

	// Third call exceeds with a UUID but the manager is not connected, so the
	// kill is skipped without touching a client.
	pe.CallUUID = "uuid-kill-me"
	w.handleChannelCreate(pe)
}

// TestWorkerPool_ProcessAndDrain runs real workers against the event queue and
// verifies both shutdown paths: context cancellation and queue close.
func TestWorkerPool_ProcessAndDrain(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	ctx, cancel := context.WithCancel(t.Context())
	em := &ESLManager{
		securityManager: sm,
		rateManager:     rm,
		queueSize:       16,
		workerCount:     2,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()

	em.dispatchEvent(makeEvent(map[string]string{
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: eventSubRegisterFail,
		hdrNetworkIP:     "203.0.113.145",
		hdrToUser:        testUserVictim,
		hdrToHost:        testDomainVictim,
	}))

	em.dispatchEvent(makeEvent(map[string]string{
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: "sofia::nonsense", // unhandled subclass branch
	}))

	em.dispatchEvent(makeEvent(map[string]string{
		hdrEventName: evHeartbeat, // unhandled event-type branch
	}))

	if !waitFor(func() bool { return em.statistics.EventsProcessed.Load() >= 3 }) {
		t.Fatal("workers did not process queued events")
	}

	// Closing the queue must end the workers (range loop termination).
	em.closeWorkerQueues()
	em.workersWg.Wait()
	cancel()
}

func TestWorkerPool_CloseEmptyQueue(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())

	ctx, cancel := context.WithCancel(t.Context())
	em := &ESLManager{
		securityManager: sm,
		rateManager:     rm,
		queueSize:       1,
		workerCount:     2,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()
	em.closeWorkerQueues() // workers exit when their queues close
	em.workersWg.Wait()
	cancel()
}

// TestProcessEventWithPool_Dispatch covers the dispatch arms not exercised
// through the live-connection tests (register, wrong_call_state, channel
// create, unknown subclass/type).
func TestProcessEventWithPool_Dispatch(t *testing.T) {
	t.Parallel()

	w := newTestWorker(t)
	w.manager.rateManager.cfg.CallRateLimit = 1 << 30
	w.manager.rateManager.cfg.RegistrationLimit = 1 << 30

	events := []*eventsocket.Event{
		makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubRegister,
			hdrNetworkIP:     "203.0.113.170",
			hdrFromUser:      testUserAlice,
			hdrFromHost:      testDomain,
			hdrStatus:        statusRegistered,
		}),
		makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubWrongCallState,
			hdrWrongStateIP:  "203.0.113.171",
			hdrWrongStateUsr: testUserCarol,
		}),
		makeEvent(map[string]string{
			hdrEventName:    eventNameChannelCreate,
			hdrVarNetworkIP: "203.0.113.172",
			hdrVarFromUser:  testUserDave,
			hdrVarFromHost:  testDomainFrom,
			hdrUniqueID:     "uuid-dispatch",
		}),
		makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: "sofia::unknown",
		}),
		makeEvent(map[string]string{
			hdrEventName: evHeartbeat,
		}),
	}
	for _, ev := range events {
		w.processEventWithPool(ev)
	}

	if got := w.manager.securityManager.GetSecurityStats(); got.TotalRegistrations != 1 {
		t.Errorf("TotalRegistrations = %d, want 1", got.TotalRegistrations)
	}

	if !waitFor(func() bool {
		_, ok := w.manager.securityManager.GetWrongCallStates()["203.0.113.171"]

		return ok
	}) {
		t.Error("wrong_call_state event not tracked")
	}
}

// TestEventPool_GetWrongTypeFallback verifies Get's defensive fallback when
// the pool hands back a foreign value.
func TestEventPool_GetWrongTypeFallback(t *testing.T) {
	t.Parallel()

	ep := NewEventPool()
	ep.pool.Put(&EventWorker{}) // wrong pointer type: not a *ProcessedEvent

	pe := ep.Get()
	if pe == nil || pe.Headers == nil {
		t.Error("Get must always return a usable ProcessedEvent")
	}
}

// TestHandleSuccessfulRegistration_WhitelistQueueFull drives the async-add
// drop branch: the whitelist queue is saturated, so the enqueue is dropped
// (logged) without ever blocking the worker.
func TestHandleSuccessfulRegistration_WhitelistQueueFull(t *testing.T) {
	t.Parallel()

	sm := newSaturatedSecurityManager()
	sm.cfg.AutoWhitelistOnSuccess = true
	sm.cfg.Enabled = true

	rm := newTestRateManager(t, sm, defaultTestRateConfig())
	em := &ESLManager{securityManager: sm, rateManager: rm, eventPool: NewEventPool()}
	w := &EventWorker{id: 1, manager: em, logger: GetLogger()}

	pe := em.eventPool.Get()
	defer em.eventPool.Put(pe)

	pe.IPAddress = "203.0.113.173"
	pe.UserID = testUserAlice
	pe.Domain = testDomain

	w.handleSuccessfulRegistration(pe) // must log the error, not panic

	if got := sm.GetSecurityStats(); got.TotalRegistrations != 1 {
		t.Errorf("TotalRegistrations = %d, want 1", got.TotalRegistrations)
	}
}

// TestVerboseLogging_Handlers re-runs representative handler paths at trace
// level so the debug/trace guard bodies execute. Not parallel: it raises the
// global logger level, which would make concurrent tests noisy.
//
//nolint:paralleltest // raises the global log level
func TestVerboseLogging_Handlers(t *testing.T) {
	logger := GetLogger()
	old := logger.GetLogLevel()
	logger.SetLogLevel(LogLevelTrace)

	defer logger.SetLogLevel(old)

	out := captureLog(t, func() {
		w := newTestWorker(t)
		// newTestWorker resets the level; raise it again for the guards.
		logger.SetLogLevel(LogLevelTrace)

		w.manager.rateManager.cfg.CallRateLimit = 1 << 30

		w.processEventWithPool(makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubRegisterFail,
			hdrNetworkIP:     "203.0.113.174",
			hdrToUser:        testUserVictim,
			hdrToHost:        testDomainVictim,
		}))
		w.processEventWithPool(makeEvent(map[string]string{
			hdrEventName:    eventNameChannelCreate,
			hdrVarNetworkIP: "203.0.113.175",
			hdrVarFromUser:  testUserDave,
		}))

		// Successful registration (debug + success-info guards).
		w.processEventWithPool(makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubRegister,
			hdrNetworkIP:     "203.0.113.176",
			hdrFromUser:      testUserAlice,
			hdrFromHost:      testDomain,
			hdrStatus:        statusRegistered,
		}))

		// Wrong call state (info guard).
		w.processEventWithPool(makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubWrongCallState,
			hdrWrongStateIP:  "203.0.113.177",
			hdrWrongStateUsr: testUserCarol,
		}))

		// Rate-limited registration and call (blocked-info guards).
		w.manager.rateManager.cfg.RegistrationLimit = 1
		w.manager.rateManager.cfg.CallRateLimit = 1

		regEvent := makeEvent(map[string]string{
			hdrEventName:     eventNameCustom,
			hdrEventSubclass: eventSubRegister,
			hdrNetworkIP:     "203.0.113.178",
			hdrFromUser:      testUserAlice,
			hdrFromHost:      testDomain,
		})
		w.processEventWithPool(regEvent)
		w.processEventWithPool(regEvent) // second one exceeds the limit

		callEvent := makeEvent(map[string]string{
			hdrEventName:    eventNameChannelCreate,
			hdrVarNetworkIP: "203.0.113.179",
			hdrVarFromUser:  testUserDave,
		})
		w.processEventWithPool(callEvent)
		w.processEventWithPool(callEvent) // second one exceeds the limit

		pe := w.manager.eventPool.Get()
		defer w.manager.eventPool.Put(pe)

		pe.IPAddress = ""
		w.handleChannelCreate(pe)

		pe.IPAddress = testInvalidIP
		w.handleChannelCreate(pe)
	})

	for _, want := range []string{"[ESL TRACE]", "[ESL DEBUG]"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s output at trace level", want)
		}
	}
}

func TestWorkerCountFor(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want int }{
		{0, eslMinWorkers},
		{1, eslMinWorkers},
		{2, 2},
		{4, 4},
		{eslMaxWorkers, eslMaxWorkers},
		{64, eslMaxWorkers},
	}
	for _, c := range cases {
		if got := workerCountFor(c.in); got != c.want {
			t.Errorf("workerCountFor(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestEventPool_GetForeignNewFallback(t *testing.T) {
	t.Parallel()

	// A pool whose New yields a foreign type deterministically drives Get's
	// defensive fallback branch.
	ep := &EventPool{pool: sync.Pool{New: func() any { return "junk" }}}

	pe := ep.Get()
	if pe == nil || pe.Headers == nil {
		t.Fatal("fallback must return a usable ProcessedEvent")
	}
}

func TestEslLogLevelFromString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in     string
		want   EslLogLevel
		wantOK bool
	}{
		{logLevelErrorStr, LogLevelError, true},
		{logLevelInfoStr, LogLevelInfo, true},
		{logLevelDebugStr, LogLevelDebug, true},
		{logLevelTraceStr, LogLevelTrace, true},
		{testBogusValue, LogLevelInfo, false},
		{"", LogLevelInfo, false},
	}
	for _, c := range cases {
		got, ok := eslLogLevelFromString(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("eslLogLevelFromString(%q) = (%d, %v), want (%d, %v)",
				c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestHandleSuccessfulRegistration_RefreshFastPath verifies a re-registration
// from an already-whitelisted IP refreshes the entry in place instead of
// queueing another whitelist request.
func TestHandleSuccessfulRegistration_RefreshFastPath(t *testing.T) {
	t.Parallel()
	w := newTestWorker(t)
	w.manager.securityManager.cfg.AutoWhitelistOnSuccess = true

	sm := w.manager.securityManager
	stale := time.Now().Add(-time.Hour)

	sm.mu.Lock()
	sm.whitelist["203.0.113.243"] = WhitelistEntry{
		IP: "203.0.113.243", ExpiresAt: time.Now().Add(time.Minute), LastSeen: stale,
	}
	sm.mu.Unlock()

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.IPAddress = "203.0.113.243"
	pe.UserID = testUserAlice
	pe.Domain = testDomain
	w.handleSuccessfulRegistration(pe)

	entry, ok := sm.GetWhitelistEntry("203.0.113.243")
	if !ok {
		t.Fatal("entry missing after re-registration")
	}

	if !entry.LastSeen.After(stale) {
		t.Error("re-registration must refresh LastSeen in place")
	}

	if len(sm.whitelistQueue) != 0 {
		t.Error("re-registration must not enqueue a whitelist request")
	}
}
