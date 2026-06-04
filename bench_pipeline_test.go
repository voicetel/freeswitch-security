package main

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// Pipeline benchmark shape. The mix mirrors a busy production FreeSWITCH box:
// mostly successful re-registrations from a stable population of endpoints, a
// steady trickle of new calls, a small set of attacker IPs hammering failed
// registrations, and occasional wrong-call-state events.
const (
	// pipelineWorkers is fixed (rather than chooseWorkerCount) so profiles
	// and numbers are comparable across machines.
	pipelineWorkers = 4

	// pipelineEventVariety is the size of the pre-built event set the
	// benchmark cycles through; large enough that counters and rate windows
	// see realistic key diversity.
	pipelineEventVariety = 4096

	// pipelineLegitIPs and pipelineAttackerIPs size the two IP populations.
	pipelineLegitIPs    = 256
	pipelineAttackerIPs = 32

	// hostsPerOctet keeps generated dotted-quad octets in range.
	hostsPerOctet = 250

	// Traffic mix per pipelineMixTotal events:
	// 14 registrations (70%), 3 calls (15%), 2 failed registrations (10%),
	// 1 wrong call state (5%).
	pipelineMixTotal    = 20
	pipelineMixRegister = 14
	pipelineMixCall     = 3
	pipelineMixFailed   = 2
)

// buildPipelineEvents returns a deterministic, production-shaped event set.
func buildPipelineEvents(n int) []*eventsocket.Event {
	events := make([]*eventsocket.Event, 0, n)

	for i := range n {
		legit := i % pipelineLegitIPs
		legitIP := fmt.Sprintf("198.51.%d.%d", legit/hostsPerOctet, legit%hostsPerOctet)
		attackerIP := fmt.Sprintf("203.0.115.%d", i%pipelineAttackerIPs)
		user := fmt.Sprintf("user%d", legit)

		var ev *eventsocket.Event

		bucket := i % pipelineMixTotal

		switch {
		case bucket < pipelineMixRegister:
			ev = makeEvent(map[string]string{
				hdrEventName:     eventNameCustom,
				hdrEventSubclass: eventSubRegister,
				hdrNetworkIP:     legitIP,
				hdrFromUser:      user,
				hdrFromHost:      testDomain,
				hdrStatus:        statusRegistered,
			})
		case bucket < pipelineMixRegister+pipelineMixCall:
			ev = makeEvent(map[string]string{
				hdrEventName:    eventNameChannelCreate,
				hdrVarNetworkIP: legitIP,
				hdrVarFromUser:  user,
				hdrVarFromHost:  testDomain,
				hdrUniqueID:     fmt.Sprintf("uuid-pipeline-%d", i),
			})
		case bucket < pipelineMixRegister+pipelineMixCall+pipelineMixFailed:
			ev = makeEvent(map[string]string{
				hdrEventName:     eventNameCustom,
				hdrEventSubclass: eventSubRegisterFail,
				hdrNetworkIP:     attackerIP,
				hdrToUser:        testUserVictim,
				hdrToHost:        testDomainVictim,
			})
		default:
			ev = makeEvent(map[string]string{
				hdrEventName:     eventNameCustom,
				hdrEventSubclass: eventSubWrongCallState,
				hdrWrongStateIP:  attackerIP,
				hdrWrongStateUsr: user,
			})
		}

		events = append(events, ev)
	}

	return events
}

// BenchmarkEventPipeline_RealisticMix measures the full production event path
// — queue → worker pool → rate manager → security manager with its batch
// drainers running — under a deterministic, production-shaped traffic mix.
// Unlike the per-function microbenchmarks, this is the benchmark to attach
// the profiler to when asking where a busy node actually spends its time.
// ns/op is the pipeline cost per event at 4-way worker concurrency.
//
// Auto-whitelist stays off here: handleSuccessfulRegistration performs a
// synchronous whitelist round-trip that flushes on a 100ms ticker, so with it
// enabled the pipeline measures ticker latency rather than processing cost.
// BenchmarkRegistrationAutoWhitelist reports that latency separately.
func BenchmarkEventPipeline_RealisticMix(b *testing.B) {
	silenceLogs(b)

	sm := newTestSecurityManager(b)

	cfg := defaultTestRateConfig()
	cfg.CallRateLimit = 20     // production default
	cfg.RegistrationLimit = 10 // production default
	rm := newTestRateManager(b, sm, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	em := &ESLManager{
		securityManager: sm,
		rateManager:     rm,
		eventQueue:      make(chan *eventsocket.Event, eslEventQueueSize),
		workerCount:     pipelineWorkers,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()
	b.Cleanup(func() {
		cancel()
		close(em.eventQueue)
		em.workersWg.Wait()
	})

	events := buildPipelineEvents(pipelineEventVariety)
	processedStart := em.statistics.EventsProcessed.Load()

	b.ReportAllocs()
	b.ResetTimer()

	for i := range b.N {
		em.eventQueue <- events[i%pipelineEventVariety]
	}

	// Throughput includes the drain: the pipeline is done when the workers
	// have processed every queued event.
	for em.statistics.EventsProcessed.Load()-processedStart < int64(b.N) {
		runtime.Gosched()
	}
}

// BenchmarkRegistrationAutoWhitelist measures the end-to-end cost of one
// successful registration with auto-whitelist enabled (the production
// default). Historically this measured ~100ms/op: the worker blocked on a
// synchronous whitelist round-trip gated by the 100ms batch ticker. The fix
// (in-place refresh for known IPs, fire-and-forget for new ones) brings it to
// nanoseconds; this benchmark is the canary that the stall stays gone.
func BenchmarkRegistrationAutoWhitelist(b *testing.B) {
	silenceLogs(b)

	w := newTestWorker(b)
	w.manager.securityManager.cfg.AutoWhitelistOnSuccess = true
	w.manager.rateManager.cfg.RegistrationLimit = 1 << 30

	ev := makeEvent(map[string]string{
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: eventSubRegister,
		hdrNetworkIP:     "198.51.99.1",
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
