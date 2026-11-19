package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// CVE guard test fixtures.
const (
	testCVEAttackerIP    = "203.0.113.200"
	testCVEAttackerUser  = "attacker"
	testCVEExploitToUser = "api+system%20id"
	testCVESystemCmd     = "system id"

	// cveVersionOutput is the shape the `version` API returns.
	cveVersionOutput = "FreeSWITCH Version 1.11.2 -release 64bit (git-1234567)"

	// testFSReady is the fake server's standby API body.
	testFSReady = "FreeSWITCH is ready"
)

func TestParseFreeSWITCHVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		in        string
		wantMajor int
		wantMinor int
		wantPatch int
		wantOK    bool
	}{
		{name: "release string", in: cveVersionOutput, wantMajor: 1, wantMinor: 11, wantPatch: 2, wantOK: true},
		{name: "release build", in: "FreeSWITCH Version 1.10.7-release-64bit", wantMajor: 1, wantMinor: 10, wantPatch: 7, wantOK: true},
		{name: "bare version", in: "FreeSWITCH Version 1.11.3", wantMajor: 1, wantMinor: 11, wantPatch: 3, wantOK: true},
		{name: "no version", in: testFSReady, wantOK: false},
		{name: "two part", in: "FreeSWITCH Version 1.11", wantOK: false},
		{name: "non numeric", in: "FreeSWITCH Version x.y.z", wantOK: false},
		{name: "empty", in: "", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			major, minor, patch, ok := parseFreeSWITCHVersion(tc.in)
			if ok != tc.wantOK || major != tc.wantMajor || minor != tc.wantMinor || patch != tc.wantPatch {
				t.Errorf("parseFreeSWITCHVersion(%q) = (%d, %d, %d, %v), want (%d, %d, %d, %v)",
					tc.in, major, minor, patch, ok, tc.wantMajor, tc.wantMinor, tc.wantPatch, tc.wantOK)
			}
		})
	}
}

func TestVulnerableCVEsForVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		major      int
		minor      int
		patch      int
		wantHas    string
		wantHasNot string
		wantEmpty  bool
	}{
		{
			name:  "1.10.x is vulnerable to everything",
			major: 1, minor: 10, patch: 12,
			wantHas: cve116779ID, wantHasNot: "",
		},
		{
			name:  "1.11.2 still has the MESSAGE RCE",
			major: 1, minor: 11, patch: 2,
			wantHas: cve116779ID, wantHasNot: cve116786ID,
		},
		{name: "1.11.3 is clean", major: 1, minor: 11, patch: 3, wantEmpty: true},
		{name: "future releases are clean", major: 2, minor: 0, patch: 0, wantEmpty: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := vulnerableCVEsForVersion(tc.major, tc.minor, tc.patch)
			if tc.wantEmpty {
				if len(got) != 0 {
					t.Errorf("vulnerableCVEsForVersion(%d.%d.%d) = %v, want empty", tc.major, tc.minor, tc.patch, got)
				}

				return
			}

			if !slices.Contains(got, tc.wantHas) {
				t.Errorf("vulnerableCVEsForVersion(%d.%d.%d) = %v, missing %s", tc.major, tc.minor, tc.patch, got, tc.wantHas)
			}

			if tc.wantHasNot != "" && slices.Contains(got, tc.wantHasNot) {
				t.Errorf("vulnerableCVEsForVersion(%d.%d.%d) = %v, must not contain %s", tc.major, tc.minor, tc.patch, got, tc.wantHasNot)
			}
		})
	}
}

func TestCVE116779MessageMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		headers  map[string]string
		wantOK   bool
		wantIP   string
		wantUser string
	}{
		{
			name: "exploit to_user",
			headers: map[string]string{
				hdrMESSAGEToUser:    testCVEExploitToUser,
				hdrMESSAGEFromSIPIP: testCVEAttackerIP,
				hdrMESSAGEFromUser:  testCVEAttackerUser,
			},
			wantOK: true, wantIP: testCVEAttackerIP, wantUser: testCVEAttackerUser,
		},
		{
			name: "exploit probe uppercase",
			headers: map[string]string{
				hdrMESSAGEToUser:    "API+version",
				hdrMESSAGEFromSIPIP: testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "marker on full To header only",
			headers: map[string]string{
				hdrMESSAGETo:        "api+version@example.com",
				hdrMESSAGEFromSIPIP: testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "lowercase keys are canonicalized on the wire (never seen)",
			headers: map[string]string{
				"to_user":     "api+version",
				"from_sip_ip": testCVEAttackerIP,
			},
			wantOK: false,
		},
		{
			name: "benign message",
			headers: map[string]string{
				hdrMESSAGEToUser:    "1019",
				hdrMESSAGEFromSIPIP: testCVEAttackerIP,
			},
			wantOK: false,
		},
		{
			name: "api user without plus",
			headers: map[string]string{
				hdrMESSAGEToUser:    "api",
				hdrMESSAGEFromSIPIP: testCVEAttackerIP,
			},
			wantOK: false,
		},
		{
			name: "missing source ip",
			headers: map[string]string{
				hdrMESSAGEToUser: "api+system",
			},
			wantOK: false,
		},
		{
			name: "invalid source ip",
			headers: map[string]string{
				hdrMESSAGEToUser:    "api+system",
				hdrMESSAGEFromSIPIP: testInvalidIP,
			},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ip, user, ok := cve116779MessageMatch(makeEvent(tc.headers))
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}

			if ip != tc.wantIP || user != tc.wantUser {
				t.Errorf("(ip, user) = (%q, %q), want (%q, %q)", ip, user, tc.wantIP, tc.wantUser)
			}
		})
	}
}

func TestCVE116786ChannelCreateMatch(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		headers  map[string]string
		wantOK   bool
		wantIP   string
		wantUser string
	}{
		{
			name: "injected execute_on_originate",
			headers: map[string]string{
				hdrVarExecuteOnOriginate: testCVESystemCmd,
				hdrVarNetworkIP:          testCVEAttackerIP,
				hdrVarFromUser:           testCVEAttackerUser,
			},
			wantOK: true, wantIP: testCVEAttackerIP, wantUser: testCVEAttackerUser,
		},
		{
			name: "bare system application",
			headers: map[string]string{
				hdrVarExecuteOnOriginate: "system",
				hdrVarNetworkIP:          testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "raw sip_invite_params injection",
			headers: map[string]string{
				hdrVarSIPInviteParams: "answer=true,execute_on_originate=system id",
				hdrVarNetworkIP:       testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "api_hangup_hook injection",
			headers: map[string]string{
				hdrVarSIPInviteParams: "x,api_hangup_hook=system id",
				hdrVarNetworkIP:       testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "case insensitive",
			headers: map[string]string{
				hdrVarExecuteOnOriginate: "System id",
				hdrVarNetworkIP:          testCVEAttackerIP,
			},
			wantOK: true, wantIP: testCVEAttackerIP,
		},
		{
			name: "clean channel",
			headers: map[string]string{
				hdrVarExecuteOnOriginate: "playback welcome",
				hdrVarSIPInviteParams:    "answer=true",
				hdrVarNetworkIP:          testCVEAttackerIP,
			},
			wantOK: false,
		},
		{
			name: "no variables",
			headers: map[string]string{
				hdrVarNetworkIP: testCVEAttackerIP,
			},
			wantOK: false,
		},
		{
			name: "missing source ip",
			headers: map[string]string{
				hdrVarExecuteOnOriginate: testCVESystemCmd,
			},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ip, user, ok := cve116786ChannelCreateMatch(makeEvent(tc.headers))
			if ok != tc.wantOK {
				t.Errorf("ok = %v, want %v", ok, tc.wantOK)
			}

			if ip != tc.wantIP || user != tc.wantUser {
				t.Errorf("(ip, user) = (%q, %q), want (%q, %q)", ip, user, tc.wantIP, tc.wantUser)
			}
		})
	}
}

func TestBlockIPImmediate(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	reason := "CVE test reason"

	if !sm.BlockIPImmediate(testCVEAttackerIP, reason, testCVEAttackerUser) {
		t.Fatal("expected the first CVE block to be applied")
	}

	if !sm.IsIPBlacklisted(testCVEAttackerIP) {
		t.Error("expected the IP to be blacklisted")
	}

	entry, ok := sm.GetBlacklistEntry(testCVEAttackerIP)
	if !ok || entry.Reason != reason {
		t.Errorf("entry = %+v (ok=%v), want reason %q", entry, ok, reason)
	}

	if got := sm.GetSecurityStats().CVEBlocks; got != 1 {
		t.Errorf("CVEBlocks = %d, want 1", got)
	}

	// A repeat attempt must be a no-op: no double-count, no expiry churn.
	if sm.BlockIPImmediate(testCVEAttackerIP, reason, testCVEAttackerUser) {
		t.Error("expected the second block of the same IP to be a no-op")
	}

	if got := sm.GetSecurityStats().CVEBlocks; got != 1 {
		t.Errorf("CVEBlocks after repeat = %d, want 1", got)
	}

	// Whitelisted and trusted-network IPs are never banned.
	whitelistedIP := "203.0.113.201"

	err := sm.AddToWhitelist(whitelistedIP, testUserAlice, testDomain, false)
	if err != nil {
		t.Fatalf("AddToWhitelist: %v", err)
	}

	if sm.BlockIPImmediate(whitelistedIP, reason, "") {
		t.Error("whitelisted IP must not be blocked")
	}

	if sm.BlockIPImmediate(testSampleIP, reason, "") {
		t.Error("trusted-network IP must not be blocked")
	}

	// Malformed IPs are rejected outright.
	if sm.BlockIPImmediate(testInvalidIP, reason, "") {
		t.Error("invalid IP must not be blocked")
	}
}

func TestBlockIPImmediate_EnforcesIPSetAndReports(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.cfg.AutoBlockEnabled = true

	// recordingRunner is not concurrency-safe; the manager's drainers are
	// idle here (no queued requests, cleanup tick is 10m away), so the only
	// ipset traffic is the synchronous BlockIPImmediate call below.
	recorder := &recordingRunner{}
	sm.ipset = newTestManager(recorder)

	sm.BlockIPImmediate(testCVEAttackerIP, "CVE-2026-116779 test", testCVEAttackerUser)

	// CVEBlockDuration is 1h in the test fixture → ipset timeout 3600.
	call, found := recorder.findCall("add fs-test " + testCVEAttackerIP + " timeout 3600")
	if !found {
		t.Errorf("expected an ipset add with the CVE block TTL, got calls: %v", recorder.calls)
	}

	if !strings.Contains(call, "-exist") {
		t.Errorf("ipset add must be idempotent (-exist): %s", call)
	}
}

func TestHandleCVEMessageEvent_Bans(t *testing.T) {
	t.Parallel()

	w := newTestWorker(t)
	w.manager.cveProtectionEnabled = true

	w.processEventWithPool(makeEvent(map[string]string{
		hdrEventName:        eventNameMessage,
		hdrMESSAGEToUser:    testCVEExploitToUser,
		hdrMESSAGEFromSIPIP: "203.0.113.210",
		hdrMESSAGEFromUser:  testCVEAttackerUser,
	}))

	if !w.manager.securityManager.IsIPBlacklisted("203.0.113.210") {
		t.Error("expected the exploit MESSAGE source to be blacklisted immediately")
	}

	// A benign MESSAGE must not ban anyone.
	w.processEventWithPool(makeEvent(map[string]string{
		hdrEventName:        eventNameMessage,
		hdrMESSAGEToUser:    "1019",
		hdrMESSAGEFromSIPIP: "203.0.113.211",
	}))

	if w.manager.securityManager.IsIPBlacklisted("203.0.113.211") {
		t.Error("benign MESSAGE must not blacklist the source")
	}
}

func TestHandleCVEMessageEvent_DisabledIsNoOp(t *testing.T) {
	t.Parallel()

	w := newTestWorker(t)
	w.manager.cveProtectionEnabled = false

	w.processEventWithPool(makeEvent(map[string]string{
		hdrEventName:        eventNameMessage,
		hdrMESSAGEToUser:    testCVEExploitToUser,
		hdrMESSAGEFromSIPIP: "203.0.113.212",
	}))

	if w.manager.securityManager.IsIPBlacklisted("203.0.113.212") {
		t.Error("disabled CVE guard must not blacklist anyone")
	}
}

// TestCVEChannelCreateGuard_BansAndTerminates runs the CHANNEL_CREATE arm
// end-to-end through a live (fake) ESL connection: the injected
// execute_on_originate is detected, the source IP is blacklisted, and the
// channel is torn down via uuid_kill.
func TestCVEChannelCreateGuard_BansAndTerminates(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 16)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	srv.sendEvent(map[string]string{
		hdrEventName:             eventNameChannelCreate,
		hdrVarNetworkIP:          "203.0.113.220",
		hdrVarFromUser:           testSpammer,
		hdrVarExecuteOnOriginate: testCVESystemCmd,
		hdrUniqueID:              "uuid-cve-1",
	})

	if !waitFor(func() bool { return srv.commandSeen("uuid_kill uuid-cve-1") }) {
		t.Error("expected the injected channel to be killed via uuid_kill")
	}

	if !waitFor(func() bool { return em.securityManager.IsIPBlacklisted("203.0.113.220") }) {
		t.Error("expected the injected channel's source IP to be blacklisted")
	}
}

func TestCVEChannelCreateGuard_IgnoresCleanChannels(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 16)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	srv.sendEvent(map[string]string{
		hdrEventName:    eventNameChannelCreate,
		hdrVarNetworkIP: "203.0.113.221",
		hdrVarFromUser:  testSpammer,
		hdrUniqueID:     "uuid-cve-2",
	})

	if !waitFor(func() bool { return em.statistics.EventsProcessed.Load() >= 1 }) {
		t.Fatal("clean channel create was not processed")
	}

	if srv.commandSeen("uuid_kill uuid-cve-2") {
		t.Error("clean channel must not be killed")
	}

	if em.securityManager.IsIPBlacklisted("203.0.113.221") {
		t.Error("clean channel source must not be blacklisted")
	}
}

// TestESLManager_VersionCheck runs the connect-time version fingerprint
// against a fake server that answers `api version` with a 1.11.2 release.
func TestESLManager_VersionCheck(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.apiBody = cveVersionOutput

	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	if !waitFor(func() bool { return em.GetESLStats()["freeswitchVersion"] == "1.11.2" }) {
		t.Fatal("version fingerprint was not recorded")
	}

	stats := em.GetESLStats()
	vulnerable, _ := stats["freeswitchVulnerableTo"].([]string)

	if !slices.Contains(vulnerable, cve116779ID) {
		t.Errorf("1.11.2 must be flagged vulnerable to %s, got %v", cve116779ID, vulnerable)
	}

	if slices.Contains(vulnerable, cve116786ID) {
		t.Errorf("1.11.2 must not be flagged vulnerable to %s (fixed in 1.11.2), got %v", cve116786ID, vulnerable)
	}

	if stats["cveProtectionEnabled"] != true {
		t.Error("cveProtectionEnabled must be reported in ESL stats")
	}
}

// TestESLManager_VersionCheck_Clean covers the patched-version arm: a 1.11.3
// fingerprint records no vulnerable CVEs.
func TestESLManager_VersionCheck_Clean(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.apiBody = "FreeSWITCH Version 1.11.3 -release 64bit (git-fedcba98)"

	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	if !waitFor(func() bool { return em.GetESLStats()["freeswitchVersion"] == "1.11.3" }) {
		t.Fatal("version fingerprint was not recorded")
	}

	vulnerable, _ := em.GetESLStats()["freeswitchVulnerableTo"].([]string)
	if len(vulnerable) != 0 {
		t.Errorf("1.11.3 must not be flagged vulnerable, got %v", vulnerable)
	}
}

func TestESLManager_VersionCheck_Unparsable(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.apiBody = testFSReady

	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	if em.GetESLStats()["freeswitchVersion"] != "" {
		t.Error("an unparsable version reply must leave the fingerprint empty")
	}
}

// TestESLManager_VersionCheck_SendError drives the version check's send-failure
// branch: every command is rejected by the fake server, so the fingerprint is
// left empty without disturbing the connection.
func TestESLManager_VersionCheck_SendError(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.replyError = true

	client, err := eventsocket.Dial(srv.ln.Addr().String(), testESLPassword)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { client.Close() })

	em := &ESLManager{eslDisconnected: make(chan bool, 1)}
	em.eslClient = client
	em.connected.Store(true)

	em.checkFreeSWITCHVersion(client) // send is rejected; must not panic

	if em.GetESLStats()["freeswitchVersion"] != "" {
		t.Error("a failed version query must leave the fingerprint empty")
	}
}

// TestBlockCVESource_DefensiveBranches covers the invalid-IP and nil-manager
// guards: a CVE event that somehow loses its source IP, or a worker without a
// security manager, must degrade to a log line instead of a ban or a panic.
func TestBlockCVESource_DefensiveBranches(t *testing.T) {
	t.Parallel()

	w := newTestWorker(t)
	w.blockCVESource(testInvalidIP, testCVEAttackerUser, "reason") // invalid IP

	w.manager.securityManager = nil
	w.blockCVESource(testCVEAttackerIP, testCVEAttackerUser, "reason") // nil manager
}

// ----- Benchmarks -----

func BenchmarkCVEMessageMatch_Clean(b *testing.B) {
	ev := makeEvent(map[string]string{
		hdrMESSAGEToUser:    "1019",
		hdrMESSAGEFromSIPIP: testCVEAttackerIP,
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ip, user, ok := cve116779MessageMatch(ev)
		sinkString, sinkString, sinkBool = ip, user, ok
	}
}

func BenchmarkCVEMessageMatch_Exploit(b *testing.B) {
	ev := makeEvent(map[string]string{
		hdrMESSAGEToUser:    testCVEExploitToUser,
		hdrMESSAGEFromSIPIP: testCVEAttackerIP,
		hdrMESSAGEFromUser:  testCVEAttackerUser,
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ip, user, ok := cve116779MessageMatch(ev)
		sinkString, sinkString, sinkBool = ip, user, ok
	}
}

func BenchmarkCVEChannelCreateMatch_Clean(b *testing.B) {
	ev := makeEvent(map[string]string{
		hdrVarNetworkIP: testCVEAttackerIP,
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ip, user, ok := cve116786ChannelCreateMatch(ev)
		sinkString, sinkString, sinkBool = ip, user, ok
	}
}

func BenchmarkCVEChannelCreateMatch_Exploit(b *testing.B) {
	ev := makeEvent(map[string]string{
		hdrVarExecuteOnOriginate: testCVESystemCmd,
		hdrVarNetworkIP:          testCVEAttackerIP,
	})

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		ip, user, ok := cve116786ChannelCreateMatch(ev)
		sinkString, sinkString, sinkBool = ip, user, ok
	}
}

// BenchmarkCVEChannelCreateGuardOn_ChannelCreate measures the worker pipeline
// cost of the CVE guard's clean (no-match) path on every CHANNEL_CREATE
// event: the protection flag is on, the channel variables are benign.
func BenchmarkCVEChannelCreateGuardOn_ChannelCreate(b *testing.B) {
	silenceLogs(b)

	w := newTestWorker(b)
	w.manager.cveProtectionEnabled = true
	w.manager.rateManager.cfg.CallRateLimit = 1 << 30

	ev := makeEvent(map[string]string{
		hdrEventName:    eventNameChannelCreate,
		hdrVarNetworkIP: testCVEAttackerIP,
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

func BenchmarkBlockIPImmediate_AlreadyBanned(b *testing.B) {
	sm := newTestSecurityManager(b)
	sm.BlockIPImmediate(testCVEAttackerIP, "bench", "")

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		sinkBool = sm.BlockIPImmediate(testCVEAttackerIP, "bench", "")
	}
}

func BenchmarkParseFreeSWITCHVersion(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		major, minor, patch, ok := parseFreeSWITCHVersion(cveVersionOutput)

		sinkBool = ok

		if ok {
			sinkInt = major + minor + patch
		}
	}
}
