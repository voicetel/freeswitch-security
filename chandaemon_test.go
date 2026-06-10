package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Repeated literals used across the chanDaemon tests, hoisted to satisfy goconst
// and keep the fixtures in one place.
const (
	testMutatePath     = "/mutate"
	testDisallowedAddr = "8.8.8.8:5000"
	testChanDaemonNode = "104.225.13.77"
)

// ---------------------------------------------------------------------------
// allow-list
// ---------------------------------------------------------------------------

func TestParseAllowedIPs(t *testing.T) {
	t.Parallel()

	t.Run("empty is nil", func(t *testing.T) {
		t.Parallel()

		list, err := parseAllowedIPs(nil)
		if err != nil || !list.Empty() {
			t.Errorf("nil input: list=%v err=%v, want empty/nil", list, err)
		}

		list, err = parseAllowedIPs([]string{"", "  "})
		if err != nil || !list.Empty() {
			t.Errorf("blank input: list=%v err=%v, want empty/nil", list, err)
		}
	})

	t.Run("bare IP and CIDR", func(t *testing.T) {
		t.Parallel()

		list, err := parseAllowedIPs([]string{testLoopbackIP, testTrustedCIDR, defaultLoopbackIPv6})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}

		for _, ok := range []string{testLoopbackIP, testSampleIP, defaultLoopbackIPv6} {
			if !list.Contains(ok) {
				t.Errorf("expected %s allowed", ok)
			}
		}

		for _, no := range []string{"8.8.8.8", "11.0.0.1"} {
			if list.Contains(no) {
				t.Errorf("expected %s denied", no)
			}
		}
	})

	t.Run("invalid entries are reported but valid ones kept", func(t *testing.T) {
		t.Parallel()

		list, err := parseAllowedIPs([]string{testLoopbackIP, testInvalidIP, "10.0.0.0/99"})
		if !errors.Is(err, ErrInvalidAllowEntry) {
			t.Errorf("err = %v, want ErrInvalidAllowEntry", err)
		}

		if list == nil || !list.Contains(testLoopbackIP) {
			t.Error("valid entry must survive alongside invalid ones")
		}
	})

	t.Run("all-invalid yields nil list", func(t *testing.T) {
		t.Parallel()

		list, err := parseAllowedIPs([]string{"bogus"})
		if !errors.Is(err, ErrInvalidAllowEntry) {
			t.Errorf("err = %v, want ErrInvalidAllowEntry", err)
		}

		if !list.Empty() {
			t.Error("a list with only invalid entries must be empty")
		}
	})
}

func TestIPAllowListContains_NilAndUnparseable(t *testing.T) {
	t.Parallel()

	var nilList *ipAllowList
	if nilList.Contains(testLoopbackIP) {
		t.Error("nil list must not contain anything")
	}

	list, _ := parseAllowedIPs([]string{testLoopbackIP})
	if list.Contains(testInvalidIP) {
		t.Error("unparseable host must not match")
	}
}

// allowRouter builds a tiny engine guarded by the allow-list, with a GET and a
// DELETE that both 200 when reached.
func allowRouter(entries []string) *gin.Engine {
	list, _ := parseAllowedIPs(entries)
	r := gin.New()
	r.Use(allowListMiddleware(list))
	r.GET("/read", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })
	r.DELETE(testMutatePath, func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"ok": true}) })

	return r
}

func reqFrom(method, url, remoteAddr string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	req.RemoteAddr = remoteAddr

	return req
}

func TestAllowListMiddleware(t *testing.T) {
	t.Parallel()

	const allowed = "10.0.0.5"

	cases := []struct {
		name       string
		entries    []string
		method     string
		path       string
		remoteAddr string
		want       int
	}{
		{"GET always open", []string{allowed}, http.MethodGet, "/read", testDisallowedAddr, http.StatusOK},
		{"mutation from disallowed IP forbidden", []string{allowed}, http.MethodDelete, testMutatePath, testDisallowedAddr, http.StatusForbidden},
		{"mutation from allowed IP passes", []string{allowed}, http.MethodDelete, testMutatePath, "10.0.0.5:5000", http.StatusOK},
		{"CIDR member passes", []string{"10.0.0.0/24"}, http.MethodDelete, testMutatePath, "10.0.0.200:5000", http.StatusOK},
		{"outside CIDR forbidden", []string{"10.0.0.0/24"}, http.MethodDelete, testMutatePath, "10.0.1.1:5000", http.StatusForbidden},
		{"malformed RemoteAddr falls back to host", []string{allowed}, http.MethodDelete, testMutatePath, "10.0.0.5", http.StatusOK},
		{"malformed RemoteAddr not allowed", []string{allowed}, http.MethodDelete, testMutatePath, "9.9.9.9", http.StatusForbidden},
		{"empty allow-list is a no-op", nil, http.MethodDelete, testMutatePath, testDisallowedAddr, http.StatusOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			allowRouter(tc.entries).ServeHTTP(rec, reqFrom(tc.method, tc.path, tc.remoteAddr))

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// config defaults
// ---------------------------------------------------------------------------

func TestChanDaemonConfigDefaults(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cd := cfg.Security.ChanDaemon

	if !cd.Enabled {
		t.Error("chanDaemon reporting should default ON")
	}

	if cd.ReportURL != defaultChanDaemonReportURL {
		t.Errorf("ReportURL = %q, want %q", cd.ReportURL, defaultChanDaemonReportURL)
	}

	if cd.ServiceName != defaultChanDaemonServiceName {
		t.Errorf("ServiceName = %q, want %q", cd.ServiceName, defaultChanDaemonServiceName)
	}

	list, err := parseAllowedIPs(cd.AllowedAPIIPs)
	if err != nil {
		t.Fatalf("default allow-list must parse cleanly: %v", err)
	}

	if !list.Contains(testLoopbackIP) || !list.Contains(testChanDaemonNode) {
		t.Error("default allow-list must include loopback and a chanDaemon node")
	}
}

// ---------------------------------------------------------------------------
// SecurityManager reporting integration
// ---------------------------------------------------------------------------

// newReportingSM builds a SecurityManager with auto-block on and a reporter
// pointed at endpoint, with a no-op (successful) ipset runner. maxFailed sets
// the failed-registration threshold. Workers are started before return.
func newReportingSM(tb testing.TB, endpoint, blockerURL string, maxFailed int) *SecurityManager {
	tb.Helper()
	GetLogger().SetLogLevel(LogLevelError)

	ipset := newTestIPSet()

	ctx, cancel := context.WithCancel(tb.Context())
	sm := &SecurityManager{
		whitelist:         make(map[string]WhitelistEntry),
		blacklist:         make(map[string]BlacklistEntry),
		failedAttempts:    make(map[string]FailedAttempt),
		wrongStates:       make(map[string]WrongCallStateEntry),
		trustedNetworks:   []netip.Prefix{netip.MustParsePrefix(testTrustedCIDR)},
		untrustedPatterns: map[string]struct{}{testUntrustedDomain: {}},
		ipset:             ipset,
		reporter:          NewChanDaemonReporter(endpoint, blockerURL, projectName, 2*time.Second),
		cfg: effectiveSecurityConfig{
			Enabled:                true,
			AutoBlockEnabled:       true,
			WhitelistEnabled:       true,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          testChain,
			IPSetName:              testIPSetName,
			DryRun:                 false,
			MaxFailedAttempts:      maxFailed,
			FailedWindow:           10 * time.Minute,
			BlockDuration:          time.Hour,
			WhitelistTTL:           24 * time.Hour,
			MaxWrongCallStates:     maxFailed,
			WrongStateWindow:       10 * time.Minute,
		},
		blacklistQueue:  make(chan BlacklistRequest, blacklistQueueSize),
		whitelistQueue:  make(chan WhitelistRequest, whitelistQueueSize),
		failedQueue:     make(chan FailedAttemptRequest, failedQueueSize),
		wrongStateQueue: make(chan WrongStateRequest, wrongStateQueueSize),
		ctx:             ctx,
		cancel:          cancel,
	}

	sm.wg.Add(5)
	go sm.processBlacklistQueue()
	go sm.processWhitelistQueue()
	go sm.processFailedAttemptQueue()
	go sm.processWrongStateQueue()
	go sm.startCleanupRoutine()

	tb.Cleanup(func() { sm.Shutdown() })

	return sm
}

func TestSecurityManager_ReportsFailedRegistrationBan(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusOK)
	sm := newReportingSM(t, srv.URL, "http://sbc:8088", 2)

	const ip = "203.0.113.50"

	// Exceed the failed-registration threshold; the auto-block must be mirrored
	// to chanDaemon with the SIP From-user attached for account attribution.
	sm.ProcessFailedRegistration(ip, "2017301000", "x.example")
	sm.ProcessFailedRegistration(ip, "2017301000", "x.example")

	select {
	case got := <-ch:
		if got.body.IP != ip {
			t.Errorf("reported ip = %q, want %q", got.body.IP, ip)
		}

		if got.body.FromUser != "2017301000" {
			t.Errorf("reported fromUser = %q, want 2017301000", got.body.FromUser)
		}

		if got.body.Service != projectName {
			t.Errorf("service = %q", got.body.Service)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no ban report reached the fake chanDaemon")
	}
}

func TestSecurityManager_ReportsWrongStateBan(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusOK)
	sm := newReportingSM(t, srv.URL, "", 2)

	const ip = "203.0.113.77"

	sm.ProcessWrongCallState(ip, "2017309999")
	sm.ProcessWrongCallState(ip, "2017309999")

	select {
	case got := <-ch:
		if got.body.IP != ip || got.body.FromUser != "2017309999" {
			t.Errorf("report = %+v, want ip %s / fromUser 2017309999", got.body, ip)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no wrong-state ban report reached the fake chanDaemon")
	}
}

func TestSecurityManager_ReportCountersInStats(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusOK)
	sm := newReportingSM(t, srv.URL, "", 1)

	sm.ProcessFailedRegistration("203.0.113.9", "alice", "x.example")
	<-ch // wait for the report to be received and counted

	// The reporter increments after the response; poll briefly for the count.
	if !waitFor(func() bool { return sm.GetSecurityStats().ReportsSent >= 1 }) {
		t.Errorf("ReportsSent = %d, want >= 1", sm.GetSecurityStats().ReportsSent)
	}
}

// ---------------------------------------------------------------------------
// initChanDaemonReporter gating
// ---------------------------------------------------------------------------

func TestInitChanDaemonReporterGating(t *testing.T) {
	t.Parallel()

	base := func() *AppConfig {
		c := defaultConfig()
		c.Security.ChanDaemon.ReportURL = "http://chand/report"

		return c
	}

	cases := []struct {
		name      string
		mutate    func(*AppConfig, *SecurityManager)
		wantSetup bool
	}{
		{"enabled with auto-block", func(_ *AppConfig, sm *SecurityManager) { sm.cfg.AutoBlockEnabled = true }, true},
		{"disabled flag", func(c *AppConfig, sm *SecurityManager) {
			c.Security.ChanDaemon.Enabled = false
			sm.cfg.AutoBlockEnabled = true
		}, false},
		{"empty URL", func(c *AppConfig, sm *SecurityManager) {
			c.Security.ChanDaemon.ReportURL = ""
			sm.cfg.AutoBlockEnabled = true
		}, false},
		{"auto-block off", func(_ *AppConfig, sm *SecurityManager) { sm.cfg.AutoBlockEnabled = false }, false},
		{"dry-run suppresses", func(_ *AppConfig, sm *SecurityManager) {
			sm.cfg.AutoBlockEnabled = true
			sm.cfg.DryRun = true
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := base()
			sm := &SecurityManager{}
			tc.mutate(cfg, sm)
			sm.initChanDaemonReporter(cfg, GetLogger())

			if (sm.reporter != nil) != tc.wantSetup {
				t.Errorf("reporter set = %v, want %v", sm.reporter != nil, tc.wantSetup)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// unban endpoint
// ---------------------------------------------------------------------------

func TestBatchBlockIPs_BlockErrorSkipsReport(t *testing.T) {
	t.Parallel()

	srv, _ := fakeChanDaemon(t, http.StatusOK)

	// No workers started: batchBlockIPs is exercised directly. A malformed IP
	// makes the ipset BlockIP fail (its checkIPv4 rejects it), so the report
	// must be skipped. permanent:true also exercises the zero-timeout path.
	sm := &SecurityManager{
		ipset:    newTestIPSet(),
		reporter: NewChanDaemonReporter(srv.URL, "", projectName, time.Second),
		cfg: effectiveSecurityConfig{
			Enabled:                false,
			AutoBlockEnabled:       true,
			WhitelistEnabled:       false,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          testChain,
			IPSetName:              testIPSetName,
			DryRun:                 false,
			MaxFailedAttempts:      0,
			FailedWindow:           0,
			BlockDuration:          time.Hour,
			WhitelistTTL:           0,
			MaxWrongCallStates:     0,
			WrongStateWindow:       0,
		},
	}

	sm.batchBlockIPs([]blockTarget{{ip: testInvalidIP, reason: "x", fromUser: "alice", permanent: true}})
	sm.reporter.Wait()

	if sent, failed := sm.reporter.Stats(); sent != 0 || failed != 0 {
		t.Errorf("a failed block must not report: stats = (sent %d, failed %d)", sent, failed)
	}
}

func TestBatchBlockIPs_EmptyIsNoOp(t *testing.T) {
	t.Parallel()

	// An empty target slice must return immediately without touching the ipset
	// or the reporter (both nil here); cfg is unused on that early-return path.
	sm := &SecurityManager{
		cfg: effectiveSecurityConfig{
			Enabled:                false,
			AutoBlockEnabled:       true,
			WhitelistEnabled:       false,
			AutoWhitelistOnSuccess: false,
			IPTablesChain:          testChain,
			IPSetName:              testIPSetName,
			DryRun:                 false,
			MaxFailedAttempts:      0,
			FailedWindow:           0,
			BlockDuration:          time.Hour,
			WhitelistTTL:           0,
			MaxWrongCallStates:     0,
			WrongStateWindow:       0,
		},
	}

	sm.batchBlockIPs(nil)
}

func TestChanDaemonUnbanHandler(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	router := gin.New()
	router.DELETE("/api/v1/ips/:ip/block", chanDaemonUnbanHandler(sm))

	// Valid IP -> 200 (idempotent even when not currently banned).
	rec := doJSON(t, router, http.MethodDelete, "/api/v1/ips/203.0.113.50/block", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid unban status = %d body=%s", rec.Code, rec.Body)
	}

	// Malformed IP -> 400.
	rec = doJSON(t, router, http.MethodDelete, "/api/v1/ips/not-an-ip/block", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed IP status = %d, want 400", rec.Code)
	}
}

func TestChanDaemonUnbanHandler_LiftsExistingBan(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	const ip = "203.0.113.123"

	err := sm.AddToBlacklist(ip, "test ban", false)
	if err != nil {
		t.Fatalf("seed blacklist: %v", err)
	}

	if !sm.IsIPBlacklisted(ip) {
		t.Fatal("precondition: IP should be blacklisted")
	}

	router := gin.New()
	router.DELETE("/api/v1/ips/:ip/block", chanDaemonUnbanHandler(sm))

	rec := doJSON(t, router, http.MethodDelete, "/api/v1/ips/"+ip+"/block", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("unban status = %d", rec.Code)
	}

	if sm.IsIPBlacklisted(ip) {
		t.Error("IP should no longer be blacklisted after unban")
	}
}
