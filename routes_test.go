package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// TestMain installs gin's TestMode globally before any test runs, suppressing
// gin's debug banner. SecurityManager test instances are wired to a no-op
// ipset runner (see ipset_fake_test.go), so tests never touch host firewall
// state. Using TestMain rather than init() keeps test setup localized to the
// testing package's lifecycle.
func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// newWhitelistRouter returns a gin engine with only the /security/whitelist
// routes wired against the given test SecurityManager. Bypassing
// RegisterSecurityRoutes avoids the singleton initialisation that the
// production registration uses.
func newWhitelistRouter(sm *SecurityManager) *gin.Engine {
	router := gin.New()
	g := router.Group("/security")
	registerWhitelistRoutes(g, sm)

	return router
}

func newBlacklistRouter(sm *SecurityManager) *gin.Engine {
	router := gin.New()
	g := router.Group("/security")
	registerBlacklistRoutes(g, sm)

	return router
}

func newUntrustedRouter(sm *SecurityManager) *gin.Engine {
	router := gin.New()
	g := router.Group("/security")
	registerUntrustedRoutes(g, sm)

	return router
}

// doJSON issues a request with the given method/url/body and returns the
// recorder. body may be nil.
func doJSON(tb testing.TB, router http.Handler, method, url, body string) *httptest.ResponseRecorder {
	tb.Helper()

	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	var req *http.Request
	if reader != nil {
		req = httptest.NewRequestWithContext(context.Background(), method, url, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec
}

// doJSONFrom is doJSON with an explicit source RemoteAddr, for exercising the
// chanDaemon API allow-list on state-changing endpoints.
func doJSONFrom(tb testing.TB, router http.Handler, method, url, body, remoteAddr string) *httptest.ResponseRecorder {
	tb.Helper()

	var req *http.Request
	if body != "" {
		req = httptest.NewRequestWithContext(context.Background(), method, url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequestWithContext(context.Background(), method, url, http.NoBody)
	}

	req.RemoteAddr = remoteAddr

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec
}

func TestRoute_Whitelist_Add(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist",
		`{"ip":"203.0.113.7","userId":"alice","domain":"x.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if !sm.IsIPWhitelisted("203.0.113.7") {
		t.Error("expected IP to be whitelisted after POST")
	}
}

func TestRoute_Whitelist_Add_InvalidIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist",
		`{"ip":"not-an-ip","userId":"alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestRoute_Whitelist_Add_MissingIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist", `{"userId":"alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing required ip, got %d", rec.Code)
	}
}

func TestRoute_Whitelist_GetByIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	err := sm.AddToWhitelist("203.0.113.8", testUserBob, "x.example", false)
	if err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "GET", "/security/whitelist/203.0.113.8", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var resp map[string]any

	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp["whitelisted"] != true {
		t.Errorf("expected whitelisted=true, got %v", resp)
	}

	if resp["userId"] != testUserBob {
		t.Errorf("expected user_id=bob, got %v", resp["userId"])
	}

	// Unknown IP returns whitelisted=false (200).
	rec = doJSON(t, router, "GET", "/security/whitelist/198.51.100.1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["whitelisted"] != false {
		t.Errorf("expected whitelisted=false for unknown IP")
	}
}

func TestRoute_Whitelist_List(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	err := sm.AddToWhitelist("203.0.113.9", "u", "d", false)
	if err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)
	rec := doJSON(t, router, "GET", "/security/whitelist", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var listing map[string]WhitelistEntry

	err = json.Unmarshal(rec.Body.Bytes(), &listing)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := listing["203.0.113.9"]; !ok {
		t.Errorf("listing missing IP, got: %v", listing)
	}
}

func TestRoute_Whitelist_Delete(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	err := sm.AddToWhitelist(testIPSample, "u", "d", false)
	if err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)
	rec := doJSON(t, router, "DELETE", "/security/whitelist/203.0.113.10", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if sm.IsIPWhitelisted(testIPSample) {
		t.Error("expected IP to be removed from whitelist")
	}
}

func TestRoute_Whitelist_Batch(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	body := `[
		{"ip":"203.0.113.20","userId":"a","domain":"x.example"},
		{"ip":"203.0.113.21","userId":"b","domain":"y.example"},
		{"ip":"not-an-ip","userId":"c"}
	]`

	rec := doJSON(t, router, "POST", "/security/whitelist/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if !sm.IsIPWhitelisted("203.0.113.20") || !sm.IsIPWhitelisted("203.0.113.21") {
		t.Error("expected first two IPs to be whitelisted")
	}
}

func TestRoute_Whitelist_BatchTooLarge(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	// Build > 1000 entries to trip the size limit.
	var sb strings.Builder

	sb.WriteString("[")

	for i := range 1001 {
		if i > 0 {
			sb.WriteString(",")
		}

		sb.WriteString(`{"ip":"203.0.113.1"}`)
	}

	sb.WriteString("]")

	rec := doJSON(t, router, "POST", "/security/whitelist/batch", sb.String())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized batch, got %d", rec.Code)
	}
}

func TestRoute_Blacklist_Add_GetCheck_Delete(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newBlacklistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/blacklist",
		`{"ip":"203.0.113.30","reason":"spam"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if !sm.IsIPBlacklisted("203.0.113.30") {
		t.Error("expected IP to be blacklisted")
	}

	rec = doJSON(t, router, "GET", "/security/blacklist/203.0.113.30", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var resp map[string]any

	_ = json.Unmarshal(rec.Body.Bytes(), &resp)

	if resp["blacklisted"] != true {
		t.Errorf("expected blacklisted=true, got %v", resp)
	}

	rec = doJSON(t, router, "DELETE", "/security/blacklist/203.0.113.30", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rec.Code)
	}

	if sm.IsIPBlacklisted("203.0.113.30") {
		t.Error("expected IP to be removed from blacklist")
	}
}

func TestRoute_Blacklist_RejectsTrusted(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newBlacklistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/blacklist",
		`{"ip":"10.1.2.3","reason":"trusted"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 (cannot blacklist trusted IP), got %d body=%s",
			rec.Code, rec.Body)
	}
}

func TestRoute_Untrusted_AddListRemove(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newUntrustedRouter(sm)

	// Add
	rec := doJSON(t, router, "POST", "/security/untrusted-networks",
		`{"pattern":"bad.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("add status=%d body=%s", rec.Code, rec.Body)
	}

	// List
	rec = doJSON(t, router, "GET", "/security/untrusted-networks", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d", rec.Code)
	}

	var patterns []string

	err := json.Unmarshal(rec.Body.Bytes(), &patterns)
	if err != nil {
		t.Fatal(err)
	}

	found := slices.Contains(patterns, "bad.example")

	if !found {
		t.Errorf("listing missing 'bad.example': %v", patterns)
	}

	// Test
	rec = doJSON(t, router, "GET", "/security/untrusted-networks/test/bad.example", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("test status=%d", rec.Code)
	}

	var testResp map[string]any

	_ = json.Unmarshal(rec.Body.Bytes(), &testResp)

	if testResp["isUntrusted"] != true {
		t.Errorf("expected is_untrusted=true, got %v", testResp)
	}

	// Remove
	rec = doJSON(t, router, "DELETE", "/security/untrusted-networks/bad.example", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", rec.Code, rec.Body)
	}

	if sm.IsUntrustedDomain("bad.example") {
		t.Error("expected pattern to be removed")
	}
}

func TestRoute_Untrusted_RemoveMissing(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newUntrustedRouter(sm)

	rec := doJSON(t, router, "DELETE", "/security/untrusted-networks/never-added.example", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for unknown pattern, got %d", rec.Code)
	}
}

func TestRoute_SystemStats(t *testing.T) {
	t.Parallel()

	router := gin.New()
	router.GET("/system/stats", systemStatsHandler())

	rec := doJSON(t, router, "GET", "/system/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var resp map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := resp["goroutines"]; !ok {
		t.Errorf("missing goroutines key: %v", resp)
	}

	if _, ok := resp["memory"]; !ok {
		t.Errorf("missing memory key: %v", resp)
	}
}

func TestRoute_Health(t *testing.T) {
	t.Parallel()

	router := gin.New()
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{testCmdStatus: "ok"})
	})

	rec := doJSON(t, router, "GET", "/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
}

// TestRoute_CacheMiddleware verifies that GET responses are served from cache
// on the second hit (validating the middleware integration end-to-end).
// Not parallel: it touches the package-level cacheManager singleton.
//
//nolint:paralleltest // singleton state
func TestRoute_CacheMiddleware(t *testing.T) {
	if cacheManager == nil {
		// Initialize a real cache manager for this test (other tests may have
		// run that left it nil). Use a config that enables caching.
		_ = InitCache()
	}

	if cacheManager == nil || !cacheManager.enabled {
		t.Skip("cache manager unavailable")
	}

	router := gin.New()
	hitCount := 0

	router.GET("/cached", CacheMiddleware("test-key"), func(c *gin.Context) {
		hitCount++

		CacheResponse("test-key", gin.H{"hello": "world"})
		c.JSON(http.StatusOK, gin.H{"hello": "world"})
	})

	// First request — miss, handler runs.
	rec := doJSON(t, router, "GET", "/cached", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("first status=%d", rec.Code)
	}

	if hitCount != 1 {
		t.Fatalf("expected handler to run once, got %d", hitCount)
	}

	// Cache writes are synchronous after the round-1 refactor; this read
	// confirms that the middleware's storage path is reachable.
	_, _ = cacheManager.GetSecurityItem("route:test-key")

	// Second request — should hit cache, handler should not run again.
	rec = doJSON(t, router, "GET", "/cached", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("second status=%d", rec.Code)
	}
}

// ----- Concurrency: hammer the routes with goroutines to exercise locks. -----

func TestRoute_Whitelist_ConcurrentAdds(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)
	ctx := t.Context()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()

			ip := fmt.Sprintf("203.0.113.%d", 100+id)
			body := fmt.Sprintf(`{"ip":%q,"userId":"u","domain":"d"}`, ip)

			for j := 0; j < 10 && ctx.Err() == nil; j++ {
				req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/security/whitelist",
					strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, req)

				if rec.Code != http.StatusOK {
					t.Errorf("status=%d body=%s", rec.Code, rec.Body)

					return
				}
			}
		}(i)
	}

	wg.Wait()
}

// ----- Request processor -----

// newTestRequestProcessor builds an isolated RequestProcessor (bypassing the
// singleton) with running workers, torn down via t.Cleanup.
func newTestRequestProcessor(tb testing.TB, sm *SecurityManager, em *ESLManager) *RequestProcessor {
	tb.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	rp := &RequestProcessor{
		securityManager: sm,
		eslManager:      em,
		statusRequests:  make(chan StatusRequest, 8),
		commandRequests: make(chan CommandRequest, 8),
		workerCount:     2,
		ctx:             ctx,
		cancel:          cancel,
	}

	for range rp.workerCount {
		rp.wg.Add(2)

		go rp.processStatusRequests()
		go rp.processCommandRequests()
	}

	tb.Cleanup(rp.Shutdown)

	return rp
}

func TestRequestProcessor_StatusTypes(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{}
	rp := newTestRequestProcessor(t, sm, em)

	for _, typ := range []string{statusTypeSecurity, "esl", "whitelist", "blacklist", "failed", "wrong-states"} {
		respChan := make(chan StatusResponse, 1)
		rp.statusRequests <- StatusRequest{Type: typ, Response: respChan}

		resp := <-respChan
		if resp.Error != nil {
			t.Errorf("status %q: %v", typ, resp.Error)
		}

		if resp.Data == nil {
			t.Errorf("status %q: nil data", typ)
		}
	}

	// Unknown type returns ErrUnknownStatusType.
	respChan := make(chan StatusResponse, 1)
	rp.statusRequests <- StatusRequest{Type: testBogusValue, Response: respChan}

	if resp := <-respChan; !errors.Is(resp.Error, ErrUnknownStatusType) {
		t.Errorf("expected ErrUnknownStatusType, got %v", resp.Error)
	}
}

func TestRequestProcessor_Command_NotConnected(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{} // never connected
	rp := newTestRequestProcessor(t, sm, em)

	respChan := make(chan CommandResponse, 1)
	rp.commandRequests <- CommandRequest{Command: testCmdStatus, Response: respChan}

	if resp := <-respChan; !errors.Is(resp.Error, ErrESLNotConnected) {
		t.Errorf("expected ErrESLNotConnected, got %v", resp.Error)
	}
}

// ----- Handlers not covered by the per-group route tests -----

func TestRoute_SecurityStatusHandler(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{eslConfig: ESLConfig{Host: "192.0.2.9", Port: "8021"}}

	router := gin.New()
	router.GET("/security/status", securityStatusHandler(sm, em))

	rec := doJSON(t, router, "GET", "/security/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var resp map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp["enabled"] != true || resp["eslConnected"] != false {
		t.Errorf("unexpected response: %v", resp)
	}

	if resp["eslHost"] != "192.0.2.9" {
		t.Errorf("esl_host = %v", resp["eslHost"])
	}
}

func TestRoute_SecurityStatsHandler(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.UpdateRegistrationStats("203.0.113.160", "u", "d")

	router := gin.New()
	router.GET("/security/stats", securityStatsHandler(sm))

	rec := doJSON(t, router, "GET", "/security/stats", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var stats SecurityStats

	err := json.Unmarshal(rec.Body.Bytes(), &stats)
	if err != nil {
		t.Fatal(err)
	}

	if stats.TotalRegistrations != 1 {
		t.Errorf("TotalRegistrations = %d, want 1", stats.TotalRegistrations)
	}
}

func TestRoute_IptablesHandler(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)

	// Success path: ipset list returns one member.
	sm.ipset.run = func(_ string, _ ...string) ([]byte, error) {
		return []byte("Name: fs-test\nMembers:\n203.0.113.5 timeout 120\n"), nil
	}

	router := gin.New()
	router.GET("/security/iptables", iptablesHandler(sm))

	rec := doJSON(t, router, "GET", "/security/iptables", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	var resp map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &resp)
	if err != nil {
		t.Fatal(err)
	}

	if resp["count"] != float64(1) {
		t.Errorf("count = %v, want 1", resp["count"])
	}

	// Error path: ipset list fails.
	sm.ipset.run = func(_ string, _ ...string) ([]byte, error) {
		return []byte("set not found"), errFakeIPSet
	}

	rec = doJSON(t, router, "GET", "/security/iptables", "")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 for failing list, got %d", rec.Code)
	}
}

func TestRoute_RateLimit(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())
	_ = rm.CheckCallRate("203.0.113.161", "u", "d")
	_ = rm.CheckRegistrationRate("203.0.113.162", "u", "d")

	router := gin.New()
	g := router.Group("/security")
	registerRateLimitRoutes(g, rm)

	rec := doJSON(t, router, "GET", "/security/rate-limit", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("config status=%d", rec.Code)
	}

	var cfg map[string]any

	err := json.Unmarshal(rec.Body.Bytes(), &cfg)
	if err != nil {
		t.Fatal(err)
	}

	if cfg["enabled"] != true {
		t.Errorf("enabled = %v", cfg["enabled"])
	}

	rec = doJSON(t, router, "GET", "/security/rate-limit/calls", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("calls status=%d", rec.Code)
	}

	var calls map[string]RateCounter

	err = json.Unmarshal(rec.Body.Bytes(), &calls)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := calls["203.0.113.161"]; !ok {
		t.Errorf("calls listing missing IP: %v", calls)
	}

	rec = doJSON(t, router, "GET", "/security/rate-limit/registrations", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("registrations status=%d", rec.Code)
	}
}

func TestRoute_ESL(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{eslConfig: ESLConfig{Host: "192.0.2.10", Port: "8021", LogLevel: logLevelErrorStr}}
	rp := newTestRequestProcessor(t, sm, em)

	router := gin.New()
	g := router.Group("/security")
	registerESLRoutes(g, em, rp)

	// Stats.
	rec := doJSON(t, router, "GET", "/security/esl", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("esl stats status=%d", rec.Code)
	}

	// Log level: happy path and binding error. Restore the global level after.
	old := GetLogger().GetLogLevel()
	defer GetLogger().SetLogLevel(old)

	rec = doJSON(t, router, "POST", "/security/esl/log-level", `{"level":"error"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("log_level status=%d body=%s", rec.Code, rec.Body)
	}

	rec = doJSON(t, router, "POST", "/security/esl/log-level", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("log_level missing field: expected 400, got %d", rec.Code)
	}

	// Reconnect on a disconnected manager is a no-op but must succeed.
	rec = doJSON(t, router, "POST", "/security/esl/reconnect", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("reconnect status=%d", rec.Code)
	}

	// Command: not connected → 500; binding error → 400.
	rec = doJSON(t, router, "POST", "/security/esl/command", `{"command":"status"}`)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("command (not connected): expected 500, got %d body=%s", rec.Code, rec.Body)
	}

	rec = doJSON(t, router, "POST", "/security/esl/command", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("command missing field: expected 400, got %d", rec.Code)
	}
}

func TestRoute_Blacklist_Batch(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newBlacklistRouter(sm)

	body := `[
		{"ip":"203.0.113.220","reason":"a"},
		{"ip":"203.0.113.221","reason":"b"},
		{"ip":"not-an-ip","reason":"c"}
	]`

	rec := doJSON(t, router, "POST", "/security/blacklist/batch", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if !sm.IsIPBlacklisted("203.0.113.220") || !sm.IsIPBlacklisted("203.0.113.221") {
		t.Error("expected first two IPs to be blacklisted")
	}

	// Binding error and oversized batch.
	rec = doJSON(t, router, "POST", "/security/blacklist/batch", `{"not":"an array"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed batch, got %d", rec.Code)
	}

	var sb strings.Builder

	sb.WriteString("[")

	for i := range 1001 {
		if i > 0 {
			sb.WriteString(",")
		}

		sb.WriteString(`{"ip":"203.0.113.1"}`)
	}

	sb.WriteString("]")

	rec = doJSON(t, router, "POST", "/security/blacklist/batch", sb.String())
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for oversized batch, got %d", rec.Code)
	}
}

func TestRoute_Blacklist_Add_Malformed(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newBlacklistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/blacklist", `{"reason":"missing ip"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing ip, got %d", rec.Code)
	}

	rec = doJSON(t, router, "POST", "/security/blacklist", `{"ip":"not-an-ip"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid ip, got %d", rec.Code)
	}
}

func TestRoute_Whitelist_DefaultDomain(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist",
		`{"ip":"203.0.113.222","userId":"nodomain"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	entry, ok := sm.GetWhitelistEntry("203.0.113.222")
	if !ok {
		t.Fatal("entry missing after add")
	}

	if entry.Domain != GetConfig().FreeSWITCH.DefaultDomain {
		t.Errorf("Domain = %q, want config default", entry.Domain)
	}
}

func TestRoute_Untrusted_AddMalformed(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newUntrustedRouter(sm)

	rec := doJSON(t, router, "POST", "/security/untrusted-networks", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing pattern, got %d", rec.Code)
	}
}

func TestCacheResponse_MarshalError(t *testing.T) {
	t.Parallel()

	// Channels cannot be marshaled; the error must be swallowed after logging.
	CacheResponse("marshal-error-key", make(chan int))

	if cm := GetCacheManager(); cm != nil {
		if _, ok := cm.GetSecurityItem("route:marshal-error-key"); ok {
			t.Error("unmarshalable value must not be cached")
		}
	}
}

func TestCacheMiddleware_NonGETPassesThrough(t *testing.T) {
	t.Parallel()

	router := gin.New()
	handled := false

	router.POST("/cached", CacheMiddleware("post-key"), func(c *gin.Context) {
		handled = true

		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	rec := doJSON(t, router, "POST", "/cached", `{}`)
	if rec.Code != http.StatusOK || !handled {
		t.Errorf("POST must bypass the cache: status=%d handled=%v", rec.Code, handled)
	}
}

// TestRequestProcessor_ExitsOnClosedChannels covers the !ok branches of both
// worker loops: channels are closed without canceling the context.
func TestRequestProcessor_ExitsOnClosedChannels(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rp := &RequestProcessor{
		securityManager: sm,
		eslManager:      em,
		statusRequests:  make(chan StatusRequest),
		commandRequests: make(chan CommandRequest),
		workerCount:     1,
		ctx:             ctx,
		cancel:          cancel,
	}

	rp.wg.Add(2)

	go rp.processStatusRequests()
	go rp.processCommandRequests()

	close(rp.statusRequests)
	close(rp.commandRequests)

	rp.wg.Wait() // workers must exit via the !ok branch
}

// TestRequestProcessor_ResponseTimeouts covers the worker-side response
// timeouts: the caller never reads the response channel. The two waits (5s
// and 10s) run concurrently and in parallel with the rest of the suite.
func TestRequestProcessor_ResponseTimeouts(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{}
	rp := newTestRequestProcessor(t, sm, em)

	// Unbuffered response channels that nothing ever reads.
	rp.statusRequests <- StatusRequest{Type: statusTypeSecurity, Response: make(chan StatusResponse)}

	rp.commandRequests <- CommandRequest{Command: testCmdStatus, Response: make(chan CommandResponse)}

	// Prove the workers survive the abandoned responses and keep serving.
	if !waitFor(func() bool {
		respChan := make(chan StatusResponse, 1)

		select {
		case rp.statusRequests <- StatusRequest{Type: statusTypeSecurity, Response: respChan}:
		default:
			return false
		}

		select {
		case resp := <-respChan:
			return resp.Error == nil
		case <-time.After(8 * time.Second):
			return false
		}
	}) {
		t.Error("worker did not recover after abandoned response channels")
	}
}

func TestRoute_Whitelist_AddTimeout(t *testing.T) {
	t.Parallel()

	// A saturated manager makes AddToWhitelist fail after its 1s enqueue
	// timeout; the route must surface a 400.
	sm := newSaturatedSecurityManager()
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist",
		`{"ip":"203.0.113.240","userId":"u","domain":"d"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when whitelist enqueue times out, got %d", rec.Code)
	}
}

func TestRoute_Whitelist_BatchMalformed(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist/batch", `{"not":"an array"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed whitelist batch, got %d", rec.Code)
	}
}

func TestRoute_Untrusted_AddDuplicate(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newUntrustedRouter(sm)

	rec := doJSON(t, router, "POST", "/security/untrusted-networks", `{"pattern":"dup.example"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("first add status=%d", rec.Code)
	}

	rec = doJSON(t, router, "POST", "/security/untrusted-networks", `{"pattern":"dup.example"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for duplicate pattern, got %d", rec.Code)
	}
}

// TestRouteESLCommand_Timeouts covers the 504 arms of the /esl/command route:
// queue-full (outer ctx.Done) and execution timeout (inner ctx.Done). Both
// 10s waits run concurrently.
func TestRouteESLCommand_Timeouts(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	em := &ESLManager{}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// No workers: a zero-capacity queue forces the enqueue to block (queue
	// timeout); a one-slot queue accepts the request but nothing answers
	// (execution timeout).
	stuck := &RequestProcessor{
		securityManager: sm, eslManager: em,
		statusRequests:  make(chan StatusRequest),
		commandRequests: make(chan CommandRequest),
		ctx:             ctx, cancel: cancel,
	}
	unanswered := &RequestProcessor{
		securityManager: sm, eslManager: em,
		statusRequests:  make(chan StatusRequest, 1),
		commandRequests: make(chan CommandRequest, 1),
		ctx:             ctx, cancel: cancel,
	}

	stuckRouter := gin.New()
	registerESLRoutes(stuckRouter.Group("/security"), em, stuck)

	unansweredRouter := gin.New()
	registerESLRoutes(unansweredRouter.Group("/security"), em, unanswered)

	var wg sync.WaitGroup

	wg.Add(2)

	go func() {
		defer wg.Done()

		rec := doJSON(t, stuckRouter, "POST", "/security/esl/command", `{"command":"status"}`)
		if rec.Code != http.StatusGatewayTimeout {
			t.Errorf("queue timeout: expected 504, got %d", rec.Code)
		}
	}()
	go func() {
		defer wg.Done()

		rec := doJSON(t, unansweredRouter, "POST", "/security/esl/command", `{"command":"status"}`)
		if rec.Code != http.StatusGatewayTimeout {
			t.Errorf("execution timeout: expected 504, got %d", rec.Code)
		}
	}()

	wg.Wait()
}
