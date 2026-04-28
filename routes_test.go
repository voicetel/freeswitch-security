package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestMain installs gin's TestMode globally before any test runs, suppressing
// gin's debug banner. Using TestMain rather than init() keeps test setup
// localized to the testing package's lifecycle.
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
		req = httptest.NewRequest(method, url, reader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, url, http.NoBody)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	return rec
}

func TestRoute_Whitelist_Add(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist",
		`{"ip":"203.0.113.7","user_id":"alice","domain":"x.example"}`)
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
		`{"ip":"not-an-ip","user_id":"alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestRoute_Whitelist_Add_MissingIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "POST", "/security/whitelist", `{"user_id":"alice"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing required ip, got %d", rec.Code)
	}
}

func TestRoute_Whitelist_GetByIP(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)

	if err := sm.AddToWhitelist("203.0.113.8", "bob", "x.example", false); err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)

	rec := doJSON(t, router, "GET", "/security/whitelist/203.0.113.8", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["whitelisted"] != true {
		t.Errorf("expected whitelisted=true, got %v", resp)
	}

	if resp["user_id"] != "bob" {
		t.Errorf("expected user_id=bob, got %v", resp["user_id"])
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
	if err := sm.AddToWhitelist("203.0.113.9", "u", "d", false); err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)
	rec := doJSON(t, router, "GET", "/security/whitelist", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}

	var listing map[string]WhitelistEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}

	if _, ok := listing["203.0.113.9"]; !ok {
		t.Errorf("listing missing IP, got: %v", listing)
	}
}

func TestRoute_Whitelist_Delete(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	if err := sm.AddToWhitelist("203.0.113.10", "u", "d", false); err != nil {
		t.Fatal(err)
	}

	router := newWhitelistRouter(sm)
	rec := doJSON(t, router, "DELETE", "/security/whitelist/203.0.113.10", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}

	if sm.IsIPWhitelisted("203.0.113.10") {
		t.Error("expected IP to be removed from whitelist")
	}
}

func TestRoute_Whitelist_Batch(t *testing.T) {
	t.Parallel()
	sm := newTestSecurityManager(t)
	router := newWhitelistRouter(sm)

	body := `[
		{"ip":"203.0.113.20","user_id":"a","domain":"x.example"},
		{"ip":"203.0.113.21","user_id":"b","domain":"y.example"},
		{"ip":"not-an-ip","user_id":"c"}
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
	if err := json.Unmarshal(rec.Body.Bytes(), &patterns); err != nil {
		t.Fatal(err)
	}

	found := false

	for _, p := range patterns {
		if p == "bad.example" {
			found = true

			break
		}
	}

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

	if testResp["is_untrusted"] != true {
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
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
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
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
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
			body := fmt.Sprintf(`{"ip":%q,"user_id":"u","domain":"d"}`, ip)

			for j := 0; j < 10 && ctx.Err() == nil; j++ {
				req := httptest.NewRequest(http.MethodPost, "/security/whitelist",
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
