package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Tests in this file exercise the package-level singletons (cache, security
// manager, ESL manager, request processor) and the production route
// registration that wires them together.
//
// They are deliberately NOT parallel and rely on source order: Go runs
// non-parallel tests sequentially in declaration order, so each singleton is
// initialized exactly once, under controlled config, before the parallel
// phase begins. Global config mutations are restored before each test
// returns.

//nolint:paralleltest // ordered singleton initialization
func TestSingleton_Cache(t *testing.T) {
	cm := GetCacheManager() // initializes from config.json (cache enabled)
	if cm == nil {
		t.Fatal("GetCacheManager returned nil")
	}

	if cm != GetCacheManager() {
		t.Fatal("GetCacheManager must return the same instance")
	}

	stats := cm.GetCacheStats()
	if stats["enabled"] != true {
		t.Errorf("expected enabled cache from config.json, got %v", stats)
	}

	// CloseCache must shut down whatever the global currently points at.
	// Swap in a throwaway instance so the shared cache stays usable for the
	// remaining tests, and restore it afterwards.
	saved := cacheManager

	defer func() { cacheManager = saved }()

	ctx, cancel := context.WithCancel(context.Background())
	throwaway := &CacheManager{
		enabled:     true,
		securityTTL: time.Minute,
		items:       make(map[string]cacheItem),
		cancel:      cancel,
	}
	throwaway.wg.Add(1)

	go throwaway.janitor(ctx, time.Minute)

	cacheManager = throwaway

	CloseCache()

	cacheManager = nil

	CloseCache() // nil global: must be a no-op

	// With the once already consumed and the global nil, GetCacheManager's
	// init attempt cannot repopulate it and must return nil.
	if got := GetCacheManager(); got != nil {
		t.Errorf("GetCacheManager after exhausted once = %v, want nil", got)
	}

	// An enabled manager with no live store makes InitCache report ErrCacheInit.
	cacheManager = &CacheManager{enabled: true}

	initErr := InitCache()
	if !errors.Is(initErr, ErrCacheInit) {
		t.Errorf("InitCache with broken manager = %v, want ErrCacheInit", initErr)
	}
}

//nolint:paralleltest // ordered singleton initialization
func TestSingleton_SecurityManager(t *testing.T) {
	// config.json has auto_block_enabled=true, so init runs the ipset
	// EnsureSetup + CleanupAutoBlocked path. Force dry-run so it touches no
	// host firewall state. Add one bad CIDR (parse-error branch) and one
	// untrusted pattern (patterns-loaded branch) before the once fires.
	cfg0 := GetConfig()
	savedTrusted := cfg0.Security.TrustedNetworks
	savedUntrusted := cfg0.Security.UntrustedNetworks
	savedDryRun := cfg0.Security.DryRun

	cfg0.Security.TrustedNetworks = append(append([]string{}, savedTrusted...), "not-a-cidr")
	cfg0.Security.UntrustedNetworks = []string{"evil.example"}
	cfg0.Security.DryRun = true

	defer func() {
		cfg0.Security.TrustedNetworks = savedTrusted
		cfg0.Security.UntrustedNetworks = savedUntrusted
		cfg0.Security.DryRun = savedDryRun
	}()

	// First access goes through GetSecurityManager's nil branch.
	sm := GetSecurityManager()
	if sm == nil {
		t.Fatal("GetSecurityManager returned nil")
	}

	// Belt-and-suspenders: ensure later reads (e.g. /security/iptables via the
	// shared singleton) never shell out to a real ipset list.
	sm.ipset.run = func(_ string, _ ...string) ([]byte, error) {
		return []byte("Name: fs\nMembers:\n"), nil
	}

	if !sm.IsUntrustedDomain("evil.example") {
		t.Error("untrusted pattern from config not loaded")
	}

	if sm != GetSecurityManager() {
		t.Fatal("GetSecurityManager must return the same instance")
	}

	InitSecurityManager() // second init is a no-op

	cfg := GetConfig()
	if sm.cfg.Enabled != cfg.Security.Enabled {
		t.Errorf("Enabled = %v, want %v", sm.cfg.Enabled, cfg.Security.Enabled)
	}

	if sm.cfg.IPTablesChain != cfg.Security.IPTablesChain {
		t.Errorf("IPTablesChain = %q, want %q", sm.cfg.IPTablesChain, cfg.Security.IPTablesChain)
	}

	if len(sm.trustedNetworks) != len(savedTrusted) {
		t.Errorf("trustedNetworks = %d entries, want %d (bad CIDR skipped)",
			len(sm.trustedNetworks), len(savedTrusted))
	}

	// The production workers are running; a round-trip proves it.
	err := sm.AddToWhitelist("198.51.100.200", "singleton", "test.example", false)
	if err != nil {
		t.Errorf("AddToWhitelist via singleton workers: %v", err)
	}
}

//nolint:paralleltest // ordered singleton initialization
func TestSingleton_ESLManager(t *testing.T) {
	srv := newFakeESL(t)
	host, port := srv.hostPort()

	cfg := GetConfig()
	savedHost, savedPort := cfg.Security.ESLHost, cfg.Security.ESLPort
	savedBackoff, savedLevel := cfg.Security.ReconnectBackoff, cfg.Security.ESLLogLevel
	cfg.Security.ESLHost = host
	cfg.Security.ESLPort = port
	cfg.Security.ReconnectBackoff = "50ms"
	cfg.Security.ESLLogLevel = logLevelErrorStr

	defer func() {
		cfg.Security.ESLHost, cfg.Security.ESLPort = savedHost, savedPort
		cfg.Security.ReconnectBackoff, cfg.Security.ESLLogLevel = savedBackoff, savedLevel
	}()

	// First access goes through GetESLManager's nil branch, which wires the
	// singleton to the security manager itself.
	em := GetESLManager()
	if em == nil {
		t.Fatal("GetESLManager returned nil")
	}

	if em != GetESLManager() {
		t.Fatal("GetESLManager must return the same instance")
	}

	if em != InitESLManager(GetSecurityManager()) {
		t.Fatal("second InitESLManager must return the existing instance")
	}

	if !waitFor(em.IsConnected) {
		t.Fatal("singleton ESL manager never connected to the fake server")
	}

	if !waitFor(func() bool { return srv.commandSeen(eventSubRegister) }) {
		t.Error("expected event subscriptions on the singleton connection")
	}

	// Shut the singleton down: nothing later in the suite dials ESL, and the
	// instance stays readable (stats, accessors) after shutdown.
	em.Shutdown()

	if em.Host() != host || em.Port() != port {
		t.Errorf("accessors after shutdown: %q:%q", em.Host(), em.Port())
	}
}

//nolint:paralleltest // ordered singleton initialization
func TestSingleton_RequestProcessor(t *testing.T) {
	sm := GetSecurityManager()
	em := GetESLManager() // shut down in the previous test; safe for stats

	rp := InitRequestProcessor(sm, em)
	if rp == nil {
		t.Fatal("InitRequestProcessor returned nil")
	}

	if rp != InitRequestProcessor(sm, em) {
		t.Fatal("InitRequestProcessor must return the same instance")
	}

	respChan := make(chan StatusResponse, 1)
	rp.statusRequests <- StatusRequest{Type: statusTypeSecurity, Response: respChan}

	if resp := <-respChan; resp.Error != nil || resp.Data == nil {
		t.Errorf("singleton processor status request: %+v", resp)
	}
}

//nolint:paralleltest // mutates global config
func TestRegisterRoutes_SecurityDisabled(t *testing.T) {
	cfg := GetConfig()
	saved := cfg.Security.Enabled
	cfg.Security.Enabled = false

	defer func() { cfg.Security.Enabled = saved }()

	router := gin.New()
	registerRoutes(router)

	rec := doJSON(t, router, "GET", "/health", "")
	if rec.Code != http.StatusOK {
		t.Errorf("health status=%d", rec.Code)
	}

	rec = doJSON(t, router, "GET", "/cache/stats", "")
	if rec.Code != http.StatusOK {
		t.Errorf("cache stats status=%d", rec.Code)
	}

	rec = doJSON(t, router, "POST", "/cache/security/clear", "")
	if rec.Code != http.StatusOK {
		t.Errorf("cache clear status=%d body=%s", rec.Code, rec.Body)
	}

	// Security routes must not have been registered.
	rec = doJSON(t, router, "GET", "/security/status", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for security routes when disabled, got %d", rec.Code)
	}
}

//nolint:paralleltest // uses singletons initialized by the preceding tests
func TestRegisterSecurityRoutes(t *testing.T) {
	router := gin.New()
	RegisterSecurityRoutes(router)

	for _, url := range []string{
		"/system/stats",
		"/security/status",
		"/security/stats",
		"/security/wrong-call-states",
		"/security/failed",
		"/security/whitelist",
		"/security/blacklist",
		"/security/esl",
		"/security/rate-limit",
		"/security/untrusted-networks",
		// The singleton's ipset runner was stubbed to a successful list in
		// TestSingleton_SecurityManager, so the firewall endpoint returns 200.
		"/security/iptables",
	} {
		rec := doJSON(t, router, "GET", url, "")
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status=%d body=%s", url, rec.Code, rec.Body)
		}
	}
}

//nolint:paralleltest // mutates global config
func TestRun_ServerStartFailure(t *testing.T) {
	cfg := GetConfig()
	saved := cfg.Server.Port
	cfg.Server.Port = "99999" // out-of-range port: listen must fail

	defer func() { cfg.Server.Port = saved }()

	shutdownChan := make(chan os.Signal, 1)

	err := run(shutdownChan)
	if err == nil {
		t.Fatal("expected server start failure")
	}
}

// TestRun_GracefulShutdown drives the full application lifecycle. It must be
// the last serial test: it shuts down the global security manager and cache.
//
//nolint:paralleltest // drives the application lifecycle on global singletons
func TestRun_GracefulShutdown(t *testing.T) {
	cfg := GetConfig()
	savedPort := cfg.Server.Port
	savedPprof, savedPprofAddr := cfg.Server.PprofEnabled, cfg.Server.PprofAddr
	cfg.Server.Port = "0" // pick any free port
	cfg.Server.PprofEnabled = true
	cfg.Server.PprofAddr = "127.0.0.1:0" // ephemeral port keeps the test hermetic

	defer func() {
		cfg.Server.Port = savedPort
		cfg.Server.PprofEnabled, cfg.Server.PprofAddr = savedPprof, savedPprofAddr
	}()

	shutdownChan := make(chan os.Signal, 1)
	done := make(chan error, 1)

	go func() { done <- run(shutdownChan) }()

	// net/http makes Shutdown-before-ListenAndServe safe, so the signal can
	// be sent immediately; a short pause just lets startup paths execute.
	time.Sleep(100 * time.Millisecond)

	shutdownChan <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not complete graceful shutdown")
	}
}

// TestCacheHelpers_DisabledGlobal swaps the global cache for a disabled one to
// cover the disabled branches of CacheMiddleware and CacheResponse.
//
//nolint:paralleltest // swaps the global cache manager
func TestCacheHelpers_DisabledGlobal(t *testing.T) {
	saved := cacheManager
	cacheManager = &CacheManager{enabled: false}

	defer func() { cacheManager = saved }()

	router := gin.New()
	handled := 0

	router.GET("/cached", CacheMiddleware("disabled-key"), func(c *gin.Context) {
		handled++

		CacheResponse("disabled-key", gin.H{"ok": true}) // disabled: no-op
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	for range 2 {
		rec := doJSON(t, router, "GET", "/cached", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d", rec.Code)
		}
	}

	if handled != 2 {
		t.Errorf("disabled cache must never serve from cache; handler ran %d times", handled)
	}
}

// TestRun_DisabledSubsystems covers run()'s disabled-cache and
// disabled-security branches plus the pprof startup-error branch.
//

func TestRun_DisabledSubsystems(t *testing.T) {
	cfg := GetConfig()
	savedPort := cfg.Server.Port
	savedCache, savedSecurity := cfg.Cache.Enabled, cfg.Security.Enabled
	savedPprof, savedPprofAddr := cfg.Server.PprofEnabled, cfg.Server.PprofAddr
	cfg.Server.Port = "0"
	cfg.Cache.Enabled = false
	cfg.Security.Enabled = false
	cfg.Server.PprofEnabled = true
	cfg.Server.PprofAddr = "256.256.256.256:0" // forces the startup-error branch

	defer func() {
		cfg.Server.Port = savedPort
		cfg.Cache.Enabled, cfg.Security.Enabled = savedCache, savedSecurity
		cfg.Server.PprofEnabled, cfg.Server.PprofAddr = savedPprof, savedPprofAddr
	}()

	t.Setenv("GIN_MODE", "release") // covers the release-mode branch

	shutdownChan := make(chan os.Signal, 1)
	done := make(chan error, 1)

	go func() { done <- run(shutdownChan) }()

	time.Sleep(100 * time.Millisecond)

	shutdownChan <- syscall.SIGTERM

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not complete graceful shutdown")
	}
}
