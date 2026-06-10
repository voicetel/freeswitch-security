package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestProcessor handles API requests using channels.
type RequestProcessor struct {
	securityManager *SecurityManager
	eslManager      *ESLManager

	// Request channels
	statusRequests  chan StatusRequest
	commandRequests chan CommandRequest

	// Worker pool
	workerCount int
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// StatusRequest asks a processor worker for one of the status snapshots.
type StatusRequest struct {
	Type     string
	Response chan StatusResponse
}

type StatusResponse struct {
	Data  any
	Error error
}

type CommandRequest struct {
	Command  string
	Response chan CommandResponse
}

type CommandResponse struct {
	Result string
	Error  error
}

// JSON keys used across the HTTP responses.
const (
	respKeyError   = "error"
	respKeyStatus  = "status"
	respKeyMessage = "message"
	respKeySuccess = "success"

	// statusTypeSecurity is the processor status-request type for security
	// statistics; the other types appear once each in the dispatch switch.
	statusTypeSecurity = "security"

	// keyEnabled is the shared "enabled" key emitted by several JSON views.
	keyEnabled = "enabled"
)

var (
	requestProcessor *RequestProcessor
	processorOnce    sync.Once
)

// InitRequestProcessor initializes the request processor.
func InitRequestProcessor(sm *SecurityManager, em *ESLManager) *RequestProcessor {
	processorOnce.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())

		requestProcessor = &RequestProcessor{
			securityManager: sm,
			eslManager:      em,
			statusRequests:  make(chan StatusRequest, 100),
			commandRequests: make(chan CommandRequest, 50),
			workerCount:     4,
			ctx:             ctx,
			cancel:          cancel,
		}

		// Start workers
		for range requestProcessor.workerCount {
			requestProcessor.wg.Add(2)
			go requestProcessor.processStatusRequests()
			go requestProcessor.processCommandRequests()
		}
	})

	return requestProcessor
}

// Shutdown shuts down the request processor.
func (rp *RequestProcessor) Shutdown() {
	rp.cancel()
	close(rp.statusRequests)
	close(rp.commandRequests)
	rp.wg.Wait()
}

// processStatusRequests handles status requests.
func (rp *RequestProcessor) processStatusRequests() {
	defer rp.wg.Done()

	for {
		select {
		case <-rp.ctx.Done():
			return

		case req, ok := <-rp.statusRequests:
			if !ok {
				return
			}

			var response StatusResponse

			switch req.Type {
			case statusTypeSecurity:
				response.Data = rp.securityManager.GetSecurityStats()
			case "esl":
				response.Data = rp.eslManager.GetESLStats()
			case "whitelist":
				response.Data = rp.securityManager.GetWhitelistedIPs()
			case "blacklist":
				response.Data = rp.securityManager.GetBlacklistedIPs()
			case "failed":
				response.Data = rp.securityManager.GetFailedAttempts()
			case "wrong-states":
				response.Data = rp.securityManager.GetWrongCallStates()
			default:
				response.Error = fmt.Errorf("%w: %s", ErrUnknownStatusType, req.Type)
			}

			// Send response (5s timeout in case the caller has gone away).
			select {
			case req.Response <- response:
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// processCommandRequests handles ESL command requests.
func (rp *RequestProcessor) processCommandRequests() {
	defer rp.wg.Done()

	for {
		select {
		case <-rp.ctx.Done():
			return

		case req, ok := <-rp.commandRequests:
			if !ok {
				return
			}

			var response CommandResponse

			// Execute command
			result, err := rp.eslManager.SendCommand(req.Command)
			response.Result = result
			response.Error = err

			// Send response (10s timeout in case the caller has gone away).
			select {
			case req.Response <- response:
			case <-time.After(10 * time.Second):
			}
		}
	}
}

// CacheMiddleware provides transparent caching for GET requests. Cached
// responses live for the underlying CacheManager's TTL.
func CacheMiddleware(cacheKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.Next()

			return
		}

		cache := GetCacheManager()
		if cache == nil || !cache.enabled {
			c.Next()

			return
		}

		fullKey := "route:" + cacheKey
		if data, found := cache.GetSecurityItem(fullKey); found {
			c.Data(200, "application/json", data)
			c.Abort()

			return
		}

		c.Next()
	}
}

// CacheResponse caches the JSON response after handler execution.
func CacheResponse(cacheKey string, data any) {
	cache := GetCacheManager()
	if cache == nil || !cache.enabled {
		return
	}

	fullKey := "route:" + cacheKey

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal cache data: %v", err)

		return
	}

	cache.CacheSecurityItem(fullKey, jsonData)
}

// validateIP validates an IP address string.
func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %s", ErrInvalidIP, ip)
	}

	return nil
}

// registerRoutes registers all API routes (health, cache, security).
func registerRoutes(router *gin.Engine) {
	config := GetConfig()

	// Gate every state-changing endpoint (the chanDaemon unban fan-out plus
	// the security/cache mutations) on the source-IP allow-list. Safe reads
	// stay open. An empty/unparseable list leaves the API unrestricted.
	allowList, err := parseAllowedIPs(config.Security.ChanDaemon.AllowedAPIIPs)
	if err != nil {
		GetLogger().Error("chanDaemon API allow-list: %v", err)
	}

	router.Use(allowListMiddleware(allowList))

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			respKeyStatus: "ok",
		})
	})

	// Cache stats endpoint
	router.GET("/cache/stats", func(c *gin.Context) {
		cache := GetCacheManager()
		c.JSON(200, cache.GetCacheStats())
	})

	// Cache control endpoints
	router.POST("/cache/security/clear", func(c *gin.Context) {
		GetCacheManager().ClearSecurityCache()
		c.JSON(200, gin.H{respKeyStatus: "security cache cleared"})
	})

	// Register security routes if security is enabled
	if config.Security.Enabled {
		RegisterSecurityRoutes(router)
	}
}

// RegisterSecurityRoutes registers security-related API routes.
func RegisterSecurityRoutes(router *gin.Engine) {
	sm := GetSecurityManager()
	eslManager := GetESLManager()
	rm := eslManager.rateManager
	processor := InitRequestProcessor(sm, eslManager)

	router.GET("/system/stats", systemStatsHandler())

	// chanDaemon (D39) unban fan-out receiver. chanDaemon pushes an
	// unauthenticated DELETE here when a customer/operator lifts a ban; the
	// allow-list middleware is the only gate. Path and method must match what
	// chanDaemon constructs: DELETE {blocker_url}/api/v1/ips/{ip}/block.
	router.DELETE("/api/v1/ips/:ip/block", chanDaemonUnbanHandler(sm))

	security := router.Group("/security")
	{
		security.GET("/status", securityStatusHandler(sm, eslManager))
		security.GET("/stats", CacheMiddleware("stats:security"), securityStatsHandler(sm))
		registerWhitelistRoutes(security, sm)
		registerBlacklistRoutes(security, sm)
		security.GET("/wrong-call-states", func(c *gin.Context) { c.JSON(200, sm.GetWrongCallStates()) })
		security.GET("/failed", func(c *gin.Context) { c.JSON(200, sm.GetFailedAttempts()) })
		security.GET("/iptables", iptablesHandler(sm))
		registerESLRoutes(security, eslManager, processor)
		registerRateLimitRoutes(security, rm)
		registerUntrustedRoutes(security, sm)
	}
}

// systemStatsHandler returns Go runtime statistics.
func systemStatsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ms runtime.MemStats

		runtime.ReadMemStats(&ms)
		c.JSON(200, gin.H{
			"goroutines": runtime.NumGoroutine(),
			"memory": gin.H{
				"allocMb":      ms.Alloc / 1024 / 1024,
				"totalAllocMb": ms.TotalAlloc / 1024 / 1024,
				"sysMb":        ms.Sys / 1024 / 1024,
				"gcRuns":       ms.NumGC,
				"heapObjects":  ms.HeapObjects,
			},
			"cpuCores": runtime.NumCPU(),
		})
	}
}

func securityStatusHandler(sm *SecurityManager, em *ESLManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		enabled, autoBlock := sm.SecurityConfigView()
		c.JSON(200, gin.H{
			keyEnabled:       enabled,
			"autoBlock":      autoBlock,
			"whitelistCount": len(sm.GetWhitelistedIPs()),
			"blacklistCount": len(sm.GetBlacklistedIPs()),
			"eslConnected":   em.IsConnected(),
			"eslHost":        em.Host(),
			"eslPort":        em.Port(),
		})
	}
}

func securityStatsHandler(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := sm.GetSecurityStats()
		CacheResponse("stats:security", stats)
		c.JSON(200, stats)
	}
}

// chanDaemonUnbanHandler lifts a ban pushed by chanDaemon's unban fan-out. It
// removes the IP from the blacklist and the kernel ipset via RemoveFromBlacklist.
// A successful lift is idempotent (removing an unknown IP is a no-op) so a retry
// from chanDaemon is harmless. Returns 400 for a malformed IP, 200 otherwise.
func chanDaemonUnbanHandler(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")

		err := validateIP(ip)
		if err != nil {
			c.JSON(400, gin.H{respKeyError: err.Error()})

			return
		}

		sm.RemoveFromBlacklist(ip)
		c.JSON(200, gin.H{
			"ip":           ip,
			"banned":       false,
			respKeyMessage: "IP unblocked successfully",
		})
	}
}

func iptablesHandler(sm *SecurityManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := sm.GetIPTablesInfo()
		if err != nil {
			c.JSON(500, gin.H{respKeyError: err.Error()})

			return
		}

		c.JSON(200, data)
	}
}

func registerWhitelistRoutes(g *gin.RouterGroup, sm *SecurityManager) {
	whitelist := g.Group("/whitelist")
	{
		// Get whitelisted IPs
		whitelist.GET("", func(c *gin.Context) {
			c.JSON(200, sm.GetWhitelistedIPs())
		})

		// Add IP to whitelist
		whitelist.POST("", func(c *gin.Context) {
			var req struct {
				IP        string `binding:"required" json:"ip"`
				UserID    string `json:"userId"`
				Domain    string `json:"domain"`
				Permanent bool   `json:"permanent"`
			}

			err := c.ShouldBindJSON(&req)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			// Validate IP address
			err = validateIP(req.IP)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			// Set default domain if not provided
			if req.Domain == "" {
				config := GetConfig()
				req.Domain = config.FreeSWITCH.DefaultDomain
			}

			err = sm.AddToWhitelist(req.IP, req.UserID, req.Domain, req.Permanent)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			c.JSON(200, gin.H{
				respKeyStatus:  respKeySuccess,
				respKeyMessage: fmt.Sprintf("IP %s added to whitelist for %s@%s", req.IP, req.UserID, req.Domain),
			})
		})

		// Batch add to whitelist
		whitelist.POST("/batch", func(c *gin.Context) {
			var batch []struct {
				IP        string `binding:"required" json:"ip"`
				UserID    string `json:"userId"`
				Domain    string `json:"domain"`
				Permanent bool   `json:"permanent"`
			}

			err := c.ShouldBindJSON(&batch)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			if len(batch) > 1000 {
				c.JSON(400, gin.H{respKeyError: "batch size exceeds limit of 1000"})

				return
			}

			// Convert to batch request type
			batchReq := make([]BatchWhitelistRequest, len(batch))
			for i, req := range batch {
				batchReq[i] = BatchWhitelistRequest{
					IP:        req.IP,
					UserID:    req.UserID,
					Domain:    req.Domain,
					Permanent: req.Permanent,
				}
			}

			results := sm.AddToWhitelistBatch(batchReq)

			// Format results for response
			responseResults := make([]gin.H, len(results))

			for i, res := range results {
				if res.Error != nil {
					responseResults[i] = gin.H{"ip": res.IP, respKeyError: res.Error.Error()}
				} else {
					responseResults[i] = gin.H{"ip": res.IP, respKeyStatus: respKeySuccess}
				}
			}

			c.JSON(200, gin.H{"results": responseResults})
		})

		// Remove IP from whitelist
		whitelist.DELETE("/:ip", func(c *gin.Context) {
			ip := c.Param("ip")
			sm.RemoveFromWhitelist(ip)
			c.JSON(200, gin.H{respKeyStatus: respKeySuccess, respKeyMessage: fmt.Sprintf("IP %s removed from whitelist", ip)})
		})

		// Check if IP is whitelisted
		whitelist.GET("/:ip", func(c *gin.Context) {
			ip := c.Param("ip")
			entry, exists := sm.GetWhitelistEntry(ip)

			if !exists {
				c.JSON(200, gin.H{
					"ip":          ip,
					"whitelisted": false,
				})

				return
			}

			c.JSON(200, gin.H{
				"ip":          ip,
				"whitelisted": true,
				"userId":      entry.UserID,
				"domain":      entry.Domain,
			})
		})
	}
}

func registerBlacklistRoutes(g *gin.RouterGroup, sm *SecurityManager) {
	blacklist := g.Group("/blacklist")
	{
		// Get blacklisted IPs
		blacklist.GET("", func(c *gin.Context) {
			c.JSON(200, sm.GetBlacklistedIPs())
		})

		// Add IP to blacklist
		blacklist.POST("", func(c *gin.Context) {
			var req struct {
				IP        string `binding:"required" json:"ip"`
				Reason    string `json:"reason"`
				Permanent bool   `json:"permanent"`
			}

			err := c.ShouldBindJSON(&req)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			// Validate IP address
			err = validateIP(req.IP)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			err = sm.AddToBlacklist(req.IP, req.Reason, req.Permanent)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			c.JSON(200, gin.H{respKeyStatus: respKeySuccess, respKeyMessage: fmt.Sprintf("IP %s added to blacklist", req.IP)})
		})

		// Batch add to blacklist
		blacklist.POST("/batch", func(c *gin.Context) {
			var batch []struct {
				IP        string `binding:"required" json:"ip"`
				Reason    string `json:"reason"`
				Permanent bool   `json:"permanent"`
			}

			err := c.ShouldBindJSON(&batch)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			if len(batch) > 1000 {
				c.JSON(400, gin.H{respKeyError: "batch size exceeds limit of 1000"})

				return
			}

			// Convert to batch request type
			batchReq := make([]BatchBlacklistRequest, len(batch))
			for i, req := range batch {
				batchReq[i] = BatchBlacklistRequest{
					IP:        req.IP,
					Reason:    req.Reason,
					Permanent: req.Permanent,
				}
			}

			results := sm.AddToBlacklistBatch(batchReq)

			// Format results for response
			responseResults := make([]gin.H, len(results))

			for i, res := range results {
				if res.Error != nil {
					responseResults[i] = gin.H{"ip": res.IP, respKeyError: res.Error.Error()}
				} else {
					responseResults[i] = gin.H{"ip": res.IP, respKeyStatus: respKeySuccess}
				}
			}

			c.JSON(200, gin.H{"results": responseResults})
		})

		// Remove IP from blacklist
		blacklist.DELETE("/:ip", func(c *gin.Context) {
			ip := c.Param("ip")
			sm.RemoveFromBlacklist(ip)
			c.JSON(200, gin.H{respKeyStatus: respKeySuccess, respKeyMessage: fmt.Sprintf("IP %s removed from blacklist", ip)})
		})

		// Check if IP is blacklisted
		blacklist.GET("/:ip", func(c *gin.Context) {
			ip := c.Param("ip")
			c.JSON(200, gin.H{
				"ip":          ip,
				"blacklisted": sm.IsIPBlacklisted(ip),
			})
		})
	}
}

func registerESLRoutes(g *gin.RouterGroup, eslManager *ESLManager, processor *RequestProcessor) {
	esl := g.Group("/esl")
	{
		// Get ESL status - now includes memory pool and dynamic channel stats
		esl.GET("", func(c *gin.Context) {
			c.JSON(200, eslManager.GetESLStats())
		})

		// Set log level
		esl.POST("/log_level", func(c *gin.Context) {
			var req struct {
				Level string `binding:"required" json:"level"` // error, info, debug, trace
			}

			err := c.ShouldBindJSON(&req)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			eslManager.SetESLLogLevel(req.Level)
			c.JSON(200, gin.H{
				respKeyStatus:  respKeySuccess,
				respKeyMessage: "ESL log level set to " + req.Level,
			})
		})

		// Reconnect ESL
		esl.POST("/reconnect", func(c *gin.Context) {
			eslManager.ReconnectESL()
			c.JSON(200, gin.H{
				respKeyStatus:  respKeySuccess,
				respKeyMessage: "ESL reconnection initiated",
			})
		})

		// Send command with timeout using channels
		esl.POST("/command", func(c *gin.Context) {
			var req struct {
				Command string `binding:"required" json:"command"`
			}

			err := c.ShouldBindJSON(&req)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
			defer cancel()

			respChan := make(chan CommandResponse, 1)

			select {
			case processor.commandRequests <- CommandRequest{
				Command:  req.Command,
				Response: respChan,
			}:
				select {
				case resp := <-respChan:
					if resp.Error != nil {
						c.JSON(500, gin.H{respKeyError: resp.Error.Error()})
					} else {
						c.JSON(200, gin.H{
							"command":  req.Command,
							"response": resp.Result,
						})
					}
				case <-ctx.Done():
					c.JSON(504, gin.H{respKeyError: "command execution timeout"})
				}
			case <-ctx.Done():
				c.JSON(504, gin.H{respKeyError: "command queue timeout"})
			}
		})
	}
}

func registerRateLimitRoutes(g *gin.RouterGroup, rm *RateManager) {
	rateLimit := g.Group("/rate-limit")
	{
		// Get rate limiting status
		rateLimit.GET("", func(c *gin.Context) {
			c.JSON(200, rm.RateLimitConfigView())
		})

		// Get current call rates
		rateLimit.GET("/calls", func(c *gin.Context) {
			c.JSON(200, rm.GetCallRates())
		})

		// Get current registration rates
		rateLimit.GET("/registrations", func(c *gin.Context) {
			c.JSON(200, rm.GetRegistrationRates())
		})
	}
}

func registerUntrustedRoutes(g *gin.RouterGroup, sm *SecurityManager) {
	untrustedNetworks := g.Group("/untrusted-networks")
	{
		// Get all untrusted network patterns
		untrustedNetworks.GET("", func(c *gin.Context) {
			c.JSON(200, sm.GetUntrustedNetworks())
		})

		// Add an untrusted network pattern
		untrustedNetworks.POST("", func(c *gin.Context) {
			var req struct {
				Pattern string `binding:"required" json:"pattern"`
			}

			err := c.ShouldBindJSON(&req)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			err = sm.AddUntrustedNetwork(req.Pattern)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			c.JSON(200, gin.H{
				respKeyStatus:  respKeySuccess,
				respKeyMessage: fmt.Sprintf("Pattern '%s' added to untrusted networks", req.Pattern),
			})
		})

		// Remove an untrusted network pattern
		untrustedNetworks.DELETE("/:pattern", func(c *gin.Context) {
			pattern := c.Param("pattern")

			err := sm.RemoveUntrustedNetwork(pattern)
			if err != nil {
				c.JSON(400, gin.H{respKeyError: err.Error()})

				return
			}

			c.JSON(200, gin.H{
				respKeyStatus:  respKeySuccess,
				respKeyMessage: fmt.Sprintf("Pattern '%s' removed from untrusted networks", pattern),
			})
		})

		// Test if a domain matches any untrusted pattern
		untrustedNetworks.GET("/test/:domain", func(c *gin.Context) {
			domain := c.Param("domain")
			c.JSON(200, gin.H{
				"domain":      domain,
				"isUntrusted": sm.IsUntrustedDomain(domain),
			})
		})
	}
}
