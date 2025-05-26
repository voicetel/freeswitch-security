package main

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RequestProcessor handles API requests using channels
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

// Request types
type StatusRequest struct {
	Type     string
	Response chan StatusResponse
}

type StatusResponse struct {
	Data  interface{}
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

var (
	requestProcessor *RequestProcessor
	processorOnce    sync.Once
)

// InitRequestProcessor initializes the request processor
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
		for i := 0; i < requestProcessor.workerCount; i++ {
			requestProcessor.wg.Add(2)
			go requestProcessor.processStatusRequests()
			go requestProcessor.processCommandRequests()
		}
	})

	return requestProcessor
}

// processStatusRequests handles status requests
func (rp *RequestProcessor) processStatusRequests() {
	defer rp.wg.Done()

	for {
		select {
		case <-rp.ctx.Done():
			return

		case req := <-rp.statusRequests:
			var response StatusResponse

			switch req.Type {
			case "security":
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
			case "channel-stats":
				response.Data = rp.securityManager.GetChannelStats()
			default:
				response.Error = fmt.Errorf("unknown status type: %s", req.Type)
			}

			// Send response
			select {
			case req.Response <- response:
			case <-time.After(5 * time.Second):
				// Timeout sending response
			}
		}
	}
}

// processCommandRequests handles ESL command requests
func (rp *RequestProcessor) processCommandRequests() {
	defer rp.wg.Done()

	for {
		select {
		case <-rp.ctx.Done():
			return

		case req := <-rp.commandRequests:
			var response CommandResponse

			// Execute command
			result, err := rp.eslManager.SendCommand(req.Command)
			response.Result = result
			response.Error = err

			// Send response
			select {
			case req.Response <- response:
			case <-time.After(10 * time.Second):
				// Timeout sending response
			}
		}
	}
}

// Shutdown shuts down the request processor
func (rp *RequestProcessor) Shutdown() {
	rp.cancel()
	close(rp.statusRequests)
	close(rp.commandRequests)
	rp.wg.Wait()
}

// RegisterSecurityRoutes registers security-related API routes with channel-based processing
func RegisterSecurityRoutes(router *gin.Engine) {
	// Initialize security manager if not already initialized
	sm := GetSecurityManager()

	// Initialize ESL manager if not already initialized
	eslManager := GetESLManager()

	// Initialize rate manager
	rm := eslManager.rateManager

	// Initialize request processor
	processor := InitRequestProcessor(sm, eslManager)

	// Add system stats endpoint
	router.GET("/system/stats", func(c *gin.Context) {
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)

		c.JSON(200, gin.H{
			"goroutines": runtime.NumGoroutine(),
			"memory": gin.H{
				"alloc_mb":       memStats.Alloc / 1024 / 1024,
				"total_alloc_mb": memStats.TotalAlloc / 1024 / 1024,
				"sys_mb":         memStats.Sys / 1024 / 1024,
				"gc_runs":        memStats.NumGC,
				"heap_objects":   memStats.HeapObjects,
			},
			"cpu_cores": runtime.NumCPU(),
		})
	})

	// Security group
	security := router.Group("/security")
	{
		// Get security status
		security.GET("/status", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"enabled":         sm.securityConfig.Enabled,
				"auto_block":      sm.securityConfig.AutoBlockEnabled,
				"whitelist_count": len(sm.GetWhitelistedIPs()),
				"blacklist_count": len(sm.GetBlacklistedIPs()),
				"esl_connected":   eslManager.eslConnected,
				"esl_host":        eslManager.eslConfig.Host,
				"esl_port":        eslManager.eslConfig.Port,
			})
		})

		// Get security statistics with caching
		security.GET("/stats", func(c *gin.Context) {
			// Check cache first
			cache := GetCacheManager()
			cacheKey := "stats:security"

			if cache.enabled {
				if data, found := cache.GetSecurityItem(cacheKey); found {
					c.Data(200, "application/json", data)
					return
				}
			}

			stats := sm.GetSecurityStats()
			c.JSON(200, stats)

			// Cache the result asynchronously
			if cache.enabled {
				if data, err := json.Marshal(stats); err == nil {
					cache.CacheSecurityItemAsync(cacheKey, data)
				}
			}
		})

		// Get dynamic channel statistics
		security.GET("/channels", func(c *gin.Context) {
			respChan := make(chan StatusResponse, 1)

			select {
			case processor.statusRequests <- StatusRequest{
				Type:     "channel-stats",
				Response: respChan,
			}:
				select {
				case resp := <-respChan:
					if resp.Error != nil {
						c.JSON(500, gin.H{"error": resp.Error.Error()})
					} else {
						c.JSON(200, resp.Data)
					}
				case <-time.After(5 * time.Second):
					c.JSON(504, gin.H{"error": "timeout getting channel stats"})
				}
			case <-time.After(1 * time.Second):
				c.JSON(504, gin.H{"error": "status queue timeout"})
			}
		})

		// Whitelist management with batch operations
		whitelist := security.Group("/whitelist")
		{
			// Get whitelisted IPs
			whitelist.GET("", func(c *gin.Context) {
				c.JSON(200, sm.GetWhitelistedIPs())
			})

			// Add IP to whitelist
			whitelist.POST("", func(c *gin.Context) {
				var req struct {
					IP        string `json:"ip" binding:"required"`
					UserID    string `json:"user_id"`
					Domain    string `json:"domain"`
					Permanent bool   `json:"permanent"`
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				// Set default domain if not provided
				if req.Domain == "" {
					config := GetConfig()
					req.Domain = config.FreeSWITCH.DefaultDomain
				}

				err := sm.AddToWhitelist(req.IP, req.UserID, req.Domain, req.Permanent)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{"status": "success", "message": fmt.Sprintf("IP %s added to whitelist for %s@%s", req.IP, req.UserID, req.Domain)})
			})

			// Batch add to whitelist
			whitelist.POST("/batch", func(c *gin.Context) {
				var batch []struct {
					IP        string `json:"ip" binding:"required"`
					UserID    string `json:"user_id"`
					Domain    string `json:"domain"`
					Permanent bool   `json:"permanent"`
				}

				if err := c.ShouldBindJSON(&batch); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				// Process batch asynchronously
				results := make([]gin.H, len(batch))
				var wg sync.WaitGroup

				for i, req := range batch {
					wg.Add(1)
					go func(idx int, r struct {
						IP        string `json:"ip" binding:"required"`
						UserID    string `json:"user_id"`
						Domain    string `json:"domain"`
						Permanent bool   `json:"permanent"`
					}) {
						defer wg.Done()

						if r.Domain == "" {
							config := GetConfig()
							r.Domain = config.FreeSWITCH.DefaultDomain
						}

						err := sm.AddToWhitelist(r.IP, r.UserID, r.Domain, r.Permanent)
						if err != nil {
							results[idx] = gin.H{"ip": r.IP, "error": err.Error()}
						} else {
							results[idx] = gin.H{"ip": r.IP, "status": "success"}
						}
					}(i, req)
				}

				wg.Wait()
				c.JSON(200, gin.H{"results": results})
			})

			// Remove IP from whitelist
			whitelist.DELETE("/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				err := sm.RemoveFromWhitelist(ip)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{"status": "success", "message": fmt.Sprintf("IP %s removed from whitelist", ip)})
			})

			// Check if IP is whitelisted
			whitelist.GET("/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				isWhitelisted := sm.IsIPWhitelisted(ip)

				// Get the domain if IP is whitelisted
				var domain string
				var userId string
				if isWhitelisted {
					sm.mutex.RLock()
					if entry, exists := sm.whitelist[ip]; exists {
						domain = entry.Domain
						userId = entry.UserID
					}
					sm.mutex.RUnlock()
				}

				c.JSON(200, gin.H{
					"ip":          ip,
					"whitelisted": isWhitelisted,
					"user_id":     userId,
					"domain":      domain,
				})
			})
		}

		// Blacklist management
		blacklist := security.Group("/blacklist")
		{
			// Get blacklisted IPs
			blacklist.GET("", func(c *gin.Context) {
				c.JSON(200, sm.GetBlacklistedIPs())
			})

			// Add IP to blacklist
			blacklist.POST("", func(c *gin.Context) {
				var req struct {
					IP        string `json:"ip" binding:"required"`
					Reason    string `json:"reason"`
					Permanent bool   `json:"permanent"`
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				err := sm.AddToBlacklist(req.IP, req.Reason, req.Permanent)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{"status": "success", "message": fmt.Sprintf("IP %s added to blacklist", req.IP)})
			})

			// Batch add to blacklist
			blacklist.POST("/batch", func(c *gin.Context) {
				var batch []struct {
					IP        string `json:"ip" binding:"required"`
					Reason    string `json:"reason"`
					Permanent bool   `json:"permanent"`
				}

				if err := c.ShouldBindJSON(&batch); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				// Process batch asynchronously
				results := make([]gin.H, len(batch))
				var wg sync.WaitGroup

				for i, req := range batch {
					wg.Add(1)
					go func(idx int, r struct {
						IP        string `json:"ip" binding:"required"`
						Reason    string `json:"reason"`
						Permanent bool   `json:"permanent"`
					}) {
						defer wg.Done()

						err := sm.AddToBlacklist(r.IP, r.Reason, r.Permanent)
						if err != nil {
							results[idx] = gin.H{"ip": r.IP, "error": err.Error()}
						} else {
							results[idx] = gin.H{"ip": r.IP, "status": "success"}
						}
					}(i, req)
				}

				wg.Wait()
				c.JSON(200, gin.H{"results": results})
			})

			// Remove IP from blacklist
			blacklist.DELETE("/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				err := sm.RemoveFromBlacklist(ip)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{"status": "success", "message": fmt.Sprintf("IP %s removed from blacklist", ip)})
			})

			// Check if IP is blacklisted
			blacklist.GET("/:ip", func(c *gin.Context) {
				ip := c.Param("ip")
				isBlacklisted := sm.IsIPBlacklisted(ip)

				c.JSON(200, gin.H{
					"ip":          ip,
					"blacklisted": isBlacklisted,
				})
			})
		}

		// Wrong call states management
		security.GET("/wrong-call-states", func(c *gin.Context) {
			c.JSON(200, sm.GetWrongCallStates())
		})

		// Failed attempts management
		security.GET("/failed", func(c *gin.Context) {
			c.JSON(200, sm.GetFailedAttempts())
		})

		// View iptables rules
		security.GET("/iptables", func(c *gin.Context) {
			rules, err := getIPTablesRules(sm.securityConfig.IPTablesChain)
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}

			c.JSON(200, gin.H{
				"chain": sm.securityConfig.IPTablesChain,
				"rules": rules,
			})
		})

		// ESL management with channel-based command processing
		esl := security.Group("/esl")
		{
			// Get ESL status - now includes memory pool and dynamic channel stats
			esl.GET("", func(c *gin.Context) {
				c.JSON(200, eslManager.GetESLStats())
			})

			// Set log level
			esl.POST("/log_level", func(c *gin.Context) {
				var req struct {
					Level string `json:"level" binding:"required"` // error, info, debug, trace
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				eslManager.SetESLLogLevel(req.Level)
				c.JSON(200, gin.H{
					"status":  "success",
					"message": fmt.Sprintf("ESL log level set to %s", req.Level),
				})
			})

			// Reconnect ESL
			esl.POST("/reconnect", func(c *gin.Context) {
				eslManager.ReconnectESL()
				c.JSON(200, gin.H{
					"status":  "success",
					"message": "ESL reconnection initiated",
				})
			})

			// Send command with timeout using channels
			esl.POST("/command", func(c *gin.Context) {
				var req struct {
					Command string `json:"command" binding:"required"`
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
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
							c.JSON(500, gin.H{"error": resp.Error.Error()})
						} else {
							c.JSON(200, gin.H{
								"command":  req.Command,
								"response": resp.Result,
							})
						}
					case <-ctx.Done():
						c.JSON(504, gin.H{"error": "command execution timeout"})
					}
				case <-ctx.Done():
					c.JSON(504, gin.H{"error": "command queue timeout"})
				}
			})
		}

		// Rate limiting management
		rateLimit := security.Group("/rate-limit")
		{
			// Get rate limiting status
			rateLimit.GET("", func(c *gin.Context) {
				c.JSON(200, gin.H{
					"enabled":              rm.rateLimitConfig.Enabled,
					"call_rate_limit":      rm.rateLimitConfig.CallRateLimit,
					"call_rate_interval":   rm.rateLimitConfig.CallRateInterval,
					"registration_limit":   rm.rateLimitConfig.RegistrationLimit,
					"registration_window":  rm.rateLimitConfig.RegistrationWindow,
					"auto_block_on_exceed": rm.rateLimitConfig.AutoBlockOnExceed,
					"block_duration":       rm.rateLimitConfig.BlockDuration,
					"whitelist_bypass":     rm.rateLimitConfig.WhitelistBypass,
					"cleanup_interval":     rm.rateLimitConfig.CleanupInterval,
				})
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

		// Untrusted networks management
		untrustedNetworks := security.Group("/untrusted-networks")
		{
			// Get all untrusted network patterns
			untrustedNetworks.GET("", func(c *gin.Context) {
				c.JSON(200, sm.GetUntrustedNetworks())
			})

			// Add an untrusted network pattern
			untrustedNetworks.POST("", func(c *gin.Context) {
				var req struct {
					Pattern string `json:"pattern" binding:"required"`
				}

				if err := c.ShouldBindJSON(&req); err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				err := sm.AddUntrustedNetwork(req.Pattern)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{
					"status":  "success",
					"message": fmt.Sprintf("Pattern '%s' added to untrusted networks", req.Pattern),
				})
			})

			// Remove an untrusted network pattern
			untrustedNetworks.DELETE("/:pattern", func(c *gin.Context) {
				pattern := c.Param("pattern")
				err := sm.RemoveUntrustedNetwork(pattern)
				if err != nil {
					c.JSON(400, gin.H{"error": err.Error()})
					return
				}

				c.JSON(200, gin.H{
					"status":  "success",
					"message": fmt.Sprintf("Pattern '%s' removed from untrusted networks", pattern),
				})
			})

			// Test if a domain matches any untrusted pattern
			untrustedNetworks.GET("/test/:domain", func(c *gin.Context) {
				domain := c.Param("domain")
				isUntrusted := sm.IsUntrustedDomain(domain)

				c.JSON(200, gin.H{
					"domain":       domain,
					"is_untrusted": isUntrusted,
				})
			})
		}
	}
}
