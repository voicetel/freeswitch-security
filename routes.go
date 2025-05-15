package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
)

// RegisterSecurityRoutes registers security-related API routes
func RegisterSecurityRoutes(router *gin.Engine) {
	// Initialize security manager if not already initialized
	sm := GetSecurityManager()

	// Initialize ESL manager if not already initialized
	eslManager := GetESLManager()

	// Initialize rate manager
	rm := eslManager.rateManager

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

		// Get security statistics
		security.GET("/stats", func(c *gin.Context) {
			c.JSON(200, sm.GetSecurityStats())
		})

		// Whitelist management
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

		// ESL management
		esl := security.Group("/esl")
		{
			// Get ESL status
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
