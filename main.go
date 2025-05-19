package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logging system
	logger := GetLogger()
	logger.SetLogLevelFromString(config.Security.ESLLogLevel)

	// Initialize cache if enabled
	if config.Cache.Enabled {
		if err := InitCache(); err != nil {
			log.Fatalf("Failed to initialize cache: %v", err)
		}
		defer CloseCache()
		log.Println("Cache system initialized")
	} else {
		log.Println("Cache system is disabled")
	}

	// Initialize security manager if enabled
	if config.Security.Enabled {
		if err := InitSecurityManager(); err != nil {
			log.Fatalf("Failed to initialize security manager: %v", err)
		}

		// Initialize ESL manager after security manager
		securityManager := GetSecurityManager()
		_, err := InitESLManager(securityManager)
		if err != nil {
			log.Printf("Failed to initialize ESL manager: %v", err)
		}

		log.Println("Security manager initialized")
	} else {
		log.Println("Security system is disabled")
	}

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "release" || !config.Server.LogRequests {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize Gin router
	router := gin.Default()

	// Register routes
	registerRoutes(router)

	// Handle graceful shutdown
	go func() {
		// Create channel to listen for OS signals
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)

		// Block until a signal is received
		sig := <-c
		log.Printf("Received signal %s, shutting down...", sig)

		// Cleanup resources
		CloseCache()
		os.Exit(0)
	}()

	// Start the server
	host := config.Server.Host
	port := config.Server.Port
	fmt.Printf("Starting FreeSWITCH Security server on %s:%s...\n", host, port)

	// Listen and serve
	if err := router.Run(fmt.Sprintf("%s:%s", host, port)); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// registerRoutes sets up all API routes
func registerRoutes(router *gin.Engine) {
	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// Add cache stats endpoint
	router.GET("/cache/stats", func(c *gin.Context) {
		cache := GetCacheManager()
		c.JSON(200, cache.GetCacheStats())
	})

	// Add cache control endpoints
	router.POST("/cache/security/clear", func(c *gin.Context) {
		cache := GetCacheManager()
		if err := cache.ClearSecurityCache(); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		c.JSON(200, gin.H{"status": "security cache cleared"})
	})

	// Register security routes if security is enabled
	config := GetConfig()
	if config.Security.Enabled {
		RegisterSecurityRoutes(router)
		log.Println("Security API routes registered")
	}
}
