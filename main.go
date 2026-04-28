package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

// Global server instance for graceful shutdown.
var httpServer *http.Server

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

		log.Println("Cache system initialized")
	} else {
		log.Println("Cache system is disabled")
	}

	// Initialize security manager if enabled
	var securityManager *SecurityManager

	var eslManager *ESLManager

	if config.Security.Enabled {
		InitSecurityManager()

		securityManager = GetSecurityManager()
		eslManager = InitESLManager(securityManager)

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

	// Create HTTP server. ReadHeaderTimeout protects against Slowloris-style
	// attacks that hold the connection open by trickling header bytes.
	host := config.Server.Host
	port := config.Server.Port
	httpServer = &http.Server{
		Addr:              fmt.Sprintf("%s:%s", host, port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Starting FreeSWITCH Security server on %s:%s...", host, port)

		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Handle graceful shutdown
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received
	sig := <-shutdownChan
	log.Printf("Received signal %s, initiating graceful shutdown...", sig)

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown sequence
	log.Println("Shutting down HTTP server...")

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	}

	// Shutdown ESL manager if initialized
	if eslManager != nil {
		log.Println("Shutting down ESL manager...")
		eslManager.Shutdown()
	}

	// Shutdown security manager if initialized
	if securityManager != nil {
		log.Println("Shutting down security manager...")
		securityManager.Shutdown()
	}

	// Close cache
	log.Println("Closing cache...")
	CloseCache()

	log.Println("Graceful shutdown complete")
}
