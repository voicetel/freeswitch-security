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
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	err := run(shutdownChan)
	if err != nil {
		log.Fatalf("%v", err)
	}
}

// run starts the application and blocks until a value arrives on
// shutdownChan (or the HTTP server fails to start), then performs the
// graceful shutdown sequence. The signal channel is injected so tests can
// drive the full lifecycle without process signals.
func run(shutdownChan <-chan os.Signal) error {
	// Load configuration
	config, err := LoadConfig("config.json")
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Initialize logging system
	logger := GetLogger()
	logger.SetLogLevelFromString(config.Security.ESLLogLevel)

	// Initialize cache if enabled
	if config.Cache.Enabled {
		err := InitCache()
		if err != nil {
			return fmt.Errorf("failed to initialize cache: %w", err)
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

	// Optional pprof diagnostics server, loopback-only by default. A failure
	// to start diagnostics is logged but never takes down the service.
	var pprofServer *http.Server

	if config.Server.PprofEnabled {
		pprofServer, err = startPprof(config.Server.PprofAddr)
		if err != nil {
			log.Printf("Failed to start pprof diagnostics on %q: %v", config.Server.PprofAddr, err)
		} else {
			log.Printf("pprof diagnostics listening on %s", pprofServer.Addr)
		}
	}

	// Start server in a goroutine; a startup failure is reported through
	// serverErr instead of aborting the process from inside the goroutine.
	serverErr := make(chan error, 1)

	go func() {
		log.Printf("Starting FreeSWITCH Security server on %s:%s...", host, port)

		err := httpServer.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	// Block until a shutdown signal is received or the server dies.
	select {
	case err := <-serverErr:
		return fmt.Errorf("failed to start server: %w", err)
	case sig := <-shutdownChan:
		log.Printf("Received signal %s, initiating graceful shutdown...", sig)
	}

	// Create a context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown sequence
	log.Println("Shutting down HTTP server...")

	err = httpServer.Shutdown(ctx)
	if err != nil {
		log.Printf("HTTP server forced to shutdown: %v", err)
	}

	// Shutdown pprof diagnostics if running
	if pprofServer != nil {
		err := pprofServer.Shutdown(ctx)
		if err != nil {
			log.Printf("pprof server forced to shutdown: %v", err)
		}
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

	return nil
}
