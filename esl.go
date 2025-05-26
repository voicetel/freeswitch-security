package main

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// ESLManager handles FreeSWITCH Event Socket Layer connections
type ESLManager struct {
	securityManager *SecurityManager
	eslClient       *eventsocket.Connection
	eslConfig       ESLConfig
	eslConnected    bool
	eslDisconnected chan bool
	eslLogLevel     EslLogLevel
	statistics      struct {
		ConnectionAttempts int64
		ConnectionErrors   int64
		EventsProcessed    int64
		EventsQueued       int64
		EventsDropped      int64
	}
	rateManager   *RateManager
	rateManagerMu sync.Mutex

	// Worker pool components
	eventQueue   chan *eventsocket.Event
	workerCount  int
	maxQueueSize int

	// Shutdown mechanism
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	shutdown   bool
	shutdownMu sync.RWMutex
}

// ESLConfig holds ESL-related configuration
type ESLConfig struct {
	Host             string
	Port             string
	Password         string
	LogLevel         string
	ReconnectBackoff string
	WorkerCount      int // Number of worker goroutines
	MaxQueueSize     int // Maximum events in queue
}

// EventWorker processes events from the queue
type EventWorker struct {
	id      int
	manager *ESLManager
	logger  *Logger
}

var (
	eslManager     *ESLManager
	eslManagerOnce sync.Once
)

// InitESLManager initializes the ESL manager
func InitESLManager(securityManager *SecurityManager) (*ESLManager, error) {
	var err error
	eslManagerOnce.Do(func() {
		logger := GetLogger()
		config := GetConfig()

		// Parse log level
		var logLevel EslLogLevel = LogLevelInfo
		switch strings.ToLower(config.Security.ESLLogLevel) {
		case "error":
			logLevel = LogLevelError
		case "info":
			logLevel = LogLevelInfo
		case "debug":
			logLevel = LogLevelDebug
		case "trace":
			logLevel = LogLevelTrace
		}

		logger.SetLogLevel(logLevel)

		// Determine worker count (default to number of CPU cores)
		workerCount := runtime.NumCPU()
		if workerCount < 2 {
			workerCount = 2 // Minimum 2 workers
		}
		if workerCount > 8 {
			workerCount = 8 // Cap at 8 workers
		}

		// Create ESL config
		eslConfig := ESLConfig{
			Host:             config.Security.ESLHost,
			Port:             config.Security.ESLPort,
			Password:         config.Security.ESLPassword,
			LogLevel:         config.Security.ESLLogLevel,
			ReconnectBackoff: config.Security.ReconnectBackoff,
			WorkerCount:      workerCount,
			MaxQueueSize:     1000, // Default queue size
		}

		// Initialize rate manager
		rateManager := NewRateManager(securityManager)

		// Create context for shutdown
		ctx, cancel := context.WithCancel(context.Background())

		// Initialize ESL manager
		eslManager = &ESLManager{
			securityManager: securityManager,
			eslConfig:       eslConfig,
			eslDisconnected: make(chan bool, 1),
			eslLogLevel:     logLevel,
			rateManager:     rateManager,
			eventQueue:      make(chan *eventsocket.Event, eslConfig.MaxQueueSize),
			workerCount:     eslConfig.WorkerCount,
			maxQueueSize:    eslConfig.MaxQueueSize,
			ctx:             ctx,
			cancel:          cancel,
			shutdown:        false,
		}

		logger.Info("Initializing ESL manager with %d workers, queue size: %d",
			eslConfig.WorkerCount, eslConfig.MaxQueueSize)

		// Start worker pool
		eslManager.startWorkerPool()

		// Start ESL connection
		logger.Info("Starting ESL connection")
		eslManager.wg.Add(1)
		go eslManager.startESLConnection()
	})

	return eslManager, err
}

// startWorkerPool starts the event processing workers
func (em *ESLManager) startWorkerPool() {
	logger := GetLogger()

	for i := 0; i < em.workerCount; i++ {
		worker := &EventWorker{
			id:      i + 1,
			manager: em,
			logger:  logger,
		}

		em.wg.Add(1)
		go worker.run()

		logger.Info("Started event worker #%d", worker.id)
	}
}

// run is the main loop for each worker
func (w *EventWorker) run() {
	defer w.manager.wg.Done()

	w.logger.Debug("Worker #%d started", w.id)

	for {
		select {
		case <-w.manager.ctx.Done():
			w.logger.Debug("Worker #%d shutting down", w.id)
			return

		case event, ok := <-w.manager.eventQueue:
			if !ok {
				w.logger.Debug("Worker #%d: event queue closed", w.id)
				return
			}

			// Process the event
			w.processEvent(event)

			// Update statistics
			atomic.AddInt64(&w.manager.statistics.EventsProcessed, 1)
		}
	}
}

// processEvent handles a single event
func (w *EventWorker) processEvent(ev *eventsocket.Event) {
	startTime := time.Now()

	// Log event processing in trace mode
	if w.logger.GetLogLevel() >= LogLevelTrace {
		w.logger.Trace("Worker #%d processing event", w.id)
	}

	// Extract event type
	eventName := ev.Get("Event-Name")
	eventSubclass := ev.Get("Event-Subclass")

	// Process based on event type
	switch eventName {
	case "CUSTOM":
		switch eventSubclass {
		case "sofia::register":
			w.handleSuccessfulRegistration(ev)
		case "sofia::register_failure":
			w.handleFailedRegistration(ev)
		case "sofia::wrong_call_state":
			w.handleWrongCallState(ev)
		default:
			w.logger.Debug("Worker #%d: Unhandled CUSTOM event subclass: %s", w.id, eventSubclass)
		}
	case "CHANNEL_CREATE":
		w.handleChannelCreate(ev)
	default:
		w.logger.Debug("Worker #%d: Unhandled event type: %s", w.id, eventName)
	}

	// Log processing time in debug mode
	if w.logger.GetLogLevel() >= LogLevelDebug {
		processingTime := time.Since(startTime)
		w.logger.Debug("Worker #%d processed %s event in %v", w.id, eventName, processingTime)
	}
}

// GetESLManager returns the ESL manager instance
func GetESLManager() *ESLManager {
	if eslManager == nil {
		securityManager := GetSecurityManager()
		_, err := InitESLManager(securityManager)
		if err != nil {
			GetLogger().Error("Error initializing ESL manager: %v", err)
		}
	}
	return eslManager
}

// Shutdown gracefully shuts down the ESL manager
func (em *ESLManager) Shutdown() {
	logger := GetLogger()
	logger.Info("Shutting down ESL manager...")

	// Set shutdown flag
	em.shutdownMu.Lock()
	em.shutdown = true
	em.shutdownMu.Unlock()

	// Cancel the context to signal shutdown
	em.cancel()

	// Close ESL connection if connected
	if em.eslConnected && em.eslClient != nil {
		em.eslClient.Close()
	}

	// Close event queue to signal workers to exit
	close(em.eventQueue)

	// Shutdown rate manager
	if em.rateManager != nil {
		em.rateManager.Shutdown()
	}

	// Wait for all goroutines to finish
	em.wg.Wait()

	logger.Info("ESL manager shutdown complete")
}

// isShuttingDown checks if we're in shutdown mode
func (em *ESLManager) isShuttingDown() bool {
	em.shutdownMu.RLock()
	defer em.shutdownMu.RUnlock()
	return em.shutdown
}

// startESLConnection connects to the FreeSWITCH ESL interface and listens for events
func (em *ESLManager) startESLConnection() {
	defer em.wg.Done()

	logger := GetLogger()

	backoffDuration, err := time.ParseDuration(em.eslConfig.ReconnectBackoff)
	if err != nil {
		logger.Error("Error parsing reconnect backoff: %v, using default 5s", err)
		backoffDuration = 5 * time.Second
	}

	reconnectAttempt := atomic.LoadInt64(&em.statistics.ConnectionAttempts)

	// Calculate dynamic backoff
	currentBackoff := backoffDuration
	if reconnectAttempt > 0 {
		maxBackoff := 60 * time.Second
		calculatedBackoff := backoffDuration * time.Duration(1<<uint(reconnectAttempt-1))
		if calculatedBackoff > maxBackoff {
			calculatedBackoff = maxBackoff
		}
		currentBackoff = calculatedBackoff
	}

	for {
		// Check if we're shutting down
		select {
		case <-em.ctx.Done():
			logger.Info("ESL connection routine shutting down")
			return
		default:
		}

		if em.isShuttingDown() {
			logger.Info("ESL manager is shutting down, stopping reconnection attempts")
			return
		}

		atomic.AddInt64(&em.statistics.ConnectionAttempts, 1)
		attemptNum := atomic.LoadInt64(&em.statistics.ConnectionAttempts)

		logger.Info("Attempting to connect to FreeSWITCH ESL (Attempt #%d) at %s:%s",
			attemptNum, em.eslConfig.Host, em.eslConfig.Port)

		portNum, err := strconv.Atoi(em.eslConfig.Port)
		if err != nil {
			logger.Error("Error parsing ESL port: %v, using default 8021", err)
			portNum = 8021
		}

		connectionStartTime := time.Now()

		// Create new client
		eslAddr := fmt.Sprintf("%s:%d", em.eslConfig.Host, portNum)
		client, err := eventsocket.Dial(eslAddr, em.eslConfig.Password)
		if err != nil {
			logger.Error("Failed to connect to FreeSWITCH ESL: %v", err)
			atomic.AddInt64(&em.statistics.ConnectionErrors, 1)

			if strings.Contains(err.Error(), "auth failed") || strings.Contains(err.Error(), "authentication") {
				logger.Error("Authentication failed! Please check your ESL password.")
			}

			// Wait with backoff
			select {
			case <-em.ctx.Done():
				return
			case <-time.After(currentBackoff):
				continue
			}
		}

		connectionDuration := time.Since(connectionStartTime)
		logger.Info("Successfully connected to FreeSWITCH ESL in %s", connectionDuration)

		em.eslClient = client
		em.eslConnected = true

		// Reset connection attempts on success
		atomic.StoreInt64(&em.statistics.ConnectionAttempts, 0)

		// Subscribe to events
		em.subscribeToEvents(client)

		// Start event reader
		em.wg.Add(1)
		go em.readEvents()

		// Wait until connection is closed or shutdown
		select {
		case <-em.eslDisconnected:
			logger.Info("Disconnected from FreeSWITCH ESL")
		case <-em.ctx.Done():
			logger.Info("ESL connection routine shutting down")
			if em.eslClient != nil {
				em.eslClient.Close()
			}
			return
		}

		em.eslConnected = false

		// Check if we're shutting down before waiting
		select {
		case <-em.ctx.Done():
			return
		case <-time.After(currentBackoff):
			// Continue with next connection attempt
		}

		reconnectAttempt = atomic.LoadInt64(&em.statistics.ConnectionAttempts)
	}
}

// subscribeToEvents subscribes to the necessary FreeSWITCH events
func (em *ESLManager) subscribeToEvents(client *eventsocket.Connection) {
	logger := GetLogger()

	events := []string{
		"event plain CUSTOM sofia::register",
		"event plain CUSTOM sofia::register_failure",
		"event plain CUSTOM sofia::wrong_call_state",
		"event plain CHANNEL_CREATE",
	}

	for _, eventCmd := range events {
		_, err := client.Send(eventCmd)
		if err != nil {
			logger.Error("Error subscribing to %s: %v", eventCmd, err)
		} else {
			logger.Info("Successfully subscribed to %s", eventCmd)
		}
	}
}

// readEvents reads events from ESL and queues them for processing
func (em *ESLManager) readEvents() {
	defer em.wg.Done()

	logger := GetLogger()
	logger.Debug("Event reader started")

	for {
		if em.isShuttingDown() {
			logger.Info("Event reader shutting down")
			em.eslDisconnected <- true
			return
		}

		ev, err := em.eslClient.ReadEvent()
		if err != nil {
			logger.Error("Error reading event: %v", err)
			em.eslDisconnected <- true
			return
		}

		// Update statistics
		atomic.AddInt64(&em.statistics.EventsQueued, 1)

		// Try to queue the event
		select {
		case em.eventQueue <- ev:
			// Event queued successfully

		case <-time.After(100 * time.Millisecond):
			// Queue is full, drop the event
			atomic.AddInt64(&em.statistics.EventsDropped, 1)
			logger.Error("Event queue full, dropping event")

		case <-em.ctx.Done():
			logger.Info("Event reader shutting down")
			return
		}
	}
}

// Event processing methods moved to EventWorker

func (w *EventWorker) handleSuccessfulRegistration(ev *eventsocket.Event) {
	ipAddress := ev.Get("Network-Ip")
	userId := ev.Get("From-User")
	if userId == "" {
		userId = ev.Get("Username")
	}
	if userId == "" {
		userId = ev.Get("User_Name")
	}

	domain := ev.Get("From-Host")
	if domain == "" {
		domain = ev.Get("Domain_Name")
	}
	if domain == "" {
		domain = ev.Get("Realm")
	}

	status := ev.Get("Status")

	w.logger.Debug("Worker #%d: Registration info - IP: %s, User: %s, Domain: %s, Status: %s",
		w.id, ipAddress, userId, domain, status)

	if ipAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from registration event", w.id)
		return
	}

	if userId == "" {
		userId = "unknown"
	}

	if domain == "" {
		config := GetConfig()
		domain = config.FreeSWITCH.DefaultDomain
	}

	// Check rate limits
	if !w.manager.rateManager.CheckRegistrationRate(ipAddress, userId, domain) {
		w.logger.Info("Worker #%d: Registration from IP %s blocked due to rate limiting", w.id, ipAddress)
		return
	}

	w.logger.Info("Worker #%d: Successful registration from IP %s for user %s@%s",
		w.id, ipAddress, userId, domain)

	// Update statistics
	w.manager.securityManager.UpdateRegistrationStats(ipAddress, userId, domain)

	// Auto-whitelist if enabled
	if w.manager.securityManager.securityConfig.AutoWhitelistOnSuccess {
		w.logger.Debug("Worker #%d: Auto-whitelisting IP %s for user %s@%s",
			w.id, ipAddress, userId, domain)
		w.manager.securityManager.AddToWhitelist(ipAddress, userId, domain, false)
	}
}

func (w *EventWorker) handleWrongCallState(ev *eventsocket.Event) {
	ipAddress := ev.Get("Network_Ip")
	userId := ev.Get("From_User")

	if ipAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from wrong call state event", w.id)
		return
	}

	if userId == "" {
		userId = "unknown"
	}

	w.logger.Info("Worker #%d: Wrong call state event from IP %s for user %s",
		w.id, ipAddress, userId)

	w.manager.securityManager.ProcessWrongCallState(ipAddress, userId)
}

func (w *EventWorker) handleFailedRegistration(ev *eventsocket.Event) {
	ipAddress := ev.Get("Network-Ip")
	userId := ev.Get("To-User")
	if userId == "" {
		userId = ev.Get("From-User")
	}
	if userId == "" {
		userId = ev.Get("Username")
	}
	if userId == "" {
		userId = ev.Get("User_Name")
	}

	domain := ev.Get("To-Host")
	if domain == "" {
		domain = ev.Get("From-Host")
	}
	if domain == "" {
		domain = ev.Get("Domain_Name")
	}
	if domain == "" {
		domain = ev.Get("Realm")
	}

	w.logger.Debug("Worker #%d: Failed registration info - IP: %s, User: %s, Domain: %s",
		w.id, ipAddress, userId, domain)

	if ipAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from failed registration event", w.id)
		return
	}

	if userId == "" {
		userId = "unknown"
	}

	if domain == "" {
		config := GetConfig()
		domain = config.FreeSWITCH.DefaultDomain
	}

	w.logger.Info("Worker #%d: Failed registration from IP %s for user %s@%s",
		w.id, ipAddress, userId, domain)

	w.manager.securityManager.ProcessFailedRegistration(ipAddress, userId, domain)
}

func (w *EventWorker) handleChannelCreate(ev *eventsocket.Event) {
	ipAddress := ev.Get("Variable_sip_network_ip")
	if ipAddress == "" {
		ipAddress = ev.Get("Variable_sip_from_host")
		if ipAddress == "" {
			w.logger.Debug("Worker #%d: Could not determine source IP for channel create event", w.id)
			return
		}
	}

	userId := ev.Get("Variable_sip_from_user")
	domain := ev.Get("Variable_sip_from_host")

	allowed := w.manager.rateManager.CheckCallRate(ipAddress, userId, domain)

	if !allowed {
		w.logger.Info("Worker #%d: Call from IP %s blocked due to rate limiting", w.id, ipAddress)

		callUUID := ev.Get("Unique-ID")
		if callUUID != "" && w.manager.eslClient != nil && w.manager.eslConnected {
			hangupCmd := fmt.Sprintf("uuid_kill %s", callUUID)
			_, err := w.manager.eslClient.Send(hangupCmd)
			if err != nil {
				w.logger.Error("Worker #%d: Error hanging up rate-limited call %s: %v",
					w.id, callUUID, err)
			} else {
				w.logger.Info("Worker #%d: Successfully terminated rate-limited call %s",
					w.id, callUUID)
			}
		}
	} else {
		w.logger.Debug("Worker #%d: Call from IP %s allowed (within rate limits)", w.id, ipAddress)
	}
}

// SetESLLogLevel sets the logging level for ESL operations
func (em *ESLManager) SetESLLogLevel(level string) {
	logger := GetLogger()
	logger.SetLogLevelFromString(level)

	switch strings.ToLower(level) {
	case "error":
		em.eslLogLevel = LogLevelError
	case "info":
		em.eslLogLevel = LogLevelInfo
	case "debug":
		em.eslLogLevel = LogLevelDebug
	case "trace":
		em.eslLogLevel = LogLevelTrace
	default:
		logger.Info("Unknown log level '%s', using 'info'", level)
		em.eslLogLevel = LogLevelInfo
	}

	logger.Info("ESL log level set to: %s", level)
}

// GetESLStats returns current ESL statistics
func (em *ESLManager) GetESLStats() map[string]interface{} {
	return map[string]interface{}{
		"connected":           em.eslConnected,
		"host":                em.eslConfig.Host,
		"port":                em.eslConfig.Port,
		"connection_attempts": atomic.LoadInt64(&em.statistics.ConnectionAttempts),
		"connection_errors":   atomic.LoadInt64(&em.statistics.ConnectionErrors),
		"events_processed":    atomic.LoadInt64(&em.statistics.EventsProcessed),
		"events_queued":       atomic.LoadInt64(&em.statistics.EventsQueued),
		"events_dropped":      atomic.LoadInt64(&em.statistics.EventsDropped),
		"log_level":           em.eslConfig.LogLevel,
		"worker_count":        em.workerCount,
		"queue_size":          em.maxQueueSize,
		"queue_length":        len(em.eventQueue),
	}
}

// ReconnectESL forces a reconnection to the ESL
func (em *ESLManager) ReconnectESL() {
	logger := GetLogger()

	if em.eslConnected && em.eslClient != nil {
		logger.Info("Manually triggering ESL reconnection")
		em.eslClient.Close()
		em.eslConnected = false
		select {
		case em.eslDisconnected <- true:
			// Sent disconnect signal
		default:
			// Channel is full or closed, ignore
		}
	}
}

// SendCommand sends a command to FreeSWITCH ESL and returns the response
func (em *ESLManager) SendCommand(command string) (string, error) {
	logger := GetLogger()
	config := GetConfig()

	if !em.eslConnected || em.eslClient == nil {
		return "", fmt.Errorf("not connected to FreeSWITCH ESL")
	}

	// Check if command is in the whitelist
	isAllowed := false
	for _, allowedCmd := range config.Security.ESLAllowedCommands {
		if strings.HasPrefix(command, allowedCmd) {
			isAllowed = true
			break
		}
	}

	if !isAllowed {
		logger.Error("Command not allowed: %s", command)
		return "", fmt.Errorf("command not allowed: %s", command)
	}

	logger.Debug("Sending command to ESL: %s", command)
	ev, err := em.eslClient.Send(fmt.Sprintf("api %s", command))
	if err != nil {
		logger.Error("Error sending command to ESL: %v", err)
		return "", err
	}

	response := ev.Get("Reply-Text")
	if response == "" {
		response = ev.Body
	}

	logger.Debug("Received response from ESL: %s", response)
	return response, nil
}
