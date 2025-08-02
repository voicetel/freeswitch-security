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
	rateManager *RateManager

	// Worker pool components
	eventQueue   chan *eventsocket.Event
	workerCount  int
	maxQueueSize int

	// Event pool for memory efficiency
	eventPool *EventPool

	// Dynamic channel sizing
	channelResizer *ChannelResizer
	lastQueueSize  int

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

// ChannelResizer manages dynamic channel buffer sizes
type ChannelResizer struct {
	baseSize       int
	currentSize    int
	maxSize        int
	lastResize     time.Time
	resizeInterval time.Duration
	loadThreshold  float64
	highLoadCount  int
	lowLoadCount   int
	mutex          sync.RWMutex
}

// EventWorker processes events from the queue
type EventWorker struct {
	id      int
	manager *ESLManager
	logger  *Logger
}

// ProcessedEvent is a reusable event object for the pool
type ProcessedEvent struct {
	EventName     string
	EventSubclass string
	IPAddress     string
	UserID        string
	Domain        string
	Status        string
	CallUUID      string
	Headers       map[string]string
}

// EventPool manages a pool of reusable ProcessedEvent objects
type EventPool struct {
	pool sync.Pool
}

// NewEventPool creates a new event pool
func NewEventPool() *EventPool {
	return &EventPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &ProcessedEvent{
					Headers: make(map[string]string, 20), // Pre-allocate common size
				}
			},
		},
	}
}

// Get retrieves a ProcessedEvent from the pool
func (ep *EventPool) Get() *ProcessedEvent {
	return ep.pool.Get().(*ProcessedEvent)
}

// Put returns a ProcessedEvent to the pool after clearing it
func (ep *EventPool) Put(e *ProcessedEvent) {
	// Clear the event
	e.EventName = ""
	e.EventSubclass = ""
	e.IPAddress = ""
	e.UserID = ""
	e.Domain = ""
	e.Status = ""
	e.CallUUID = ""

	// Clear headers map
	for k := range e.Headers {
		delete(e.Headers, k)
	}

	ep.pool.Put(e)
}

// NewChannelResizer creates a new channel resizer
func NewChannelResizer(baseSize, maxSize int) *ChannelResizer {
	return &ChannelResizer{
		baseSize:       baseSize,
		currentSize:    baseSize,
		maxSize:        maxSize,
		lastResize:     time.Now(),
		resizeInterval: 30 * time.Second, // Check every 30 seconds
		loadThreshold:  0.7,              // 70% utilization triggers resize
	}
}

// CalculateSize determines the appropriate channel size based on load
func (cr *ChannelResizer) CalculateSize(currentLoad, capacity int64) int {
	cr.mutex.Lock()
	defer cr.mutex.Unlock()

	// Don't resize too frequently
	if time.Since(cr.lastResize) < cr.resizeInterval {
		return cr.currentSize
	}

	utilization := float64(currentLoad) / float64(capacity)

	// High load detection
	if utilization > cr.loadThreshold {
		cr.highLoadCount++
		cr.lowLoadCount = 0

		// After 3 consecutive high load detections, increase size
		if cr.highLoadCount >= 3 {
			newSize := cr.currentSize * 2
			if newSize > cr.maxSize {
				newSize = cr.maxSize
			}
			if newSize != cr.currentSize {
				cr.currentSize = newSize
				cr.lastResize = time.Now()
				cr.highLoadCount = 0
			}
		}
	} else if utilization < 0.3 { // Low load
		cr.lowLoadCount++
		cr.highLoadCount = 0

		// After 5 consecutive low load detections, decrease size
		if cr.lowLoadCount >= 5 {
			newSize := cr.currentSize / 2
			if newSize < cr.baseSize {
				newSize = cr.baseSize
			}
			if newSize != cr.currentSize {
				cr.currentSize = newSize
				cr.lastResize = time.Now()
				cr.lowLoadCount = 0
			}
		}
	} else {
		// Normal load, reset counters
		cr.highLoadCount = 0
		cr.lowLoadCount = 0
	}

	return cr.currentSize
}

// GetCurrentSize returns the current channel size
func (cr *ChannelResizer) GetCurrentSize() int {
	cr.mutex.RLock()
	defer cr.mutex.RUnlock()
	return cr.currentSize
}

// GetStats returns resizer statistics
func (cr *ChannelResizer) GetStats() map[string]interface{} {
	cr.mutex.RLock()
	defer cr.mutex.RUnlock()

	return map[string]interface{}{
		"base_size":       cr.baseSize,
		"current_size":    cr.currentSize,
		"max_size":        cr.maxSize,
		"high_load_count": cr.highLoadCount,
		"low_load_count":  cr.lowLoadCount,
		"last_resize":     cr.lastResize.Format(time.RFC3339),
	}
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

		// Initial queue size - will be dynamically adjusted
		initialQueueSize := 1000
		maxQueueSize := 10000

		// Create ESL config
		eslConfig := ESLConfig{
			Host:             config.Security.ESLHost,
			Port:             config.Security.ESLPort,
			Password:         config.Security.ESLPassword,
			LogLevel:         config.Security.ESLLogLevel,
			ReconnectBackoff: config.Security.ReconnectBackoff,
			WorkerCount:      workerCount,
			MaxQueueSize:     maxQueueSize,
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
			eventQueue:      make(chan *eventsocket.Event, initialQueueSize),
			workerCount:     eslConfig.WorkerCount,
			maxQueueSize:    eslConfig.MaxQueueSize,
			eventPool:       NewEventPool(),
			channelResizer:  NewChannelResizer(initialQueueSize, maxQueueSize),
			lastQueueSize:   initialQueueSize,
			ctx:             ctx,
			cancel:          cancel,
			shutdown:        false,
		}

		logger.Info("Initializing ESL manager with %d workers, initial queue size: %d, max queue size: %d",
			eslConfig.WorkerCount, initialQueueSize, maxQueueSize)

		// Start worker pool
		eslManager.startWorkerPool()

		// Start channel resizer monitor
		eslManager.wg.Add(1)
		go eslManager.monitorChannelSize()

		// Start ESL connection
		logger.Info("Starting ESL connection")
		eslManager.wg.Add(1)
		go eslManager.startESLConnection()
	})

	return eslManager, err
}

// monitorChannelSize monitors and adjusts channel sizes based on load
func (em *ESLManager) monitorChannelSize() {
	defer em.wg.Done()

	logger := GetLogger()
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-em.ctx.Done():
			logger.Info("Channel size monitor shutting down")
			return

		case <-ticker.C:
			// Calculate current load
			queueLen := len(em.eventQueue)
			capacity := cap(em.eventQueue)
			eventsQueued := atomic.LoadInt64(&em.statistics.EventsQueued)

			// Calculate new size
			newSize := em.channelResizer.CalculateSize(int64(queueLen), int64(capacity))

			// If size needs to change, recreate the channel
			if newSize != em.lastQueueSize {
				logger.Info("Adjusting event queue size from %d to %d (current load: %d/%d)",
					em.lastQueueSize, newSize, queueLen, capacity)

				// Create new channel
				newQueue := make(chan *eventsocket.Event, newSize)

				// Transfer existing events
				close(em.eventQueue)
				transferred := 0
				for event := range em.eventQueue {
					select {
					case newQueue <- event:
						transferred++
					default:
						// New queue is full, drop event
						atomic.AddInt64(&em.statistics.EventsDropped, 1)
					}
				}

				em.eventQueue = newQueue
				em.lastQueueSize = newSize

				logger.Info("Channel resize complete, transferred %d events", transferred)
			}

			// Log statistics periodically
			if logger.GetLogLevel() >= LogLevelDebug {
				logger.Debug("Channel monitor - Queue: %d/%d, Events queued: %d, Dropped: %d",
					queueLen, capacity, eventsQueued,
					atomic.LoadInt64(&em.statistics.EventsDropped))
			}
		}
	}
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

			// Process the event using the memory pool
			w.processEventWithPool(event)

			// Update statistics
			atomic.AddInt64(&w.manager.statistics.EventsProcessed, 1)
		}
	}
}

// processEventWithPool processes an event using the memory pool
func (w *EventWorker) processEventWithPool(ev *eventsocket.Event) {
	startTime := time.Now()

	// Get a processed event from the pool
	processedEvent := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(processedEvent) // Return to pool when done

	// Extract and store event data in the pooled object
	processedEvent.EventName = ev.Get("Event-Name")
	processedEvent.EventSubclass = ev.Get("Event-Subclass")

	// Log event processing in trace mode
	if w.logger.GetLogLevel() >= LogLevelTrace {
		w.logger.Trace("Worker #%d processing event: %s/%s",
			w.id, processedEvent.EventName, processedEvent.EventSubclass)
	}

	// Process based on event type
	switch processedEvent.EventName {
	case "CUSTOM":
		switch processedEvent.EventSubclass {
		case "sofia::register":
			w.extractRegistrationData(ev, processedEvent)
			w.handleSuccessfulRegistrationPooled(processedEvent)
		case "sofia::register_failure":
			w.extractFailedRegistrationData(ev, processedEvent)
			w.handleFailedRegistrationPooled(processedEvent)
		case "sofia::wrong_call_state":
			w.extractWrongCallStateData(ev, processedEvent)
			w.handleWrongCallStatePooled(processedEvent)
		default:
			w.logger.Debug("Worker #%d: Unhandled CUSTOM event subclass: %s",
				w.id, processedEvent.EventSubclass)
		}
	case "CHANNEL_CREATE":
		w.extractChannelCreateData(ev, processedEvent)
		w.handleChannelCreatePooled(processedEvent)
	default:
		w.logger.Debug("Worker #%d: Unhandled event type: %s", w.id, processedEvent.EventName)
	}

	// Log processing time in debug mode
	if w.logger.GetLogLevel() >= LogLevelDebug {
		processingTime := time.Since(startTime)
		w.logger.Debug("Worker #%d processed %s event in %v",
			w.id, processedEvent.EventName, processingTime)
	}
}

// extractRegistrationData extracts registration data into the pooled event
func (w *EventWorker) extractRegistrationData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network-Ip")

	pe.UserID = ev.Get("From-User")
	if pe.UserID == "" {
		pe.UserID = ev.Get("Username")
	}
	if pe.UserID == "" {
		pe.UserID = ev.Get("User_Name")
	}

	pe.Domain = ev.Get("From-Host")
	if pe.Domain == "" {
		pe.Domain = ev.Get("Domain_Name")
	}
	if pe.Domain == "" {
		pe.Domain = ev.Get("Realm")
	}

	pe.Status = ev.Get("Status")
}

// extractFailedRegistrationData extracts failed registration data into the pooled event
func (w *EventWorker) extractFailedRegistrationData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network-Ip")

	pe.UserID = ev.Get("To-User")
	if pe.UserID == "" {
		pe.UserID = ev.Get("From-User")
	}
	if pe.UserID == "" {
		pe.UserID = ev.Get("Username")
	}
	if pe.UserID == "" {
		pe.UserID = ev.Get("User_Name")
	}

	pe.Domain = ev.Get("To-Host")
	if pe.Domain == "" {
		pe.Domain = ev.Get("From-Host")
	}
	if pe.Domain == "" {
		pe.Domain = ev.Get("Domain_Name")
	}
	if pe.Domain == "" {
		pe.Domain = ev.Get("Realm")
	}
}

// extractWrongCallStateData extracts wrong call state data into the pooled event
func (w *EventWorker) extractWrongCallStateData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network_Ip")
	pe.UserID = ev.Get("From_User")
}

// extractChannelCreateData extracts channel create data into the pooled event
func (w *EventWorker) extractChannelCreateData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Variable_sip_network_ip")
	if pe.IPAddress == "" {
		pe.IPAddress = ev.Get("Variable_sip_from_host")
	}

	pe.UserID = ev.Get("Variable_sip_from_user")
	pe.Domain = ev.Get("Variable_sip_from_host")
	pe.CallUUID = ev.Get("Unique-ID")
}

// handleSuccessfulRegistrationPooled handles successful registration with pooled event
func (w *EventWorker) handleSuccessfulRegistrationPooled(pe *ProcessedEvent) {
	w.logger.Debug("Worker #%d: Registration info - IP: %s, User: %s, Domain: %s, Status: %s",
		w.id, pe.IPAddress, pe.UserID, pe.Domain, pe.Status)

	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from registration event", w.id)
		return
	}

	if pe.UserID == "" {
		pe.UserID = "unknown"
	}

	if pe.Domain == "" {
		config := GetConfig()
		pe.Domain = config.FreeSWITCH.DefaultDomain
	}

	// Check rate limits
	if !w.manager.rateManager.CheckRegistrationRate(pe.IPAddress, pe.UserID, pe.Domain) {
		w.logger.Info("Worker #%d: Registration from IP %s blocked due to rate limiting",
			w.id, pe.IPAddress)
		return
	}

	w.logger.Info("Worker #%d: Successful registration from IP %s for user %s@%s",
		w.id, pe.IPAddress, pe.UserID, pe.Domain)

	// Update statistics
	w.manager.securityManager.UpdateRegistrationStats(pe.IPAddress, pe.UserID, pe.Domain)

	// Auto-whitelist if enabled
	if w.manager.securityManager.securityConfig.AutoWhitelistOnSuccess {
		w.logger.Debug("Worker #%d: Auto-whitelisting IP %s for user %s@%s",
			w.id, pe.IPAddress, pe.UserID, pe.Domain)
		if err := w.manager.securityManager.AddToWhitelist(pe.IPAddress, pe.UserID, pe.Domain, false); err != nil {
			w.logger.Error("Worker #%d: Failed to add IP %s to whitelist: %v", w.id, pe.IPAddress, err)
		}
	}
}

// handleFailedRegistrationPooled handles failed registration with pooled event
func (w *EventWorker) handleFailedRegistrationPooled(pe *ProcessedEvent) {
	w.logger.Debug("Worker #%d: Failed registration info - IP: %s, User: %s, Domain: %s",
		w.id, pe.IPAddress, pe.UserID, pe.Domain)

	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from failed registration event", w.id)
		return
	}

	if pe.UserID == "" {
		pe.UserID = "unknown"
	}

	if pe.Domain == "" {
		config := GetConfig()
		pe.Domain = config.FreeSWITCH.DefaultDomain
	}

	w.logger.Info("Worker #%d: Failed registration from IP %s for user %s@%s",
		w.id, pe.IPAddress, pe.UserID, pe.Domain)

	w.manager.securityManager.ProcessFailedRegistration(pe.IPAddress, pe.UserID, pe.Domain)
}

// handleWrongCallStatePooled handles wrong call state with pooled event
func (w *EventWorker) handleWrongCallStatePooled(pe *ProcessedEvent) {
	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: Failed to extract IP address from wrong call state event", w.id)
		return
	}

	if pe.UserID == "" {
		pe.UserID = "unknown"
	}

	w.logger.Info("Worker #%d: Wrong call state event from IP %s for user %s",
		w.id, pe.IPAddress, pe.UserID)

	w.manager.securityManager.ProcessWrongCallState(pe.IPAddress, pe.UserID)
}

// handleChannelCreatePooled handles channel create with pooled event
func (w *EventWorker) handleChannelCreatePooled(pe *ProcessedEvent) {
	if pe.IPAddress == "" {
		w.logger.Debug("Worker #%d: Could not determine source IP for channel create event", w.id)
		return
	}

	allowed := w.manager.rateManager.CheckCallRate(pe.IPAddress, pe.UserID, pe.Domain)

	if !allowed {
		w.logger.Info("Worker #%d: Call from IP %s blocked due to rate limiting", w.id, pe.IPAddress)

		if pe.CallUUID != "" && w.manager.eslClient != nil && w.manager.eslConnected {
			hangupCmd := fmt.Sprintf("uuid_kill %s", pe.CallUUID)
			_, err := w.manager.eslClient.Send(hangupCmd)
			if err != nil {
				w.logger.Error("Worker #%d: Error hanging up rate-limited call %s: %v",
					w.id, pe.CallUUID, err)
			} else {
				w.logger.Info("Worker #%d: Successfully terminated rate-limited call %s",
					w.id, pe.CallUUID)
			}
		}
	} else {
		w.logger.Debug("Worker #%d: Call from IP %s allowed (within rate limits)", w.id, pe.IPAddress)
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

	// Don't close event queue here as it might be recreated by monitor

	// Shutdown rate manager
	if em.rateManager != nil {
		em.rateManager.Shutdown()
	}

	// Wait for all goroutines to finish
	em.wg.Wait()

	// Now safe to close the queue
	close(em.eventQueue)

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

	// Calculate dynamic backoff
	currentBackoff := backoffDuration
	connectionAttempts := atomic.LoadInt64(&em.statistics.ConnectionAttempts)
	if connectionAttempts > 0 {
		maxBackoff := 60 * time.Second
		calculatedBackoff := backoffDuration * time.Duration(1<<uint(connectionAttempts-1))
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

// GetESLStats returns current ESL statistics including channel sizing info
func (em *ESLManager) GetESLStats() map[string]interface{} {
	channelStats := em.channelResizer.GetStats()

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
		"queue_size":          em.lastQueueSize,
		"queue_length":        len(em.eventQueue),
		"queue_capacity":      cap(em.eventQueue),
		"memory_pool_enabled": true,
		"dynamic_sizing":      true,
		"channel_stats":       channelStats,
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
