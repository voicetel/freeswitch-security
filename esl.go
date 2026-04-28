package main

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// Static event-queue parameters. The previous code attempted to dynamically
// resize this channel, but the resize logic closed an in-use channel which
// races with readers/writers. A generously sized fixed buffer is preferable.
const (
	eslEventQueueSize = 8192
	eslMinWorkers     = 2
	eslMaxWorkers     = 8

	// unknownUser is the placeholder UserID used when the FreeSWITCH event
	// did not include a usable user identifier.
	unknownUser = "unknown"

	// logLevelInfoStr is the string spelling of the "info" log level.
	logLevelInfoStr = "info"
)

// ESLManager handles FreeSWITCH Event Socket Layer connections.
type ESLManager struct {
	securityManager *SecurityManager
	eslConfig       ESLConfig

	clientMu  sync.RWMutex
	eslClient *eventsocket.Connection
	connected atomic.Bool

	eslDisconnected chan bool
	rateManager     *RateManager

	statistics struct {
		ConnectionAttempts atomic.Int64
		ConnectionErrors   atomic.Int64
		EventsProcessed    atomic.Int64
		EventsQueued       atomic.Int64
		EventsDropped      atomic.Int64
	}

	// Worker pool.
	eventQueue  chan *eventsocket.Event
	workerCount int

	eventPool *EventPool

	// Lifecycle.
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	shutdown atomic.Bool
}

// ESLConfig holds ESL-related configuration.
type ESLConfig struct {
	Host             string
	Port             string
	Password         string
	LogLevel         string
	ReconnectBackoff string
	WorkerCount      int
}

// EventWorker processes events from the queue.
type EventWorker struct {
	id      int
	manager *ESLManager
	logger  *Logger
}

// ProcessedEvent is a reusable event object held by EventPool.
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

// EventPool manages a pool of reusable ProcessedEvent objects.
type EventPool struct {
	pool sync.Pool
}

// eventHeadersInitialCapacity is the initial capacity allocated for
// ProcessedEvent.Headers. FreeSWITCH events typically have ~10–20 headers.
const eventHeadersInitialCapacity = 20

// NewEventPool creates a new event pool.
func NewEventPool() *EventPool {
	return &EventPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &ProcessedEvent{Headers: make(map[string]string, eventHeadersInitialCapacity)}
			},
		},
	}
}

// Get retrieves a ProcessedEvent from the pool. The pool's New always returns
// *ProcessedEvent, so the type assertion is safe; we still check it to satisfy
// the linter and to fail fast if the pool is ever misconfigured.
func (ep *EventPool) Get() *ProcessedEvent {
	pe, ok := ep.pool.Get().(*ProcessedEvent)
	if !ok {
		// Should be impossible: pool only stores *ProcessedEvent.
		return &ProcessedEvent{Headers: make(map[string]string, eventHeadersInitialCapacity)}
	}

	return pe
}

// Put returns a ProcessedEvent to the pool after clearing it.
func (ep *EventPool) Put(pe *ProcessedEvent) {
	pe.EventName = ""
	pe.EventSubclass = ""
	pe.IPAddress = ""
	pe.UserID = ""
	pe.Domain = ""
	pe.Status = ""
	pe.CallUUID = ""

	for k := range pe.Headers {
		delete(pe.Headers, k)
	}

	ep.pool.Put(pe)
}

var (
	eslManager     *ESLManager
	eslManagerOnce sync.Once
)

// backoffMultipliers maps an attempt index (0-based, capped) to a multiplier
// applied to the base backoff. This is preferable to dynamic shift math
// because it eliminates the int/uint conversion warnings flagged by gosec.
var backoffMultipliers = [...]int64{1, 2, 4, 8, 16, 32, 64}

// computeBackoff returns the backoff for the given attempt index (1-based).
// The result is clamped to [base, cap].
func computeBackoff(base, ceiling time.Duration, attempt int64) time.Duration {
	if attempt <= 1 {
		return base
	}

	idx := attempt - 1
	if idx >= int64(len(backoffMultipliers)) {
		idx = int64(len(backoffMultipliers)) - 1
	}

	d := time.Duration(backoffMultipliers[idx]) * base
	if d <= 0 || d > ceiling {
		return ceiling
	}

	return d
}

// chooseWorkerCount returns a sensible worker pool size for the host.
func chooseWorkerCount() int {
	n := runtime.NumCPU()
	if n < eslMinWorkers {
		return eslMinWorkers
	}

	if n > eslMaxWorkers {
		return eslMaxWorkers
	}

	return n
}

// InitESLManager initializes the ESL manager and returns the singleton.
// Currently it never returns an error; the connection lifecycle is managed
// asynchronously by a background goroutine that performs reconnects with
// exponential backoff.
func InitESLManager(sm *SecurityManager) *ESLManager {
	eslManagerOnce.Do(func() {
		logger := GetLogger()
		cfg := GetConfig()

		var logLevel EslLogLevel

		switch strings.ToLower(cfg.Security.ESLLogLevel) {
		case "error":
			logLevel = LogLevelError
		case "info":
			logLevel = LogLevelInfo
		case "debug":
			logLevel = LogLevelDebug
		case "trace":
			logLevel = LogLevelTrace
		default:
			logLevel = LogLevelInfo
		}

		logger.SetLogLevel(logLevel)

		workerCount := chooseWorkerCount()
		ec := ESLConfig{
			Host:             cfg.Security.ESLHost,
			Port:             cfg.Security.ESLPort,
			Password:         cfg.Security.ESLPassword,
			LogLevel:         cfg.Security.ESLLogLevel,
			ReconnectBackoff: cfg.Security.ReconnectBackoff,
			WorkerCount:      workerCount,
		}

		ctx, cancel := context.WithCancel(context.Background())
		eslManager = &ESLManager{
			securityManager: sm,
			eslConfig:       ec,
			eslDisconnected: make(chan bool, 1),
			rateManager:     NewRateManager(sm),
			eventQueue:      make(chan *eventsocket.Event, eslEventQueueSize),
			workerCount:     workerCount,
			eventPool:       NewEventPool(),
			ctx:             ctx,
			cancel:          cancel,
		}

		logger.Info("Initializing ESL manager: workers=%d, queue=%d", workerCount, eslEventQueueSize)
		eslManager.startWorkerPool()

		eslManager.wg.Add(1)
		go eslManager.startESLConnection()
	})

	return eslManager
}

// GetESLManager returns the ESL manager instance, initializing it on first call.
func GetESLManager() *ESLManager {
	if eslManager == nil {
		InitESLManager(GetSecurityManager())
	}

	return eslManager
}

// startWorkerPool starts the event-processing workers.
func (em *ESLManager) startWorkerPool() {
	logger := GetLogger()
	for i := range em.workerCount {
		w := &EventWorker{id: i + 1, manager: em, logger: logger}
		em.wg.Add(1)

		go w.run()
		logger.Info("Started event worker #%d", w.id)
	}
}

// run is the main loop for each worker.
func (w *EventWorker) run() {
	defer w.manager.wg.Done()

	for {
		select {
		case <-w.manager.ctx.Done():
			return
		case ev, ok := <-w.manager.eventQueue:
			if !ok {
				return
			}

			w.processEventWithPool(ev)
			w.manager.statistics.EventsProcessed.Add(1)
		}
	}
}

// processEventWithPool processes an event using the memory pool.
func (w *EventWorker) processEventWithPool(ev *eventsocket.Event) {
	startTime := time.Now()

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.EventName = ev.Get("Event-Name")
	pe.EventSubclass = ev.Get("Event-Subclass")

	if w.logger.enabled(LogLevelTrace) {
		w.logger.Trace("Worker #%d processing event: %s/%s", w.id, pe.EventName, pe.EventSubclass)
	}

	switch pe.EventName {
	case "CUSTOM":
		switch pe.EventSubclass {
		case "sofia::register":
			w.extractRegistrationData(ev, pe)
			w.handleSuccessfulRegistration(pe)
		case "sofia::register_failure":
			w.extractFailedRegistrationData(ev, pe)
			w.handleFailedRegistration(pe)
		case "sofia::wrong_call_state":
			w.extractWrongCallStateData(ev, pe)
			w.handleWrongCallState(pe)
		default:
			w.logger.Debug("Worker #%d: unhandled CUSTOM subclass: %s", w.id, pe.EventSubclass)
		}
	case "CHANNEL_CREATE":
		w.extractChannelCreateData(ev, pe)
		w.handleChannelCreate(pe)
	default:
		w.logger.Debug("Worker #%d: unhandled event type: %s", w.id, pe.EventName)
	}

	if w.logger.enabled(LogLevelDebug) {
		w.logger.Debug("Worker #%d processed %s in %v", w.id, pe.EventName, time.Since(startTime))
	}
}

// firstNonEmpty returns the first non-empty header value from ev.
func firstNonEmpty(ev *eventsocket.Event, names ...string) string {
	for _, n := range names {
		if v := ev.Get(n); v != "" {
			return v
		}
	}

	return ""
}

func (w *EventWorker) extractRegistrationData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network-Ip")
	pe.UserID = firstNonEmpty(ev, "From-User", "Username", "User_Name")
	pe.Domain = firstNonEmpty(ev, "From-Host", "Domain_Name", "Realm")
	pe.Status = ev.Get("Status")
}

func (w *EventWorker) extractFailedRegistrationData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network-Ip")
	pe.UserID = firstNonEmpty(ev, "To-User", "From-User", "Username", "User_Name")
	pe.Domain = firstNonEmpty(ev, "To-Host", "From-Host", "Domain_Name", "Realm")
}

func (w *EventWorker) extractWrongCallStateData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Network_Ip")
	pe.UserID = ev.Get("From_User")
}

func (w *EventWorker) extractChannelCreateData(ev *eventsocket.Event, pe *ProcessedEvent) {
	pe.IPAddress = ev.Get("Variable_sip_network_ip")
	pe.UserID = ev.Get("Variable_sip_from_user")
	pe.Domain = ev.Get("Variable_sip_from_host")
	pe.CallUUID = ev.Get("Unique-ID")
}

// validIP reports whether s parses as a real IP (not a hostname).
func validIP(s string) bool { return net.ParseIP(s) != nil }

func (w *EventWorker) handleSuccessfulRegistration(pe *ProcessedEvent) {
	// The Debug guard avoids the variadic-arg slice allocation when debug is off.
	if w.logger.enabled(LogLevelDebug) {
		w.logger.Debug("Worker #%d: registration IP=%s user=%s domain=%s status=%s",
			w.id, pe.IPAddress, pe.UserID, pe.Domain, pe.Status)
	}

	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: missing IP from registration event", w.id)

		return
	}

	if !validIP(pe.IPAddress) {
		w.logger.Error("Worker #%d: invalid IP %q from registration event", w.id, pe.IPAddress)

		return
	}

	if pe.UserID == "" {
		pe.UserID = unknownUser
	}

	if pe.Domain == "" {
		pe.Domain = GetConfig().FreeSWITCH.DefaultDomain
	}

	if !w.manager.rateManager.CheckRegistrationRate(pe.IPAddress, pe.UserID, pe.Domain) {
		if w.logger.enabled(LogLevelInfo) {
			w.logger.Info("Worker #%d: registration from %s blocked by rate limit", w.id, pe.IPAddress)
		}

		return
	}

	// Guarded to avoid the variadic-args slice allocation when info-level
	// logging is disabled (typical at LogLevelError or higher).
	if w.logger.enabled(LogLevelInfo) {
		w.logger.Info("Worker #%d: registration from %s for %s@%s", w.id, pe.IPAddress, pe.UserID, pe.Domain)
	}

	w.manager.securityManager.UpdateRegistrationStats(pe.IPAddress, pe.UserID, pe.Domain)

	cfg := w.manager.securityManager.cfg
	if cfg.AutoWhitelistOnSuccess {
		if err := w.manager.securityManager.AddToWhitelist(pe.IPAddress, pe.UserID, pe.Domain, false); err != nil {
			w.logger.Error("Worker #%d: failed to whitelist IP %s: %v", w.id, pe.IPAddress, err)
		}
	}
}

func (w *EventWorker) handleFailedRegistration(pe *ProcessedEvent) {
	if w.logger.enabled(LogLevelDebug) {
		w.logger.Debug("Worker #%d: failed registration IP=%s user=%s domain=%s",
			w.id, pe.IPAddress, pe.UserID, pe.Domain)
	}

	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: missing IP from failed registration event", w.id)

		return
	}

	if !validIP(pe.IPAddress) {
		w.logger.Error("Worker #%d: invalid IP %q from failed registration event", w.id, pe.IPAddress)

		return
	}

	if pe.UserID == "" {
		pe.UserID = unknownUser
	}

	if pe.Domain == "" {
		pe.Domain = GetConfig().FreeSWITCH.DefaultDomain
	}

	if w.logger.enabled(LogLevelInfo) {
		w.logger.Info("Worker #%d: failed registration from %s for %s@%s", w.id, pe.IPAddress, pe.UserID, pe.Domain)
	}

	w.manager.securityManager.ProcessFailedRegistration(pe.IPAddress, pe.UserID, pe.Domain)
}

func (w *EventWorker) handleWrongCallState(pe *ProcessedEvent) {
	if pe.IPAddress == "" {
		w.logger.Error("Worker #%d: missing IP from wrong call state event", w.id)

		return
	}

	if !validIP(pe.IPAddress) {
		w.logger.Error("Worker #%d: invalid IP %q from wrong call state event", w.id, pe.IPAddress)

		return
	}

	if pe.UserID == "" {
		pe.UserID = unknownUser
	}

	if w.logger.enabled(LogLevelInfo) {
		w.logger.Info("Worker #%d: wrong call state from %s for %s", w.id, pe.IPAddress, pe.UserID)
	}

	w.manager.securityManager.ProcessWrongCallState(pe.IPAddress, pe.UserID)
}

func (w *EventWorker) handleChannelCreate(pe *ProcessedEvent) {
	if pe.IPAddress == "" {
		if w.logger.enabled(LogLevelDebug) {
			w.logger.Debug("Worker #%d: no IP in channel create event", w.id)
		}

		return
	}

	if !validIP(pe.IPAddress) {
		if w.logger.enabled(LogLevelDebug) {
			w.logger.Debug("Worker #%d: invalid IP %q in channel create event", w.id, pe.IPAddress)
		}

		return
	}

	if w.manager.rateManager.CheckCallRate(pe.IPAddress, pe.UserID, pe.Domain) {
		if w.logger.enabled(LogLevelDebug) {
			w.logger.Debug("Worker #%d: call from %s allowed", w.id, pe.IPAddress)
		}

		return
	}

	if w.logger.enabled(LogLevelInfo) {
		w.logger.Info("Worker #%d: call from %s blocked by rate limit", w.id, pe.IPAddress)
	}

	if pe.CallUUID == "" {
		return
	}

	w.manager.clientMu.RLock()
	client := w.manager.eslClient
	w.manager.clientMu.RUnlock()

	if !w.manager.connected.Load() || client == nil {
		return
	}

	if _, err := client.Send("uuid_kill " + pe.CallUUID); err != nil {
		w.logger.Error("Worker #%d: error hanging up rate-limited call %s: %v", w.id, pe.CallUUID, err)
	} else {
		w.logger.Info("Worker #%d: terminated rate-limited call %s", w.id, pe.CallUUID)
	}
}

// Shutdown gracefully shuts down the ESL manager.
func (em *ESLManager) Shutdown() {
	if !em.shutdown.CompareAndSwap(false, true) {
		return
	}

	logger := GetLogger()
	logger.Info("Shutting down ESL manager...")

	em.cancel()

	em.clientMu.RLock()
	client := em.eslClient
	em.clientMu.RUnlock()

	if em.connected.Load() && client != nil {
		client.Close()
	}

	if em.rateManager != nil {
		em.rateManager.Shutdown()
	}

	em.wg.Wait()
	close(em.eventQueue)

	logger.Info("ESL manager shutdown complete")
}

// startESLConnection connects to FreeSWITCH ESL and listens for events,
// reconnecting with exponential backoff on failure.
func (em *ESLManager) startESLConnection() {
	defer em.wg.Done()

	logger := GetLogger()
	baseBackoff, err := time.ParseDuration(em.eslConfig.ReconnectBackoff)

	if err != nil || baseBackoff <= 0 {
		logger.Error("Error parsing reconnect backoff %q, using 5s: %v", em.eslConfig.ReconnectBackoff, err)

		baseBackoff = 5 * time.Second
	}

	const maxBackoff = 60 * time.Second

	for {
		if em.shutdown.Load() {
			return
		}
		select {
		case <-em.ctx.Done():
			return
		default:
		}

		// Compute backoff for this attempt with exponential growth, capped.
		// A precomputed multiplier table avoids any shift math (and the
		// associated gosec int-conversion warnings).
		attempts := em.statistics.ConnectionAttempts.Add(1)
		backoff := computeBackoff(baseBackoff, maxBackoff, attempts)

		logger.Info("Connecting to FreeSWITCH ESL at %s:%s (attempt #%d)",
			em.eslConfig.Host, em.eslConfig.Port, attempts)

		port, err := strconv.Atoi(em.eslConfig.Port)
		if err != nil {
			logger.Error("Error parsing ESL port %q, using 8021: %v", em.eslConfig.Port, err)

			port = 8021
		}

		started := time.Now()

		client, err := eventsocket.Dial(fmt.Sprintf("%s:%d", em.eslConfig.Host, port), em.eslConfig.Password)
		if err != nil {
			em.statistics.ConnectionErrors.Add(1)

			if strings.Contains(err.Error(), "auth failed") || strings.Contains(err.Error(), "authentication") {
				logger.Error("ESL authentication failed — check the password")
			} else {
				logger.Error("Failed to connect to FreeSWITCH ESL: %v", err)
			}
			select {
			case <-em.ctx.Done():
				return
			case <-time.After(backoff):
				continue
			}
		}

		logger.Info("Connected to FreeSWITCH ESL in %s", time.Since(started))
		em.clientMu.Lock()
		em.eslClient = client
		em.clientMu.Unlock()
		em.connected.Store(true)
		em.statistics.ConnectionAttempts.Store(0) // reset on success

		em.subscribeToEvents(client)

		em.wg.Add(1)
		go em.readEvents(client)

		select {
		case <-em.eslDisconnected:
			logger.Info("Disconnected from FreeSWITCH ESL")
		case <-em.ctx.Done():
			client.Close()

			return
		}

		em.connected.Store(false)
		em.clientMu.Lock()
		em.eslClient = nil
		em.clientMu.Unlock()

		select {
		case <-em.ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// subscribeToEvents subscribes to the necessary FreeSWITCH events.
func (em *ESLManager) subscribeToEvents(client *eventsocket.Connection) {
	logger := GetLogger()

	events := []string{
		"event plain CUSTOM sofia::register",
		"event plain CUSTOM sofia::register_failure",
		"event plain CUSTOM sofia::wrong_call_state",
		"event plain CHANNEL_CREATE",
	}
	for _, cmd := range events {
		if _, err := client.Send(cmd); err != nil {
			logger.Error("Error subscribing to %q: %v", cmd, err)
		} else {
			logger.Info("Subscribed to %q", cmd)
		}
	}
}

// readEvents reads events from the given client and queues them for processing.
// The client argument avoids racing with reconnection swapping em.eslClient.
func (em *ESLManager) readEvents(client *eventsocket.Connection) {
	defer em.wg.Done()

	logger := GetLogger()
	logger.Debug("Event reader started")

	for {
		if em.shutdown.Load() {
			select {
			case em.eslDisconnected <- true:
			default:
			}

			return
		}

		ev, err := client.ReadEvent()
		if err != nil {
			logger.Error("Error reading event: %v", err)
			select {
			case em.eslDisconnected <- true:
			default:
			}

			return
		}

		em.statistics.EventsQueued.Add(1)

		select {
		case em.eventQueue <- ev:
		case <-em.ctx.Done():
			return
		default:
			em.statistics.EventsDropped.Add(1)
			logger.Error("Event queue full, dropping event")
		}
	}
}

// SetESLLogLevel sets the logging level for ESL operations.
func (em *ESLManager) SetESLLogLevel(level string) {
	GetLogger().SetLogLevelFromString(strings.ToLower(level))
	GetLogger().Info("ESL log level set to: %s", level)
}

// IsConnected reports whether the ESL connection is currently established.
func (em *ESLManager) IsConnected() bool { return em.connected.Load() }

// Host returns the configured ESL host (read-only after init).
func (em *ESLManager) Host() string { return em.eslConfig.Host }

// Port returns the configured ESL port (read-only after init).
func (em *ESLManager) Port() string { return em.eslConfig.Port }

// GetESLStats returns current ESL statistics.
func (em *ESLManager) GetESLStats() map[string]interface{} {
	return map[string]interface{}{
		"connected":           em.connected.Load(),
		"host":                em.eslConfig.Host,
		"port":                em.eslConfig.Port,
		"connection_attempts": em.statistics.ConnectionAttempts.Load(),
		"connection_errors":   em.statistics.ConnectionErrors.Load(),
		"events_processed":    em.statistics.EventsProcessed.Load(),
		"events_queued":       em.statistics.EventsQueued.Load(),
		"events_dropped":      em.statistics.EventsDropped.Load(),
		"log_level":           em.eslConfig.LogLevel,
		"worker_count":        em.workerCount,
		"queue_length":        len(em.eventQueue),
		"queue_capacity":      cap(em.eventQueue),
	}
}

// ReconnectESL forces a reconnection to the ESL.
func (em *ESLManager) ReconnectESL() {
	logger := GetLogger()

	em.clientMu.RLock()
	client := em.eslClient
	em.clientMu.RUnlock()

	if em.connected.Load() && client != nil {
		logger.Info("Triggering ESL reconnection")
		client.Close()
		em.connected.Store(false)
		select {
		case em.eslDisconnected <- true:
		default:
		}
	}
}

// SendCommand sends an ESL api command. Only commands matching one of the
// allowed-prefix entries (exact match or prefix followed by whitespace) are
// permitted; this prevents `status` from authorizing `statusand_evil`.
func (em *ESLManager) SendCommand(command string) (string, error) {
	logger := GetLogger()
	cfg := GetConfig()

	em.clientMu.RLock()
	client := em.eslClient
	em.clientMu.RUnlock()

	if !em.connected.Load() || client == nil {
		return "", ErrESLNotConnected
	}

	if !commandAllowed(command, cfg.Security.ESLAllowedCommands) {
		logger.Error("Command not allowed: %s", command)

		return "", fmt.Errorf("%w: %s", ErrESLCommandNotAllowed, command)
	}

	logger.Debug("Sending command to ESL: %s", command)

	ev, err := client.Send("api " + command)
	if err != nil {
		logger.Error("Error sending command to ESL: %v", err)

		return "", fmt.Errorf("eventsocket send: %w", err)
	}

	response := ev.Get("Reply-Text")
	if response == "" {
		response = ev.Body
	}

	logger.Debug("Received response from ESL: %s", response)

	return response, nil
}

// commandAllowed reports whether cmd is an exact match for an allowed entry,
// or starts with one of the allowed entries followed by ASCII whitespace.
//
// This prevents the prefix-match bug where allowing "status" would also allow
// "status_evil" or "statusXYZ".
func commandAllowed(cmd string, allowed []string) bool {
	for _, prefix := range allowed {
		if prefix == "" {
			continue
		}

		if cmd == prefix {
			return true
		}

		if strings.HasPrefix(cmd, prefix) && len(cmd) > len(prefix) {
			next := cmd[len(prefix)]
			if next == ' ' || next == '\t' {
				return true
			}
		}
	}

	return false
}
