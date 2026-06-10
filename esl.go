package main

import (
	"context"
	"fmt"
	"net/netip"
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

	// FreeSWITCH event names and CUSTOM subclasses dispatched by the worker
	// pool and subscribed to on connect.
	eventNameCustom        = "CUSTOM"
	eventNameChannelCreate = "CHANNEL_CREATE"
	eventSubRegister       = "sofia::register"
	eventSubRegisterFail   = "sofia::register_failure"
	eventSubWrongCallState = "sofia::wrong_call_state"

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

	// Worker pool. Each worker drains its own queue; the reader round-robins
	// events across them so receivers never contend on a single channel lock
	// (the shared-queue chanrecv/lock-spin was the top realistic-pipeline cost).
	workerQueues []chan *eventsocket.Event
	queueSize    int
	dispatchNext atomic.Uint32
	workerCount  int

	eventPool *EventPool

	// Lifecycle. The senders into eventQueue (connection loop + event
	// reader) and the receivers (workers) are tracked separately: Shutdown
	// must prove every sender has exited before it closes the queue, and the
	// workers exit by draining the closed queue.
	ctx       context.Context
	cancel    context.CancelFunc
	readersWg sync.WaitGroup
	workersWg sync.WaitGroup
	shutdown  atomic.Bool
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
	queue   chan *eventsocket.Event
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
			New: func() any {
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
	return workerCountFor(runtime.NumCPU())
}

// workerCountFor clamps n to [eslMinWorkers, eslMaxWorkers].
func workerCountFor(n int) int {
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

		logLevel, _ := eslLogLevelFromString(strings.ToLower(cfg.Security.ESLLogLevel))
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
			queueSize:       eslEventQueueSize,
			workerCount:     workerCount,
			eventPool:       NewEventPool(),
			ctx:             ctx,
			cancel:          cancel,
		}

		logger.Info("Initializing ESL manager: workers=%d, queue=%d", workerCount, eslEventQueueSize)
		eslManager.startWorkerPool()

		eslManager.readersWg.Add(1)
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

// run is the main loop for each worker.
//
// A bare channel receive, deliberately: the previous two-case select (ctx +
// queue) made selectgo and channel-lock spin the top cost in the realistic
// pipeline profile. Workers stop when Shutdown closes the queue, which it
// does only after every sender has exited.
func (w *EventWorker) run() {
	defer w.manager.workersWg.Done()

	for ev := range w.queue {
		w.processEventWithPool(ev)
		w.manager.statistics.EventsProcessed.Add(1)
	}
}

// processEventWithPool processes an event using the memory pool.
func (w *EventWorker) processEventWithPool(ev *eventsocket.Event) {
	// The clock is only read when the debug timing log that consumes it is
	// enabled; an unconditional time.Now() here was ~5% of the realistic
	// pipeline profile.
	debugTiming := w.logger.enabled(LogLevelDebug)

	var startTime time.Time
	if debugTiming {
		startTime = time.Now()
	}

	pe := w.manager.eventPool.Get()
	defer w.manager.eventPool.Put(pe)

	pe.EventName = ev.Get("Event-Name")
	pe.EventSubclass = ev.Get("Event-Subclass")

	if w.logger.enabled(LogLevelTrace) {
		w.logger.Trace("Worker #%d processing event: %s/%s", w.id, pe.EventName, pe.EventSubclass)
	}

	switch pe.EventName {
	case eventNameCustom:
		switch pe.EventSubclass {
		case eventSubRegister:
			w.extractRegistrationData(ev, pe)
			w.handleSuccessfulRegistration(pe)
		case eventSubRegisterFail:
			w.extractFailedRegistrationData(ev, pe)
			w.handleFailedRegistration(pe)
		case eventSubWrongCallState:
			w.extractWrongCallStateData(ev, pe)
			w.handleWrongCallState(pe)
		default:
			w.logger.Debug("Worker #%d: unhandled CUSTOM subclass: %s", w.id, pe.EventSubclass)
		}
	case eventNameChannelCreate:
		w.extractChannelCreateData(ev, pe)
		w.handleChannelCreate(pe)
	default:
		w.logger.Debug("Worker #%d: unhandled event type: %s", w.id, pe.EventName)
	}

	if debugTiming {
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
	// The eventsocket library capitalizes wire headers ("Unique-ID" arrives
	// as "Unique-Id"), and Event.Get is an exact-key lookup. Check both
	// spellings so the call UUID survives the wire format.
	pe.CallUUID = firstNonEmpty(ev, "Unique-ID", "Unique-Id")
}

// validIP reports whether s parses as a real IP (not a hostname).
func validIP(s string) bool {
	_, err := netip.ParseAddr(s)

	return err == nil
}

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
		// Re-registrations refresh the existing entry in place; new IPs
		// enqueue without waiting. The previous synchronous round-trip
		// stalled the worker for the full 100ms batch tick per registration.
		if !w.manager.securityManager.RefreshWhitelistEntry(pe.IPAddress) {
			w.manager.securityManager.AddToWhitelistAsync(pe.IPAddress, pe.UserID, pe.Domain, false)
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

	_, err := client.Send("uuid_kill " + pe.CallUUID)
	if err != nil {
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

	// Readers (connection loop + event reader) are the only queue senders;
	// they must exit before the queues close, then the workers drain them.
	em.readersWg.Wait()
	em.closeWorkerQueues()
	em.workersWg.Wait()

	logger.Info("ESL manager shutdown complete")
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
func (em *ESLManager) GetESLStats() map[string]any {
	return map[string]any{
		"connected":          em.connected.Load(),
		"host":               em.eslConfig.Host,
		"port":               em.eslConfig.Port,
		"connectionAttempts": em.statistics.ConnectionAttempts.Load(),
		"connectionErrors":   em.statistics.ConnectionErrors.Load(),
		"eventsProcessed":    em.statistics.EventsProcessed.Load(),
		"eventsQueued":       em.statistics.EventsQueued.Load(),
		"eventsDropped":      em.statistics.EventsDropped.Load(),
		"logLevel":           em.eslConfig.LogLevel,
		"workerCount":        em.workerCount,
		"queueLength":        em.queueLen(),
		"queueCapacity":      em.queueCap(),
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

// startWorkerPool starts the event-processing workers.
func (em *ESLManager) startWorkerPool() {
	logger := GetLogger()

	// Spread the total queue capacity across the per-worker queues so the
	// aggregate buffer matches the old single-queue size.
	per := 1
	if em.workerCount > 0 {
		per = max(1, em.queueSize/em.workerCount)
	}

	em.workerQueues = make([]chan *eventsocket.Event, em.workerCount)

	for i := range em.workerCount {
		queue := make(chan *eventsocket.Event, per)
		em.workerQueues[i] = queue
		w := &EventWorker{id: i + 1, manager: em, logger: logger, queue: queue}
		em.workersWg.Add(1)

		go w.run()

		logger.Info("Started event worker #%d", w.id)
	}
}

// dispatchEvent hands an event to a worker queue round-robin. The send is
// non-blocking: a full target queue (or no workers) drops the event and counts
// it, which is the right back-pressure policy under an attack-rate event flood.
func (em *ESLManager) dispatchEvent(ev *eventsocket.Event) {
	em.statistics.EventsQueued.Add(1)

	count := len(em.workerQueues)
	if count == 0 {
		em.statistics.EventsDropped.Add(1)

		return
	}

	// A uint32 round-robin counter: int(uint32) cannot overflow on 64-bit,
	// and wrapping at 2^32 is harmless for round-robin dispatch.
	idx := int(em.dispatchNext.Add(1)-1) % count

	select {
	case em.workerQueues[idx] <- ev:
	default:
		em.statistics.EventsDropped.Add(1)
		GetLogger().Error("Worker queue %d full, dropping event", idx)
	}
}

// closeWorkerQueues closes every worker queue, ending the worker range loops.
// Call only after all senders (the event reader) have stopped.
func (em *ESLManager) closeWorkerQueues() {
	for _, queue := range em.workerQueues {
		close(queue)
	}
}

// queueLen reports the total events buffered across all worker queues.
func (em *ESLManager) queueLen() int {
	total := 0
	for _, queue := range em.workerQueues {
		total += len(queue)
	}

	return total
}

// queueCap reports the aggregate worker-queue capacity.
func (em *ESLManager) queueCap() int {
	total := 0
	for _, queue := range em.workerQueues {
		total += cap(queue)
	}

	return total
}

// reconnectBaseBackoff parses the configured reconnect backoff, falling back
// to five seconds on a missing or unusable value.
func (em *ESLManager) reconnectBaseBackoff(logger *Logger) time.Duration {
	baseBackoff, err := time.ParseDuration(em.eslConfig.ReconnectBackoff)
	if err != nil || baseBackoff <= 0 {
		logger.Error("Error parsing reconnect backoff %q, using 5s: %v", em.eslConfig.ReconnectBackoff, err)

		return 5 * time.Second
	}

	return baseBackoff
}

// dialESL parses the configured port (falling back to 8021) and dials the
// event socket, classifying authentication failures in the log output.
func (em *ESLManager) dialESL(logger *Logger) (*eventsocket.Connection, error) {
	port, err := strconv.Atoi(em.eslConfig.Port)
	if err != nil {
		logger.Error("Error parsing ESL port %q, using 8021: %v", em.eslConfig.Port, err)

		port = 8021
	}

	client, err := eventsocket.Dial(fmt.Sprintf("%s:%d", em.eslConfig.Host, port), em.eslConfig.Password)
	if err != nil {
		em.statistics.ConnectionErrors.Add(1)

		if strings.Contains(err.Error(), "auth failed") || strings.Contains(err.Error(), "authentication") {
			logger.Error("ESL authentication failed — check the password")
		} else {
			logger.Error("Failed to connect to FreeSWITCH ESL: %v", err)
		}

		return nil, fmt.Errorf("dialing ESL: %w", err)
	}

	return client, nil
}

// startESLConnection connects to FreeSWITCH ESL and listens for events,
// reconnecting with exponential backoff on failure.
func (em *ESLManager) startESLConnection() {
	defer em.readersWg.Done()

	logger := GetLogger()
	baseBackoff := em.reconnectBaseBackoff(logger)

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

		// Drop any stale disconnect signal left over from a previous
		// connection generation so it cannot be mistaken for a disconnect of
		// the connection we are about to establish.
		select {
		case <-em.eslDisconnected:
		default:
		}

		started := time.Now()

		client, err := em.dialESL(logger)
		if err != nil {
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

		em.readersWg.Add(1)
		go em.readEvents(client)

		select {
		case <-em.eslDisconnected:
			logger.Info("Disconnected from FreeSWITCH ESL")
		case <-em.ctx.Done():
			client.Close()

			return
		}

		// Close this generation's connection unconditionally. The disconnect
		// signal can be stale (sent by a previous generation's reader racing
		// with the reconnect); without this close a live connection and its
		// reader goroutine would be abandoned and leak.
		client.Close()

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
		"event plain " + eventNameCustom + " " + eventSubRegister,
		"event plain " + eventNameCustom + " " + eventSubRegisterFail,
		"event plain " + eventNameCustom + " " + eventSubWrongCallState,
		"event plain " + eventNameChannelCreate,
	}
	for _, cmd := range events {
		_, err := client.Send(cmd)
		if err != nil {
			logger.Error("Error subscribing to %q: %v", cmd, err)
		} else {
			logger.Info("Subscribed to %q", cmd)
		}
	}
}

// readEvents reads events from the given client and queues them for processing.
// The client argument avoids racing with reconnection swapping em.eslClient.
func (em *ESLManager) readEvents(client *eventsocket.Connection) {
	defer em.readersWg.Done()

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

		em.dispatchEvent(ev)
	}
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
