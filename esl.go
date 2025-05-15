package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// EslLogLevel defines the verbosity of ESL logging
type EslLogLevel int

const (
	// LogLevelError logs only errors
	LogLevelError EslLogLevel = iota
	// LogLevelInfo logs connection info and errors
	LogLevelInfo
	// LogLevelDebug logs all ESL activities including messages
	LogLevelDebug
	// LogLevelTrace logs everything with full content
	LogLevelTrace
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
		ConnectionAttempts int
		ConnectionErrors   int
		EventsProcessed    int
	}
	statsMutex    sync.RWMutex
	rateManager   *RateManager
	rateManagerMu sync.Mutex
}

// ESLConfig holds ESL-related configuration
type ESLConfig struct {
	Host             string
	Port             string
	Password         string
	LogLevel         string
	ReconnectBackoff string
}

var (
	eslManager     *ESLManager
	eslManagerOnce sync.Once
)

// InitESLManager initializes the ESL manager
func InitESLManager(securityManager *SecurityManager) (*ESLManager, error) {
	var err error
	eslManagerOnce.Do(func() {
		config := GetConfig()

		// Parse log level
		var logLevel EslLogLevel = LogLevelInfo // Default to info level
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

		// Create ESL config
		eslConfig := ESLConfig{
			Host:             config.Security.ESLHost,
			Port:             config.Security.ESLPort,
			Password:         config.Security.ESLPassword,
			LogLevel:         config.Security.ESLLogLevel,
			ReconnectBackoff: config.Security.ReconnectBackoff,
		}

		// Initialize rate manager
		rateManager := NewRateManager(securityManager)

		// Initialize ESL manager
		eslManager = &ESLManager{
			securityManager: securityManager,
			eslConfig:       eslConfig,
			eslDisconnected: make(chan bool, 1),
			eslLogLevel:     logLevel,
			rateManager:     rateManager,
		}

		// Start ESL connection
		log.Println("Starting ESL connection")
		go eslManager.startESLConnection()
	})

	return eslManager, err
}

// GetESLManager returns the ESL manager instance
func GetESLManager() *ESLManager {
	if eslManager == nil {
		securityManager := GetSecurityManager()
		_, err := InitESLManager(securityManager)
		if err != nil {
			log.Printf("Error initializing ESL manager: %v", err)
		}
	}
	return eslManager
}

// eslLog logs ESL-related messages based on configured log level
func (em *ESLManager) eslLog(level EslLogLevel, format string, args ...interface{}) {
	if level <= em.eslLogLevel {
		prefix := ""
		switch level {
		case LogLevelError:
			prefix = "[ESL ERROR] "
		case LogLevelInfo:
			prefix = "[ESL INFO] "
		case LogLevelDebug:
			prefix = "[ESL DEBUG] "
		case LogLevelTrace:
			prefix = "[ESL TRACE] "
		}
		log.Printf(prefix+format, args...)
	}
}

// startESLConnection connects to the FreeSWITCH ESL interface and listens for events
func (em *ESLManager) startESLConnection() {
	backoffDuration, err := time.ParseDuration(em.eslConfig.ReconnectBackoff)
	if err != nil {
		em.eslLog(LogLevelError, "Error parsing reconnect backoff: %v, using default 5s", err)
		backoffDuration = 5 * time.Second
	}

	// Track statistics
	em.statsMutex.Lock()
	reconnectAttempt := em.statistics.ConnectionAttempts
	em.statistics.ConnectionAttempts++
	em.statsMutex.Unlock()

	// Calculate dynamic backoff based on consecutive failures
	currentBackoff := backoffDuration
	if reconnectAttempt > 0 {
		// Exponential backoff with a cap
		maxBackoff := 60 * time.Second
		calculatedBackoff := backoffDuration * time.Duration(1<<uint(reconnectAttempt-1))
		if calculatedBackoff > maxBackoff {
			calculatedBackoff = maxBackoff
		}
		currentBackoff = calculatedBackoff
	}

	for {
		em.eslLog(LogLevelInfo, "Attempting to connect to FreeSWITCH ESL (Attempt #%d) at %s:%s",
			reconnectAttempt+1, em.eslConfig.Host, em.eslConfig.Port)

		portNum, err := strconv.Atoi(em.eslConfig.Port)
		if err != nil {
			em.eslLog(LogLevelError, "Error parsing ESL port: %v, using default 8021", err)
			portNum = 8021
		}

		// Track connection attempt start time
		connectionStartTime := time.Now()

		// Create new client using the go-eventsocket library
		eslAddr := fmt.Sprintf("%s:%d", em.eslConfig.Host, portNum)
		client, err := eventsocket.Dial(eslAddr, em.eslConfig.Password)
		if err != nil {
			em.eslLog(LogLevelError, "Failed to connect to FreeSWITCH ESL: %v", err)
			em.statsMutex.Lock()
			em.statistics.ConnectionErrors++
			em.statsMutex.Unlock()

			// Provide detailed troubleshooting info for authentication issues
			if strings.Contains(err.Error(), "auth failed") || strings.Contains(err.Error(), "authentication") {
				em.eslLog(LogLevelError, "Authentication failed! Please check your ESL password.")
				em.eslLog(LogLevelError, "Verify password in FreeSWITCH's event_socket.conf.xml matches your configuration.")
				em.eslLog(LogLevelError, "Current password: %s", em.eslConfig.Password)
			}

			time.Sleep(currentBackoff)
			continue
		}

		connectionDuration := time.Since(connectionStartTime)
		em.eslLog(LogLevelInfo, "Successfully connected to FreeSWITCH ESL in %s", connectionDuration)

		em.eslClient = client
		em.eslConnected = true

		// Reset connection attempts counter on successful connection
		em.statsMutex.Lock()
		em.statistics.ConnectionAttempts = 0
		em.statsMutex.Unlock()

		// This confirms the ESL connection is working but no events are being processed
		em.eslLog(LogLevelInfo, "Connection established - waiting for events. If none arrive, check FreeSWITCH event generation.")

		// Subscribe to specific events we need (plain format)
		_, err = client.Send("event plain CUSTOM sofia::register")
		if err != nil {
			em.eslLog(LogLevelError, "Error subscribing to sofia::register events: %v", err)
		} else {
			em.eslLog(LogLevelInfo, "Successfully subscribed to sofia::register events")
		}

		// Subscribe to register failure events
		_, err = client.Send("event plain CUSTOM sofia::register_failure")
		if err != nil {
			em.eslLog(LogLevelError, "Error subscribing to sofia::register_failure events: %v", err)
		} else {
			em.eslLog(LogLevelInfo, "Successfully subscribed to sofia::register_failure events")
		}

		// Subscribe to wrong call state events
		if _, err := client.Send("event plain CUSTOM sofia::wrong_call_state"); err != nil {
			em.eslLog(LogLevelError, "Error subscribing to sofia::wrong_call_state events: %v", err)
		} else {
			em.eslLog(LogLevelInfo, "Successfully subscribed to sofia::wrong_call_state events")
		}

		// Subscribe to CHANNEL_CREATE events
		_, err = client.Send("event plain CHANNEL_CREATE")
		if err != nil {
			em.eslLog(LogLevelError, "Error subscribing to CHANNEL_CREATE events: %v", err)
		} else {
			em.eslLog(LogLevelInfo, "Successfully subscribed to CHANNEL_CREATE events for call rate limiting")
		}

		// Start event processing
		go em.handleEvents()

		// Wait until connection is closed
		<-em.eslDisconnected
		em.eslLog(LogLevelInfo, "Disconnected from FreeSWITCH ESL")

		em.eslConnected = false
		time.Sleep(currentBackoff)

		// Update statistics for next reconnection attempt
		em.statsMutex.Lock()
		reconnectAttempt = em.statistics.ConnectionAttempts
		em.statistics.ConnectionAttempts++
		em.statsMutex.Unlock()
	}
}

// handleEvents processes events from FreeSWITCH's Event Socket Layer
func (em *ESLManager) handleEvents() {
	em.eslLog(LogLevelDebug, "Event handler started, processing events")

	for {
		em.eslLog(LogLevelTrace, "Waiting for next event")
		ev, err := em.eslClient.ReadEvent()
		if err != nil {
			em.eslLog(LogLevelError, "Error reading event: %v", err)
			em.eslDisconnected <- true
			return
		}

		// Update statistics
		em.statsMutex.Lock()
		em.statistics.EventsProcessed++
		em.statsMutex.Unlock()

		// Log the entire event content for debugging if in trace mode
		if em.eslLogLevel >= LogLevelTrace {
			em.eslLog(LogLevelTrace, "Received event with %d headers", len(ev.Header))
			for k, v := range ev.Header {
				em.eslLog(LogLevelTrace, "Header [%s] = %s", k, v)
			}

			if ev.Body != "" {
				em.eslLog(LogLevelTrace, "Event body: %s", ev.Body)
			} else {
				em.eslLog(LogLevelTrace, "Event body is empty")
			}
		}

		// Extract key event information
		eventName := ev.Get("Event-Name")
		eventSubclass := ev.Get("Event-Subclass")

		em.eslLog(LogLevelDebug, "Received event: %s, subclass: %s", eventName, eventSubclass)

		// Process the event based on type
		switch eventName {
		case "CUSTOM":
			switch eventSubclass {
			case "sofia::register":
				em.eslLog(LogLevelDebug, "Sofia Register event")
				em.handleSuccessfulRegistration(ev)
			case "sofia::register_failure":
				em.eslLog(LogLevelDebug, "Sofia Register Failure event")
				em.handleFailedRegistration(ev)
			case "sofia::wrong_call_state":
				em.eslLog(LogLevelDebug, "Sofia Wrong Call State event")
				em.handleWrongCallState(ev)
			default:
				em.eslLog(LogLevelDebug, "Unhandled CUSTOM event subclass: %s", eventSubclass)
			}
		case "CHANNEL_CREATE":
			em.eslLog(LogLevelDebug, "Channel Create event")
			em.handleChannelCreate(ev)
		default:
			em.eslLog(LogLevelDebug, "Unhandled event type: %s", eventName)
		}
	}
}

// handleSuccessfulRegistration processes successful registration events
func (em *ESLManager) handleSuccessfulRegistration(ev *eventsocket.Event) {
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

	// Log information for debugging
	em.eslLog(LogLevelDebug, "Registration info - IP: %s, User: %s, Domain: %s, Status: %s",
		ipAddress, userId, domain, status)

	// Check if we have the minimum information needed
	if ipAddress == "" {
		em.eslLog(LogLevelError, "Failed to extract IP address from registration event (Network-Ip header not found)")

		// Print all headers to help diagnose the issue
		if em.eslLogLevel >= LogLevelDebug {
			em.eslLog(LogLevelDebug, "All available headers:")
			for k, v := range ev.Header {
				em.eslLog(LogLevelDebug, "  Header [%s] = [%s]", k, v)
			}
		}
		return
	}

	// Use default values if still missing
	if userId == "" {
		userId = "unknown"
		em.eslLog(LogLevelDebug, "Could not determine user ID from registration event, using '%s'", userId)
	}

	if domain == "" {
		config := GetConfig()
		domain = config.FreeSWITCH.DefaultDomain
		em.eslLog(LogLevelDebug, "Could not determine domain from registration event, using default '%s'", domain)
	}

	// Check if the IP is within registration rate limits
	if !em.rateManager.CheckRegistrationRate(ipAddress, userId, domain) {
		em.eslLog(LogLevelInfo, "Registration from IP %s blocked due to rate limiting", ipAddress)
		return
	}

	em.eslLog(LogLevelInfo, "Successful registration from IP %s for user %s@%s", ipAddress, userId, domain)

	// Update statistics
	em.securityManager.UpdateRegistrationStats(ipAddress, userId, domain)

	// Auto-whitelist if enabled
	if em.securityManager.securityConfig.AutoWhitelistOnSuccess {
		em.eslLog(LogLevelDebug, "Auto-whitelisting IP %s for user %s@%s", ipAddress, userId, domain)
		em.securityManager.AddToWhitelist(ipAddress, userId, domain, false)
	}
}

// handleWrongCallState handles wrong call state events
func (em *ESLManager) handleWrongCallState(ev *eventsocket.Event) {
	// Extract data from the event
	ipAddress := ev.Get("Network_Ip")
	userId := ev.Get("From_User")

	// Check if we have the minimum information needed
	if ipAddress == "" {
		em.eslLog(LogLevelError, "Failed to extract IP address from wrong call state event (network_ip header not found)")

		// Print all headers to help diagnose the issue
		if em.eslLogLevel >= LogLevelDebug {
			em.eslLog(LogLevelDebug, "All available headers:")
			for k, v := range ev.Header {
				em.eslLog(LogLevelDebug, "  Header [%s] = [%s]", k, v)
			}
		}
		return
	}

	// Use default values if missing
	if userId == "" {
		userId = "unknown"
		em.eslLog(LogLevelDebug, "Could not determine user ID from wrong call state event, using '%s'", userId)
	}

	em.eslLog(LogLevelInfo, "Wrong call state event from IP %s for user %s", ipAddress, userId)

	// Process wrong call state through security manager
	em.securityManager.ProcessWrongCallState(ipAddress, userId)
}

// handleFailedRegistration processes failed registration events
func (em *ESLManager) handleFailedRegistration(ev *eventsocket.Event) {
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

	// Log information for debugging
	em.eslLog(LogLevelDebug, "Failed registration info - IP: %s, User: %s, Domain: %s",
		ipAddress, userId, domain)

	// Check if we have the minimum information needed
	if ipAddress == "" {
		em.eslLog(LogLevelError, "Failed to extract IP address from failed registration event (Network-Ip header not found)")

		// Print all headers to help diagnose the issue
		if em.eslLogLevel >= LogLevelDebug {
			em.eslLog(LogLevelDebug, "All available headers:")
			for k, v := range ev.Header {
				em.eslLog(LogLevelDebug, "  Header [%s] = [%s]", k, v)
			}
		}
		return
	}

	// Use default values if still missing
	if userId == "" {
		userId = "unknown"
		em.eslLog(LogLevelDebug, "Could not determine user ID from failed registration event, using '%s'", userId)
	}

	if domain == "" {
		config := GetConfig()
		domain = config.FreeSWITCH.DefaultDomain
		em.eslLog(LogLevelDebug, "Could not determine domain from failed registration event, using default '%s'", domain)
	}

	em.eslLog(LogLevelInfo, "Failed registration from IP %s for user %s@%s", ipAddress, userId, domain)

	// Process failed registration through security manager
	em.securityManager.ProcessFailedRegistration(ipAddress, userId, domain)
}

// handleChannelCreate handles CHANNEL_CREATE events
func (em *ESLManager) handleChannelCreate(ev *eventsocket.Event) {
	// Extract IP address
	ipAddress := ev.Get("Variable_sip_network_ip")
	if ipAddress == "" {
		ipAddress = ev.Get("Variable_sip_from_host")
		if ipAddress == "" {
			em.eslLog(LogLevelDebug, "Could not determine source IP for channel create event")
			return
		}
	}

	// Extract user ID and domain if available
	userId := ev.Get("Variable_sip_from_user")
	domain := ev.Get("Variable_sip_from_host")

	// Check if this IP exceeds the call rate limit
	allowed := em.rateManager.CheckCallRate(ipAddress, userId, domain)

	if !allowed {
		em.eslLog(LogLevelInfo, "Call from IP %s blocked due to rate limiting", ipAddress)

		// Optional: You can take further action here like hanging up the channel
		callUUID := ev.Get("Unique-ID")
		if callUUID != "" && em.eslClient != nil && em.eslConnected {
			hangupCmd := fmt.Sprintf("uuid_kill %s", callUUID)
			_, err := em.eslClient.Send(hangupCmd)
			if err != nil {
				em.eslLog(LogLevelError, "Error hanging up rate-limited call %s: %v", callUUID, err)
			} else {
				em.eslLog(LogLevelInfo, "Successfully terminated rate-limited call %s", callUUID)
			}
		}
	} else {
		em.eslLog(LogLevelDebug, "Call from IP %s allowed (within rate limits)", ipAddress)
	}
}

// SetESLLogLevel sets the logging level for ESL operations
func (em *ESLManager) SetESLLogLevel(level string) {
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
		log.Printf("Unknown log level '%s', using 'info'", level)
		em.eslLogLevel = LogLevelInfo
	}
	log.Printf("ESL log level set to: %s", level)
}

// GetESLStats returns current ESL statistics
func (em *ESLManager) GetESLStats() map[string]interface{} {
	em.statsMutex.RLock()
	defer em.statsMutex.RUnlock()

	return map[string]interface{}{
		"connected":           em.eslConnected,
		"host":                em.eslConfig.Host,
		"port":                em.eslConfig.Port,
		"connection_attempts": em.statistics.ConnectionAttempts,
		"connection_errors":   em.statistics.ConnectionErrors,
		"events_processed":    em.statistics.EventsProcessed,
		"log_level":           em.eslConfig.LogLevel,
	}
}

// ReconnectESL forces a reconnection to the ESL
func (em *ESLManager) ReconnectESL() {
	if em.eslConnected && em.eslClient != nil {
		log.Println("Manually triggering ESL reconnection")
		em.eslClient.Close()
		em.eslConnected = false
		em.eslDisconnected <- true
	}
}
