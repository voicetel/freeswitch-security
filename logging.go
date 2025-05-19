package main

import (
	"log"
	"sync"
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

// Logger provides a centralized logging interface
type Logger struct {
	logLevel EslLogLevel
	mutex    sync.RWMutex
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// GetLogger returns the singleton logger instance
func GetLogger() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = &Logger{
			logLevel: LogLevelInfo, // Default to info level
		}
	})
	return globalLogger
}

// SetLogLevel sets the logging level
func (l *Logger) SetLogLevel(level EslLogLevel) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.logLevel = level
}

// SetLogLevelFromString sets the logging level from a string representation
func (l *Logger) SetLogLevelFromString(levelStr string) {
	var level EslLogLevel = LogLevelInfo // Default to info level

	switch levelStr {
	case "error":
		level = LogLevelError
	case "info":
		level = LogLevelInfo
	case "debug":
		level = LogLevelDebug
	case "trace":
		level = LogLevelTrace
	default:
		log.Printf("Unknown log level '%s', using 'info'", levelStr)
	}

	l.SetLogLevel(level)
}

// GetLogLevel returns the current logging level
func (l *Logger) GetLogLevel() EslLogLevel {
	l.mutex.RLock()
	defer l.mutex.RUnlock()
	return l.logLevel
}

// Error logs error messages
func (l *Logger) Error(format string, args ...interface{}) {
	if LogLevelError <= l.GetLogLevel() {
		log.Printf("[ESL ERROR] "+format, args...)
	}
}

// Info logs informational messages
func (l *Logger) Info(format string, args ...interface{}) {
	if LogLevelInfo <= l.GetLogLevel() {
		log.Printf("[ESL INFO] "+format, args...)
	}
}

// Debug logs debug messages
func (l *Logger) Debug(format string, args ...interface{}) {
	if LogLevelDebug <= l.GetLogLevel() {
		log.Printf("[ESL DEBUG] "+format, args...)
	}
}

// Trace logs trace messages (highest verbosity)
func (l *Logger) Trace(format string, args ...interface{}) {
	if LogLevelTrace <= l.GetLogLevel() {
		log.Printf("[ESL TRACE] "+format, args...)
	}
}

// Log is a generic logging function that respects the log level
func (l *Logger) Log(level EslLogLevel, format string, args ...interface{}) {
	if level <= l.GetLogLevel() {
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
