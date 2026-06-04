package main

import (
	"log"
	"sync"
	"sync/atomic"
)

// EslLogLevel defines the verbosity of ESL logging.
type EslLogLevel int32

const (
	LogLevelError EslLogLevel = iota
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

// Logger provides a centralized, low-overhead logging interface.
// Level is stored as an atomic int32 so the level check on every
// Info/Debug/Trace call is lock-free.
type Logger struct {
	level atomic.Int32
}

var (
	globalLogger     *Logger
	globalLoggerOnce sync.Once
)

// GetLogger returns the singleton logger instance.
func GetLogger() *Logger {
	globalLoggerOnce.Do(func() {
		globalLogger = &Logger{}
		globalLogger.level.Store(int32(LogLevelInfo))
	})

	return globalLogger
}

// SetLogLevel sets the logging level.
func (l *Logger) SetLogLevel(level EslLogLevel) {
	l.level.Store(int32(level))
}

// String spellings of the log levels, shared by the parser, config defaults,
// and tests.
const (
	logLevelErrorStr = "error"
	logLevelDebugStr = "debug"
	logLevelTraceStr = "trace"
)

// eslLogLevelFromString maps a level name to its EslLogLevel. The second
// return reports whether the name was recognized; unknown names map to info.
func eslLogLevelFromString(name string) (EslLogLevel, bool) {
	switch name {
	case logLevelErrorStr:
		return LogLevelError, true
	case logLevelInfoStr:
		return LogLevelInfo, true
	case logLevelDebugStr:
		return LogLevelDebug, true
	case logLevelTraceStr:
		return LogLevelTrace, true
	default:
		return LogLevelInfo, false
	}
}

// SetLogLevelFromString sets the logging level from a string.
// Unknown values default to info.
func (l *Logger) SetLogLevelFromString(name string) {
	level, ok := eslLogLevelFromString(name)
	if !ok {
		log.Printf("Unknown log level %q, using 'info'", name)
	}

	l.SetLogLevel(level)
}

// GetLogLevel returns the current log level.
func (l *Logger) GetLogLevel() EslLogLevel {
	return EslLogLevel(l.level.Load())
}

func (l *Logger) Error(format string, args ...any) {
	if l.enabled(LogLevelError) {
		log.Printf("[ESL ERROR] "+format, args...)
	}
}

func (l *Logger) Info(format string, args ...any) {
	if l.enabled(LogLevelInfo) {
		log.Printf("[ESL INFO] "+format, args...)
	}
}

func (l *Logger) Debug(format string, args ...any) {
	if l.enabled(LogLevelDebug) {
		log.Printf("[ESL DEBUG] "+format, args...)
	}
}

func (l *Logger) Trace(format string, args ...any) {
	if l.enabled(LogLevelTrace) {
		log.Printf("[ESL TRACE] "+format, args...)
	}
}

// Log emits a message at the given level if the level is currently enabled.
func (l *Logger) Log(level EslLogLevel, format string, args ...any) {
	if !l.enabled(level) {
		return
	}

	var prefix string

	switch level {
	case LogLevelError:
		prefix = "[ESL ERROR] "
	case LogLevelInfo:
		prefix = "[ESL INFO] "
	case LogLevelDebug:
		prefix = "[ESL DEBUG] "
	case LogLevelTrace:
		prefix = "[ESL TRACE] "
	default:
		prefix = "[ESL ?] "
	}

	log.Printf(prefix+format, args...)
}

// enabled reports whether the given level is currently active.
// It is intentionally inlinable.
func (l *Logger) enabled(level EslLogLevel) bool {
	return int32(level) <= l.level.Load()
}
