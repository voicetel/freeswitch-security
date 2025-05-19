# Logging System Documentation

The FreeSWITCH Security application features a robust, centralized logging system designed to provide consistent logging capabilities across all components. This document details how the logging system works, how to configure it, and how to effectively use logs for troubleshooting.

## Logging Architecture

The logging system is implemented in `logging.go` and provides a singleton `Logger` instance accessible throughout the application. Key features include:

- Thread-safe operation with mutex protection
- Multiple verbosity levels
- Dynamic log level configuration
- Focused Event Socket Layer (ESL) logging

### Log Levels

The application supports four log levels, each providing a different degree of verbosity:

| Level | Enum Value | Description | Use Case |
|-------|------------|-------------|----------|
| Error | 0 | Critical issues that impact functionality | Production environments, critical alerts |
| Info | 1 | General information about operations | Production environments, general monitoring |
| Debug | 2 | Detailed information for troubleshooting | Development, testing, troubleshooting |
| Trace | 3 | Extremely detailed information including message contents | Development, deep troubleshooting |

Each level is inclusive of the lower levels. For example, setting the log level to `Debug` will include `Error`, `Info`, and `Debug` messages, but not `Trace` messages.

## Configuring Logging

### Configuration File Method

In your `config.json`, set the log level in the security section:

```json
"security": {
  "esl_log_level": "debug"  // Options: "error", "info", "debug", "trace"
}
```

### Environment Variable Method

Set the log level using an environment variable:

```bash
export SECURITY_ESL_LOG_LEVEL=debug
```

### Runtime API Method

Adjust the log level dynamically during runtime using the API:

```bash
curl -X POST http://127.0.0.1:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}'
```

## Log Output Format

The log messages follow this format:

```
[ESL LEVEL] message
```

Where:
- `LEVEL` is one of: `ERROR`, `INFO`, `DEBUG`, or `TRACE`
- `message` is the formatted log message

Examples:

```
[ESL INFO] Successfully connected to FreeSWITCH ESL in 15.5ms
[ESL DEBUG] Received event: CUSTOM, subclass: sofia::register
[ESL ERROR] Failed to extract IP address from registration event (Network-Ip header not found)
```

## When to Use Each Log Level

### Error Level

Use for serious issues that affect the functionality of the application:
- Connection failures
- Authentication errors
- Configuration problems
- Runtime exceptions

### Info Level

Use for important operational information:
- Application startup/shutdown
- Connection establishment/closure
- Security events (IP blocking, whitelist additions)
- Periodic status updates

### Debug Level

Use for detailed troubleshooting information:
- Event processing details
- Rate limiting decisions
- Cache operations
- IP checks against white/blacklists

### Trace Level

Use for the most detailed debugging, including message contents:
- Complete event headers and bodies
- Network request/response details
- Full configuration dumps
- Security decision process details

## Logging Best Practices

1. **Production Environments**: Use `error` or `info` levels to keep logs manageable and focused on important events.

2. **Development/Testing**: Use `debug` or `trace` levels for comprehensive information during development and testing.

3. **Troubleshooting Issues**:
   - Start with `info` level
   - If more details are needed, increase to `debug`
   - For complex issues, use `trace` level temporarily
   - Return to normal levels after troubleshooting

4. **Log Rotation**: Implement log rotation for production deployments to manage log file sizes.

5. **Sensitive Information**: Be cautious about `trace` level logs in production as they may contain sensitive information like SIP authentication details.

## Log Examples For Common Scenarios

### Successful Registration

```
[ESL DEBUG] Registration info - IP: 192.168.1.100, User: 1001, Domain: example.com, Status: Registered
[ESL INFO] Successful registration from IP 192.168.1.100 for user 1001@example.com
```

### Failed Registration

```
[ESL DEBUG] Failed registration info - IP: 203.0.113.25, User: unknown, Domain: example.com
[ESL INFO] Failed registration from IP 203.0.113.25 for user unknown@example.com
```

### Auto-Blocking

```
[ESL INFO] Threshold exceeded: Auto-blocking IP 203.0.113.25 - Exceeded max failed registrations (5)
[ESL INFO] Added IP 203.0.113.25 to blacklist: Exceeded max failed registrations (5) (expires: 2023-04-15T15:30:45Z, permanent: false)
[ESL INFO] Blocked IP 203.0.113.25 with iptables in chain FREESWITCH
```

### ESL Connection

```
[ESL INFO] Attempting to connect to FreeSWITCH ESL (Attempt #1) at 127.0.0.1:8021
[ESL INFO] Successfully connected to FreeSWITCH ESL in 25.3ms
[ESL INFO] Successfully subscribed to sofia::register events
```

## Troubleshooting with Logs

### Common Issues and Log Patterns

#### ESL Connection Problems

```
[ESL ERROR] Failed to connect to FreeSWITCH ESL: dial tcp 127.0.0.1:8021: connection refused
```

**Troubleshooting steps:**
1. Verify FreeSWITCH is running
2. Check that mod_event_socket is loaded
3. Verify ESL configuration in event_socket.conf.xml
4. Ensure the configured port is open in firewalls

#### Authentication Issues

```
[ESL ERROR] Failed to connect to FreeSWITCH ESL: auth failed
[ESL ERROR] Authentication failed! Please check your ESL password.
```

**Troubleshooting steps:**
1. Verify the password in config.json matches the one in FreeSWITCH's event_socket.conf.xml
2. Check for special characters that might need escaping

#### No Events Received

```
[ESL INFO] Connection established - waiting for events. If none arrive, check FreeSWITCH event generation.
```

**Troubleshooting steps:**
1. Verify event subscriptions in the application
2. Check FreeSWITCH event generation settings
3. Try generating test events by making registration attempts

### Increasing Log Verbosity for Troubleshooting

1. Set log level to debug:
   ```bash
   curl -X POST http://127.0.0.1:8080/security/esl/log_level \
     -H "Content-Type: application/json" \
     -d '{"level": "debug"}'
   ```

2. For deeper issues, set to trace:
   ```bash
   curl -X POST http://127.0.0.1:8080/security/esl/log_level \
     -H "Content-Type: application/json" \
     -d '{"level": "trace"}'
   ```

3. Generate events by making test calls or registrations

4. Analyze the logs to identify the issue

5. Return to normal log level after troubleshooting:
   ```bash
   curl -X POST http://127.0.0.1:8080/security/esl/log_level \
     -H "Content-Type: application/json" \
     -d '{"level": "info"}'
   ```

## Code Example: Using the Logger

```go
package main

import (
    // your imports
)

func someFunction() {
    // Get the logger instance
    logger := GetLogger()

    // Log at different levels
    logger.Error("Critical failure when connecting to %s: %v", host, err)
    logger.Info("Processing registration from IP %s", ipAddress)
    logger.Debug("Checking if IP %s is whitelisted", ipAddress)
    logger.Trace("Event details: %+v", event)

    // Conditionally log based on dynamic conditions
    if shouldLogDetails {
        logger.Debug("Detailed processing information: %+v", details)
    }
}
```

## Conclusion

Effective use of the logging system is crucial for monitoring, troubleshooting, and maintaining the FreeSWITCH Security application. By selecting appropriate log levels and understanding the log patterns, you can ensure optimal performance while having the necessary information available when issues arise.

For further assistance with specific log messages or troubleshooting scenarios, please open an issue on the project repository.
