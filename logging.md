# Logging System Documentation

The FreeSWITCH Security application features a sophisticated, high-performance logging system designed for enterprise-grade VoIP security monitoring. The system provides real-time insights into security events, performance metrics, and system health with configurable verbosity levels and zero-allocation logging paths.

## 🏗️ Architecture Overview

The logging system is built on a singleton pattern with thread-safe operations, providing consistent logging capabilities across all application components:

- **Centralized Logger Instance**: Single point of configuration and control
- **Thread-Safe Operations**: Mutex-protected concurrent access
- **Dynamic Level Configuration**: Runtime log level adjustments via API
- **Performance Optimized**: Minimal overhead in production environments
- **Memory Efficient**: Zero-allocation logging paths for hot code paths

## 📊 Log Levels

The application supports four hierarchical log levels, each serving specific operational needs:

| Level | Value | Description | Use Case | Performance Impact |
|-------|-------|-------------|----------|-------------------|
| **Error** | 0 | Critical issues requiring immediate attention | Production alerts, system failures | Minimal |
| **Info** | 1 | Important operational events and status updates | Production monitoring, audit trails | Low |
| **Debug** | 2 | Detailed troubleshooting information | Development, problem diagnosis | Moderate |
| **Trace** | 3 | Comprehensive event details including message contents | Deep debugging, protocol analysis | High |

### Level Hierarchy

Log levels are inclusive of lower levels. Setting `Debug` will output `Error`, `Info`, and `Debug` messages, but exclude `Trace` messages.

## ⚙️ Configuration Methods

### 1. Configuration File

Set the default log level in `config.json`:

```json
{
  "security": {
    "esl_log_level": "info"
  }
}
```

**Supported Values**: `"error"`, `"info"`, `"debug"`, `"trace"`

### 2. Environment Variables

Override configuration file settings:

```bash
export SECURITY_ESL_LOG_LEVEL=debug
./freeswitch-security
```

### 3. Runtime API (Recommended for Production)

Dynamically adjust log levels without restarting:

```bash
# Increase verbosity for troubleshooting
curl -X POST http://127.0.0.1:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}'

# Return to production level
curl -X POST http://127.0.0.1:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level": "info"}'
```

**API Response:**
```json
{
  "status": "success",
  "message": "ESL log level set to debug"
}
```

## 📝 Log Message Format

All log messages follow a consistent, parseable format:

```
[ESL LEVEL] timestamp message_content
```

**Components:**
- `ESL`: Application identifier
- `LEVEL`: Log level (ERROR, INFO, DEBUG, TRACE)
- `timestamp`: Automatic Go log timestamp
- `message_content`: Formatted message with context

**Examples:**
```
2024-01-15T10:30:45.123Z [ESL INFO] Successfully connected to FreeSWITCH ESL in 15.5ms
2024-01-15T10:30:46.456Z [ESL DEBUG] Received event: CUSTOM, subclass: sofia::register
2024-01-15T10:30:47.789Z [ESL ERROR] Failed to extract IP address from registration event
```

## 🎯 Logging Best Practices by Level

### Error Level - Critical Issues Only

**Use for:**
- Connection failures to FreeSWITCH
- Authentication/authorization failures
- Configuration errors preventing startup
- Runtime exceptions affecting functionality
- IPTables command failures

**Example Messages:**
```log
[ESL ERROR] Failed to connect to FreeSWITCH ESL: dial tcp 127.0.0.1:8021: connection refused
[ESL ERROR] Authentication failed! Please check your ESL password
[ESL ERROR] Error parsing registration window: time: invalid duration "10x"
[ESL ERROR] IPTables command failed: exit status 1
```

### Info Level - Operational Events

**Use for:**
- Application lifecycle events (start/stop)
- Connection establishment/closure
- Security actions (IP blocking, whitelisting)
- Rate limiting decisions
- Periodic health status
- Worker pool changes

**Example Messages:**
```log
[ESL INFO] Security manager initialized with dynamic channel sizing
[ESL INFO] Successfully connected to FreeSWITCH ESL in 25.3ms
[ESL INFO] Auto-blocking IP 203.0.113.25 - Exceeded max failed registrations (5)
[ESL INFO] Resized failed attempt channel from 5000 to 10000 (high load detected)
[ESL INFO] ESL log level set to: debug
```

### Debug Level - Detailed Troubleshooting

**Use for:**
- Event processing details
- Security decision logic
- Cache operations and hit/miss ratios
- Rate limiting calculations
- Worker assignment and processing
- Channel resize decisions
- Memory pool operations

**Example Messages:**
```log
[ESL DEBUG] Worker #3 processing event: CUSTOM/sofia::register
[ESL DEBUG] Registration info - IP: 192.168.1.100, User: 1001, Domain: example.com
[ESL DEBUG] IP 192.168.1.100 is whitelisted, bypassing call rate limit
[ESL DEBUG] Channel monitor - Queue: 45/1000, Events queued: 15234, Dropped: 0
[ESL DEBUG] Cache hit for key: whitelist:192.168.1.100
```

### Trace Level - Complete Event Details

**Use for:**
- Full event headers and content
- Network request/response bodies
- Complete configuration dumps
- Memory allocation tracking
- Performance timing details
- Protocol-level debugging

**Example Messages:**
```log
[ESL TRACE] Worker #2 processing event: CUSTOM/sofia::register
[ESL TRACE] Event headers: {Event-Name: CUSTOM, Event-Subclass: sofia::register, ...}
[ESL TRACE] Complete event body: [full SIP message content]
[ESL TRACE] Memory pool: allocated 1 ProcessedEvent, pool size: 47
[ESL TRACE] Worker #2 processed CUSTOM event in 1.234ms
```

## 🔧 Advanced Configuration

### Production Logging Strategy

```json
{
  "security": {
    "esl_log_level": "info"
  },
  "server": {
    "log_requests": false,
    "log_responses": false
  }
}
```

### Development/Testing Strategy

```json
{
  "security": {
    "esl_log_level": "debug"
  },
  "server": {
    "log_requests": true,
    "log_responses": false
  }
}
```

### Troubleshooting Strategy

```bash
# Temporarily increase verbosity
curl -X POST http://localhost:8080/security/esl/log_level \
  -d '{"level": "trace"}'

# Generate test events
# [perform actions that trigger the issue]

# Return to normal level
curl -X POST http://localhost:8080/security/esl/log_level \
  -d '{"level": "info"}'
```

## 🔍 Troubleshooting Guide

### Common Scenarios and Log Patterns

#### 1. ESL Connection Issues

**Symptoms:**
```log
[ESL ERROR] Failed to connect to FreeSWITCH ESL: dial tcp 127.0.0.1:8021: connection refused
[ESL INFO] Attempting to connect to FreeSWITCH ESL (Attempt #2) at 127.0.0.1:8021
```

**Diagnosis Steps:**
1. Verify FreeSWITCH is running: `fs_cli -x "status"`
2. Check mod_event_socket is loaded: `fs_cli -x "module_exists mod_event_socket"`
3. Verify ESL configuration in `event_socket.conf.xml`
4. Test network connectivity: `telnet 127.0.0.1 8021`

#### 2. Authentication Problems

**Symptoms:**
```log
[ESL ERROR] Authentication failed! Please check your ESL password
[ESL ERROR] Failed to connect to FreeSWITCH ESL: auth failed
```

**Resolution:**
- Compare password in `config.json` with FreeSWITCH `event_socket.conf.xml`
- Check for special characters requiring escaping
- Verify ACL permissions in FreeSWITCH configuration

#### 3. High Event Volume Issues

**Symptoms:**
```log
[ESL ERROR] Event queue full, dropping event
[ESL INFO] Resized failed attempt channel from 5000 to 20000 (high load detected)
[ESL DEBUG] Channel monitor - Queue: 950/1000, Events queued: 25000, Dropped: 15
```

**Optimization:**
- Monitor queue depths: `GET /security/channels`
- Adjust worker count based on CPU cores
- Increase initial queue sizes in configuration
- Consider hardware upgrades for sustained high load

#### 4. Memory/Performance Issues

**Symptoms:**
```log
[ESL DEBUG] Memory pool: allocated 500 ProcessedEvent, pool size: 50
[ESL DEBUG] Worker #5 processed CUSTOM event in 15.234ms (slow)
```

**Investigation:**
- Monitor system resources: `GET /system/stats`
- Check garbage collection frequency
- Verify object pool efficiency
- Analyze processing time trends

### Debug Workflow

#### Step 1: Increase Verbosity
```bash
curl -X POST http://localhost:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level": "debug"}'
```

#### Step 2: Monitor Real-time Logs
```bash
# Follow application logs
tail -f /var/log/freeswitch-security.log

# Or if running in foreground
./freeswitch-security | grep "\[ESL"
```

#### Step 3: Generate Test Events
```bash
# Trigger registration events
fs_cli -x "sofia profile internal flush_inbound_reg"

# Generate failed registration
# [attempt registration with wrong credentials]

# Create call events
fs_cli -x "originate user/1001 &echo"
```

#### Step 4: Analyze Patterns
Look for patterns in:
- Event processing times
- Queue depth changes
- Memory pool utilization
- Error frequency and types

#### Step 5: Return to Production Level
```bash
curl -X POST http://localhost:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level": "info"}'
```

## 📊 Log Analysis and Monitoring

### Key Metrics to Extract

#### Security Metrics
```bash
# Count blocked IPs
grep "Auto-blocking IP" /var/log/freeswitch-security.log | wc -l

# Analyze attack patterns
grep "Failed registration" /var/log/freeswitch-security.log | \
  awk '{print $8}' | sort | uniq -c | sort -nr
```

#### Performance Metrics
```bash
# Event processing rates
grep "Worker.*processed.*event" /var/log/freeswitch-security.log | \
  grep "$(date +%Y-%m-%d)" | wc -l

# Queue resize events
grep "Resized.*channel" /var/log/freeswitch-security.log
```

#### Connection Health
```bash
# Connection attempts and success
grep -E "(Attempting to connect|Successfully connected)" \
  /var/log/freeswitch-security.log
```

### Log Rotation Configuration

**Using logrotate:**
```bash
# /etc/logrotate.d/freeswitch-security
/var/log/freeswitch-security.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        killall -USR1 freeswitch-security || true
    endscript
}
```

### Structured Logging with JSON

For automated analysis, consider redirecting logs to structured formats:

```bash
./freeswitch-security 2>&1 | \
  jq -R 'split(" ") | {timestamp: .[0], level: .[1], message: (.[2:] | join(" "))}'
```

## 🚨 Alerting and Monitoring

### Critical Alerts

Set up monitoring for these log patterns:

```bash
# High error rate
grep -c "\[ESL ERROR\]" /var/log/freeswitch-security.log

# Connection failures
grep "Failed to connect to FreeSWITCH ESL" /var/log/freeswitch-security.log

# Authentication issues
grep "Authentication failed" /var/log/freeswitch-security.log

# Queue overflows
grep "Event queue full" /var/log/freeswitch-security.log
```

### Performance Monitoring

```bash
# Processing latency (trace level required)
grep "processed.*event in" /var/log/freeswitch-security.log | \
  sed 's/.*in \([0-9.]*\)ms/\1/' | \
  awk '{sum+=$1; count++} END {print "Average:", sum/count "ms"}'

# Memory pool efficiency
grep "Memory pool:" /var/log/freeswitch-security.log | tail -10
```

## 🛠️ Code Examples

### Custom Logging in Extensions

```go
func customSecurityCheck(ip string) {
    logger := GetLogger()

    // Log at appropriate level
    logger.Debug("Starting security check for IP %s", ip)

    if isBlacklisted(ip) {
        logger.Info("Blocked access attempt from blacklisted IP %s", ip)
        return
    }

    if err := performCheck(ip); err != nil {
        logger.Error("Security check failed for IP %s: %v", ip, err)
        return
    }

    logger.Debug("Security check completed successfully for IP %s", ip)
}
```

### Performance Logging

```go
func processWithTiming(event *Event) {
    logger := GetLogger()
    start := time.Now()

    // Process event
    err := processEvent(event)

    duration := time.Since(start)

    if logger.GetLogLevel() >= LogLevelTrace {
        logger.Trace("Event processing completed in %v", duration)
    }

    if duration > time.Millisecond*10 {
        logger.Debug("Slow event processing detected: %v", duration)
    }
}
```

## 🎛️ Log Level Management Strategy

### Production Deployment

1. **Start with Info Level**: Provides operational visibility without performance impact
2. **Monitor Error Patterns**: Set up alerting for ERROR level messages
3. **Scheduled Debug Sessions**: Temporarily increase verbosity during maintenance windows
4. **Emergency Troubleshooting**: Use API to enable trace level for specific issues

### Development Workflow

1. **Default Debug Level**: Maximum visibility during development
2. **Trace for Complex Issues**: Enable when diagnosing protocol or timing issues
3. **Performance Testing**: Use Info level to minimize logging overhead
4. **Integration Testing**: Debug level for event flow validation

### Operational Guidelines

```bash
# Daily health check
curl -s http://localhost:8080/security/esl | jq '.connected'

# Weekly log level audit
grep "ESL log level set" /var/log/freeswitch-security.log | tail -5

# Performance baseline
curl -s http://localhost:8080/security/channels | jq '.channel_stats'
```

## 🔧 Advanced Features

### Log Filtering by Component

The logging system automatically prefixes all messages with `[ESL LEVEL]`, making it easy to filter:

```bash
# ESL-specific logs only
grep "\[ESL" /var/log/application.log

# Error logs only
grep "\[ESL ERROR\]" /var/log/application.log

# Security decision logs
grep -E "(Auto-blocking|whitelisted|blacklisted)" /var/log/application.log
```

### Integration with External Systems

#### Syslog Integration
```bash
./freeswitch-security 2>&1 | logger -t freeswitch-security
```

#### ELK Stack Integration
```bash
# Filebeat configuration for structured parsing
- type: log
  paths:
    - /var/log/freeswitch-security.log
  multiline.pattern: '^\d{4}-\d{2}-\d{2}'
  multiline.negate: true
  multiline.match: after
```

## 📈 Performance Impact

### Log Level Performance Characteristics

| Level | CPU Overhead | Disk I/O | Network Impact | Recommended Use |
|-------|-------------|----------|----------------|-----------------|
| Error | <0.1% | Minimal | None | Always enabled |
| Info | <0.5% | Low | Minimal | Production default |
| Debug | 1-3% | Moderate | Low | Troubleshooting |
| Trace | 5-15% | High | Moderate | Emergency diagnosis |

### Optimization Tips

1. **Use Appropriate Levels**: Don't run trace in production
2. **Structured Queries**: Use grep patterns for specific searches
3. **Log Rotation**: Implement proper log rotation to manage disk space
4. **Remote Logging**: Consider centralized logging for distributed deployments

## 🔚 Conclusion

The FreeSWITCH Security logging system provides comprehensive visibility into application behavior and security events. By following the guidelines in this documentation, you can:

- **Maintain optimal performance** while preserving necessary visibility
- **Quickly diagnose issues** using appropriate log levels and patterns
- **Implement effective monitoring** for proactive system management
- **Scale logging appropriately** for your deployment environment

For additional support or specific logging scenarios not covered here, please refer to the main [README.md](README.md) or open an issue in the project repository.

---

**Related Documentation:**
- [IPTables Security Guide](iptables.md) - Firewall integration and security
- [ESL Command API](esl.md) - FreeSWITCH command interface
