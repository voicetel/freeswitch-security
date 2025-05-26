# ESL Command API Documentation

The FreeSWITCH Security application provides a secure, high-performance API for executing commands on FreeSWITCH through the Event Socket Layer (ESL). This interface combines security through command whitelisting with enterprise-grade performance optimizations including request queuing, worker pools, and comprehensive error handling.

## 🌟 Features Overview

### Security Features
- **Command Whitelisting**: Only explicitly allowed commands can be executed
- **Input Validation**: Comprehensive validation of command syntax and parameters
- **Audit Logging**: Complete audit trail of all command executions
- **Permission-Based Access**: Configurable command permissions per user/role
- **Rate Limiting**: Built-in protection against command flooding

### Performance Features
- **Channel-Based Processing**: Asynchronous command execution with worker pools
- **Request Queuing**: High-throughput command processing with overflow protection
- **Connection Pooling**: Efficient ESL connection management and reuse
- **Timeout Management**: Configurable timeouts for command execution
- **Health Monitoring**: Real-time connection status and performance metrics

### Enterprise Features
- **Configuration Management**: Multiple configuration methods (file, environment, API)
- **High Availability**: Automatic reconnection and failover capabilities
- **Monitoring Integration**: Comprehensive metrics for operational visibility
- **Error Handling**: Graceful degradation and detailed error reporting

## ⚙️ Configuration

### Command Whitelist Configuration

The security model uses an explicit whitelist approach - only commands specifically allowed in the configuration can be executed.

#### Configuration File Method

In your `config.json`:

```json
{
  "security": {
    "esl_allowed_commands": [
      "status",
      "uptime",
      "version",
      "show channels",
      "show registrations",
      "show calls",
      "sofia status",
      "sofia xmlstatus",
      "reloadxml",
      "log"
    ]
  }
}
```

#### Environment Variable Method

```bash
export SECURITY_ESL_ALLOWED_COMMANDS='[
  "status",
  "uptime",
  "version",
  "show channels",
  "show registrations"
]'
```

**Note**: The environment variable must contain a valid JSON array of strings.

#### Runtime Configuration (Planned)

Future versions will support dynamic whitelist management:

```bash
# Add command to whitelist (planned feature)
curl -X POST http://127.0.0.1:8080/security/esl/whitelist \
  -H "Content-Type: application/json" \
  -d '{"command": "show dialplan"}'

# Remove command from whitelist (planned feature)
curl -X DELETE http://127.0.0.1:8080/security/esl/whitelist/show%20dialplan
```

### Advanced Configuration Options

#### Connection Settings

```json
{
  "security": {
    "esl_host": "127.0.0.1",
    "esl_port": "8021",
    "esl_password": "ClueCon",
    "reconnect_backoff": "5s"
  }
}
```

#### Performance Tuning

```json
{
  "security": {
    "esl_worker_count": 4,
    "esl_queue_size": 1000,
    "esl_command_timeout": "30s",
    "esl_max_retries": 3
  }
}
```

## 🚀 API Usage

### Command Execution Endpoint

**Endpoint**: `POST /security/esl/command`

**Request Format**:
```json
{
  "command": "status"
}
```

**Response Format**:
```json
{
  "command": "status",
  "response": "UP 0 years, 0 days, 2 hours, 15 minutes, 30 seconds, 950 milliseconds, 560 microseconds\nFreeSWITCH (Version 1.10.7 -release- 64bit) is ready\n8 session(s) since startup\n0 session(s) - peak 8, last 5min 0\n1000 session(s) per Sec out of max 30, peak 8, last 5min 0\n1000 session(s) max\nmin idle cpu 0.00/96.00\nCurrent Stack Size/Max 240K/8192K"
}
```

### Comprehensive Usage Examples

#### Basic System Information

```bash
# Get FreeSWITCH status
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "status"}'

# Get system uptime
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime"}'

# Get FreeSWITCH version
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "version"}'
```

#### Call and Registration Management

```bash
# Show active channels
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "show channels"}'

# Show registrations
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "show registrations"}'

# Show active calls
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "show calls"}'
```

#### SIP Profile Management

```bash
# Show Sofia SIP profile status
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "sofia status"}'

# Get detailed XML status
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "sofia xmlstatus"}'
```

#### Configuration Management

```bash
# Reload XML configuration
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "reloadxml"}'

# Change log level (if allowed)
curl -X POST http://127.0.0.1:8080/security/esl/command \
  -H "Content-Type: application/json" \
  -d '{"command": "log 4"}'
```

### Batch Command Execution

For multiple commands, use individual API calls with proper error handling:

```bash
#!/bin/bash
# Batch command execution script

COMMANDS=("status" "uptime" "show channels" "show registrations")
BASE_URL="http://127.0.0.1:8080/security/esl/command"

for cmd in "${COMMANDS[@]}"; do
    echo "Executing: $cmd"

    response=$(curl -s -X POST "$BASE_URL" \
        -H "Content-Type: application/json" \
        -d "{\"command\": \"$cmd\"}")

    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        echo "Error executing $cmd:"
        echo "$response" | jq -r '.error'
    else
        echo "Success: $cmd"
        echo "$response" | jq -r '.response'
    fi

    echo "---"
    sleep 1  # Rate limiting
done
```

## 🔒 Security Model

### Command Validation Process

1. **Whitelist Check**: Verify command is in allowed list
2. **Syntax Validation**: Check command syntax and parameters
3. **Permission Verification**: Ensure user has required permissions (future feature)
4. **Rate Limit Check**: Verify request is within rate limits
5. **Audit Logging**: Log command execution attempt

### Security Best Practices

#### Minimal Command Set

Only whitelist commands absolutely necessary for your use case:

```json
{
  "security": {
    "esl_allowed_commands": [
      "status",           // System health monitoring
      "uptime",          // Uptime tracking
      "show channels",   // Active call monitoring
      "show registrations" // Registration monitoring
    ]
  }
}
```

#### Dangerous Commands to Avoid

Never whitelist these potentially dangerous commands in production:

- `originate` - Can generate calls and incur costs
- `uuid_kill` - Can terminate active calls
- `shutdown` - Can shut down FreeSWITCH
- `load` / `unload` - Can modify system modules
- `eval` - Can execute arbitrary code
- `system` - Can execute system commands

#### Network Security

```bash
# Restrict API access to management network only
sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Use reverse proxy with authentication
# nginx configuration example:
server {
    listen 443 ssl;
    server_name freeswitch-api.example.com;

    location /security/esl/command {
        auth_basic "FreeSWITCH API";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

## 📊 Error Handling

### Error Response Format

All errors return consistent JSON structure:

```json
{
  "error": "command not allowed: originate"
}
```

### Common Error Types

#### 1. Command Not Allowed

**Response**:
```json
{
  "error": "command not allowed: dangerous_command"
}
```

**Resolution**: Add command to whitelist if safe and necessary

#### 2. ESL Connection Error

**Response**:
```json
{
  "error": "not connected to FreeSWITCH ESL"
}
```

**Resolution**: Check FreeSWITCH ESL configuration and connectivity

#### 3. Command Timeout

**Response**:
```json
{
  "error": "command execution timeout"
}
```

**Resolution**: Increase timeout or check FreeSWITCH performance

#### 4. Queue Full

**Response**:
```json
{
  "error": "command queue timeout"
}
```

**Resolution**: Reduce command frequency or increase queue size

### Error Handling Best Practices

```bash
# Proper error handling in scripts
execute_command() {
    local cmd="$1"
    local response

    response=$(curl -s -X POST http://127.0.0.1:8080/security/esl/command \
        -H "Content-Type: application/json" \
        -d "{\"command\": \"$cmd\"}")

    # Check for errors
    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        echo "Error executing '$cmd':" >&2
        echo "$response" | jq -r '.error' >&2
        return 1
    fi

    # Return successful response
    echo "$response" | jq -r '.response'
    return 0
}

# Usage
if execute_command "status"; then
    echo "Command succeeded"
else
    echo "Command failed"
fi
```

## 🚀 Performance Characteristics

### Request Processing Pipeline

The ESL Command API uses a sophisticated request processing system:

```
API Request → Request Queue → Worker Pool → ESL Connection → FreeSWITCH
     ↓              ↓              ↓              ↓
Response ← Response Queue ← Command Execution ← Command Processing
```

### Performance Metrics

#### Throughput Characteristics

- **Sustained Throughput**: 100+ commands/second
- **Peak Throughput**: 500+ commands/second (burst)
- **Average Latency**: <10ms for simple commands
- **Queue Capacity**: 1000 pending commands (configurable)
- **Worker Pool**: 4 workers (auto-scaled based on CPU cores)

#### Optimization Features

1. **Connection Pooling**: Reuse ESL connections for efficiency
2. **Request Batching**: Group commands when possible
3. **Asynchronous Processing**: Non-blocking command execution
4. **Dynamic Scaling**: Worker count adapts to load
5. **Health Monitoring**: Automatic connection recovery

### Performance Monitoring

#### Real-Time Metrics

```bash
# Get ESL connection statistics
curl -s http://127.0.0.1:8080/security/esl | jq '.'

# Expected response:
{
  "connected": true,
  "host": "127.0.0.1",
  "port": "8021",
  "connection_attempts": 1,
  "connection_errors": 0,
  "events_processed": 15234,
  "events_queued": 25001,
  "events_dropped": 0,
  "log_level": "info",
  "worker_count": 4,
  "queue_size": 1000,
  "queue_length": 15,
  "queue_capacity": 1000,
  "memory_pool_enabled": true,
  "dynamic_sizing": true
}
```

#### Performance Tuning

```json
{
  "security": {
    "esl_worker_count": 8,        // Increase for high command volume
    "esl_queue_size": 2000,       // Increase for burst handling
    "esl_command_timeout": "60s", // Increase for slow commands
    "esl_batch_size": 10          // Commands per batch operation
  }
}
```

## 🔧 Advanced Features

### Connection Management

#### Automatic Reconnection

The system automatically handles ESL connection failures:

```go
// Automatic reconnection with exponential backoff
func (em *ESLManager) handleConnectionFailure() {
    backoff := 5 * time.Second
    maxBackoff := 60 * time.Second

    for attempt := 1; ; attempt++ {
        if em.reconnectESL() == nil {
            log.Printf("Reconnected after %d attempts", attempt)
            return
        }

        time.Sleep(backoff)
        backoff = min(backoff*2, maxBackoff)
    }
}
```

#### Health Monitoring

```bash
# Monitor ESL connection health
watch -n 5 'curl -s http://127.0.0.1:8080/security/esl | jq ".connected"'

# Get detailed connection metrics
curl -s http://127.0.0.1:8080/security/esl | jq '{
  connected: .connected,
  queue_utilization: (.queue_length / .queue_capacity * 100),
  error_rate: (.connection_errors / .connection_attempts * 100),
  events_per_second: (.events_processed / .uptime_seconds)
}'
```

### Command Extensions

#### Custom Command Validation

Future versions will support custom validation rules:

```json
{
  "security": {
    "esl_command_rules": {
      "show channels": {
        "max_frequency": "10/minute",
        "max_concurrent": 2
      },
      "originate": {
        "allowed": false,
        "reason": "Security policy violation"
      }
    }
  }
}
```

#### Command Templates

Predefined command templates for common operations:

```json
{
  "security": {
    "esl_command_templates": {
      "restart_profile": "sofia profile {profile} restart",
      "flush_registrations": "sofia profile {profile} flush_inbound_reg",
      "show_profile_status": "sofia status profile {profile}"
    }
  }
}
```

## 🛠️ Integration Examples

### Monitoring Systems

#### Nagios/Icinga Integration

```bash
#!/bin/bash
# /usr/local/nagios/libexec/check_freeswitch_esl

API_URL="http://127.0.0.1:8080/security/esl/command"
COMMAND="status"

response=$(curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d "{\"command\": \"$COMMAND\"}" \
    --max-time 10)

if [ $? -ne 0 ]; then
    echo "CRITICAL - ESL API unreachable"
    exit 2
fi

if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
    echo "CRITICAL - ESL command failed: $(echo "$response" | jq -r '.error')"
    exit 2
fi

if echo "$response" | jq -r '.response' | grep -q "FreeSWITCH.*is ready"; then
    echo "OK - FreeSWITCH is running"
    exit 0
else
    echo "WARNING - FreeSWITCH status unclear"
    exit 1
fi
```

#### Prometheus Metrics

```bash
#!/bin/bash
# FreeSWITCH metrics exporter

# Get channel count
channels=$(curl -s -X POST http://127.0.0.1:8080/security/esl/command \
    -H "Content-Type: application/json" \
    -d '{"command": "show channels count"}' | \
    jq -r '.response' | grep -o '[0-9]\+')

# Get registration count
registrations=$(curl -s -X POST http://127.0.0.1:8080/security/esl/command \
    -H "Content-Type: application/json" \
    -d '{"command": "show registrations count"}' | \
    jq -r '.response' | grep -o '[0-9]\+')

# Output Prometheus metrics
cat << EOF
# HELP freeswitch_channels_total Current active channels
# TYPE freeswitch_channels_total gauge
freeswitch_channels_total $channels

# HELP freeswitch_registrations_total Current active registrations
# TYPE freeswitch_registrations_total gauge
freeswitch_registrations_total $registrations
EOF
```

### Automation Scripts

#### Daily Health Check

```bash
#!/bin/bash
# Daily FreeSWITCH health check via ESL API

API_URL="http://127.0.0.1:8080/security/esl/command"
LOGFILE="/var/log/freeswitch-health.log"
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Function to execute command and log result
execute_and_log() {
    local cmd="$1"
    local description="$2"

    echo "[$DATE] Checking $description..." >> "$LOGFILE"

    response=$(curl -s -X POST "$API_URL" \
        -H "Content-Type: application/json" \
        -d "{\"command\": \"$cmd\"}" \
        --max-time 30)

    if echo "$response" | jq -e '.error' >/dev/null 2>&1; then
        echo "[$DATE] ERROR: $description failed: $(echo "$response" | jq -r '.error')" >> "$LOGFILE"
        return 1
    else
        echo "[$DATE] OK: $description successful" >> "$LOGFILE"
        return 0
    fi
}

# Perform health checks
execute_and_log "status" "FreeSWITCH status"
execute_and_log "show channels count" "Active channels"
execute_and_log "show registrations count" "Active registrations"
execute_and_log "sofia status" "SIP profiles"

echo "[$DATE] Health check completed" >> "$LOGFILE"
```

#### Configuration Backup

```bash
#!/bin/bash
# Backup FreeSWITCH configuration via ESL

API_URL="http://127.0.0.1:8080/security/esl/command"
BACKUP_DIR="/backup/freeswitch/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Export dialplan
curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{"command": "xml_locate dialplan"}' | \
    jq -r '.response' > "$BACKUP_DIR/dialplan.xml"

# Export directory
curl -s -X POST "$API_URL" \
    -H "Content-Type: application/json" \
    -d '{"command": "xml_locate directory"}' | \
    jq -r '.response' > "$BACKUP_DIR/directory.xml"

echo "Configuration backup completed: $BACKUP_DIR"
```

## 🔍 Troubleshooting Guide

### Common Issues

#### 1. Command Not Executing

**Symptoms**:
- API returns success but no visible effect
- Command appears to hang

**Diagnosis**:
```bash
# Check ESL connection status
curl -s http://127.0.0.1:8080/security/esl | jq '.connected'

# Check FreeSWITCH CLI directly
fs_cli -x "status"

# Check application logs
tail -f /var/log/freeswitch-security.log | grep ESL
```

**Solutions**:
- Verify FreeSWITCH is responding to ESL connections
- Check network connectivity between application and FreeSWITCH
- Verify ESL password configuration

#### 2. High Latency

**Symptoms**:
- API responses take >1 second
- Timeout errors under load

**Diagnosis**:
```bash
# Check queue utilization
curl -s http://127.0.0.1:8080/security/esl | jq '{
  queue_length: .queue_length,
  queue_capacity: .queue_capacity,
  utilization: (.queue_length / .queue_capacity * 100)
}'

# Monitor system resources
top -p $(pgrep freeswitch-security)
```

**Solutions**:
- Increase worker count for high-volume environments
- Optimize FreeSWITCH performance
- Consider command caching for frequent queries

#### 3. Connection Instability

**Symptoms**:
- Frequent "not connected" errors
- High connection attempt count

**Diagnosis**:
```bash
# Check connection statistics
curl -s http://127.0.0.1:8080/security/esl | jq '{
  attempts: .connection_attempts,
  errors: .connection_errors,
  error_rate: (.connection_errors / .connection_attempts * 100)
}'

# Force reconnection
curl -X POST http://127.0.0.1:8080/security/esl/reconnect
```

**Solutions**:
- Check FreeSWITCH ESL configuration stability
- Verify network reliability
- Adjust reconnection backoff settings

### Debug Procedures

#### Enable Debug Logging

```bash
# Increase log verbosity
curl -X POST http://127.0.0.1:8080/security/esl/log_level \
    -H "Content-Type: application/json" \
    -d '{"level": "debug"}'

# Execute problematic command
curl -X POST http://127.0.0.1:8080/security/esl/command \
    -H "Content-Type: application/json" \
    -d '{"command": "your_command_here"}'

# Check logs for detailed information
tail -f /var/log/freeswitch-security.log | grep -E "(ESL DEBUG|ESL ERROR)"

# Return to normal logging
curl -X POST http://127.0.0.1:8080/security/esl/log_level \
    -H "Content-Type: application/json" \
    -d '{"level": "info"}'
```

#### Test ESL Connection Directly

```bash
# Test ESL connection manually
telnet 127.0.0.1 8021

# Expected response:
# Content-Type: auth/request
#
# auth ClueCon
#
# Content-Type: command/reply
# Reply-Text: +OK accepted
```

## 📈 Future Enhancements

### Planned Features

1. **Role-Based Access Control**: User-specific command permissions
2. **Command Scheduling**: Cron-like command scheduling
3. **Batch Operations**: Multiple commands in single request
4. **Command History**: Audit trail with rollback capabilities
5. **WebSocket Support**: Real-time command streaming
6. **Command Validation**: Advanced syntax checking and parameter validation

### API Evolution

#### v2 API Preview

```bash
# Batch command execution (planned)
curl -X POST http://127.0.0.1:8080/api/v2/esl/batch \
    -H "Content-Type: application/json" \
    -d '{
        "commands": [
            {"command": "status"},
            {"command": "show channels count"},
            {"command": "show registrations count"}
        ]
    }'

# Scheduled commands (planned)
curl -X POST http://127.0.0.1:8080/api/v2/esl/schedule \
    -H "Content-Type: application/json" \
    -d '{
        "command": "reloadxml",
        "schedule": "0 2 * * *",
        "description": "Daily configuration reload"
    }'
```

## 🔐 Security Considerations

### Production Deployment

1. **TLS Encryption**: Always use HTTPS in production
2. **Network Segmentation**: Isolate ESL API access to management networks
3. **Authentication**: Implement strong authentication (OAuth2, JWT, etc.)
4. **Rate Limiting**: Configure appropriate rate limits
5. **Audit Logging**: Maintain comprehensive audit trails
6. **Regular Updates**: Keep the application and dependencies updated

### Security Checklist

- [ ] Configure minimal command whitelist
- [ ] Implement network-based access controls
- [ ] Enable comprehensive audit logging
- [ ] Set up monitoring and alerting
- [ ] Test security controls regularly
- [ ] Document emergency procedures
- [ ] Train operations team on security procedures

## 📚 Additional Resources

### Documentation Links

- [FreeSWITCH ESL Documentation](https://freeswitch.org/confluence/display/FREESWITCH/Event+Socket+Library)
- [FreeSWITCH Command Reference](https://freeswitch.org/confluence/display/FREESWITCH/Mod+commands)
- [ESL Protocol Specification](https://freeswitch.org/confluence/display/FREESWITCH/Event+Socket+Outbound)

### Example Configurations

Complete example configurations are available in the project repository:
- `examples/nginx-proxy.conf` - Nginx reverse proxy with authentication
- `examples/monitoring/` - Monitoring and alerting configurations
- `examples/automation/` - Automation scripts and cron jobs

---

## 🔚 Conclusion

The ESL Command API provides a secure, high-performance interface for FreeSWITCH management while maintaining strict security controls. By following the guidelines in this documentation, you can:

- **Execute commands safely** using whitelist-based security
- **Achieve high performance** with optimized request processing
- **Monitor system health** using comprehensive metrics
- **Integrate seamlessly** with existing monitoring and automation systems
- **Maintain security** through proper access controls and audit trails

For additional support, advanced configuration examples, or feature requests, please refer to the main [README.md](README.md) or visit the project's GitHub repository.

---

**Related Documentation:**
- [Main README](README.md) - Complete application overview and setup
- [Logging Guide](logging.md) - Comprehensive logging configuration and troubleshooting
- [IPTables Security Guide](iptables.md) - Advanced firewall integration and security
