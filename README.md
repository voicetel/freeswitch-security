# FreeSWITCH Security

[![CI](https://github.com/voicetel/freeswitch-security/actions/workflows/ci.yml/badge.svg)](https://github.com/voicetel/freeswitch-security/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/voicetel/freeswitch-security)](https://goreportcard.com/report/github.com/voicetel/freeswitch-security)
[![Go Reference](https://pkg.go.dev/badge/github.com/voicetel/freeswitch-security.svg)](https://pkg.go.dev/github.com/voicetel/freeswitch-security)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A high-performance security application for FreeSWITCH that provides comprehensive protection against VoIP attacks through real-time event monitoring, intelligent rate limiting, and dynamic threat response. Built with Go for maximum performance and scalability.

## 🚀 Features

### Advanced Security Management
- **Intelligent IP Whitelisting/Blacklisting**: Dynamic management with TTL support and automatic cleanup
- **Auto-blocking with ipset**: O(1) kernel hash set behind one iptables DROP rule, with in-kernel ban expiry
- **Failed Registration Tracking**: Multi-layered detection of authentication attacks
- **Wrong Call State Detection**: Identify toll fraud and system abuse attempts
- **Untrusted Network Filtering**: Pattern-based blocking of known malicious domains
- **Bounded Work Queues**: Generously sized fixed buffers with non-blocking enqueue and drop accounting

### High-Performance Architecture
- **Channel-Based Processing**: Asynchronous event handling with worker pools
- **Memory Pool Management**: Efficient object reuse to minimize garbage collection
- **Sharded Rate Counters**: Per-IP counters across 16 lock shards eliminate contention under multi-source load
- **Batch Operations**: Optimized batch processing for IPTables and cache operations
- **Thread-Safe Operations**: Concurrent access support with fine-grained locking

### Real-Time ESL Integration
- **Multi-Worker Event Processing**: Configurable worker pools for high-throughput event handling
- **Automatic Reconnection**: Exponential backoff with connection resilience
- **Memory-Optimized Event Handling**: Object pooling for zero-allocation event processing
- **Lock-Free Hot Paths**: Atomic statistics and in-place whitelist refresh keep workers from blocking
- **Comprehensive Event Support**: Registration, call creation, and security events
- **Secure Command Interface**: Whitelist-based command execution with audit logging

### Intelligent Rate Limiting
- **Adaptive Call Rate Limiting**: Per-IP call frequency controls with automatic adjustment
- **Registration Flood Protection**: Advanced detection and mitigation of registration attacks
- **Whitelist Bypass**: Trusted IP exemptions from rate limiting
- **Automatic Cleanup**: Memory-efficient expired counter removal
- **Real-time Monitoring**: Live rate tracking with detailed statistics

### Enterprise-Grade Caching
- **In-Memory Response Cache**: lightweight TTL cache for HTTP responses (stdlib, no external dependency)
- **Channel-Based Write Operations**: Batched writes for optimal performance
- **Configurable TTLs**: Granular expiration control for different data types
- **Automatic Eviction**: Intelligent cleanup to prevent memory bloat
- **Statistics and Monitoring**: Comprehensive cache performance metrics

## 📁 Project Structure

```
├── main.go              # Application entry point and graceful shutdown
├── config.go            # Configuration management with environment variable support
├── cache.go             # In-memory TTL response cache (stdlib)
├── security.go          # Core security engine: lists, batching, iptables
├── esl.go               # Event Socket Layer integration with worker pools
├── rate.go              # Sharded per-IP rate limiting with automatic cleanup
├── routes.go            # REST API with request processing pipeline
├── logging.go           # Centralized logging system with configurable levels
├── pprof.go             # Optional loopback-only pprof diagnostics server
├── Makefile             # Build, test, lint, coverage, and benchmark targets
├── *_test.go            # Hermetic test suite (no FreeSWITCH or iptables needed)
├── config.json.example  # Annotated configuration example
├── README.md            # This comprehensive documentation
├── logging.md           # Detailed logging system documentation
├── iptables.md          # IPTables integration and security guide
└── esl.md               # ESL Command API documentation
```

## ⚡ Performance Characteristics

Benchmarked with the in-repo suite (`make bench`, statistically validated
with `benchstat`); figures from a 12th-gen mobile CPU:

- **Event Pipeline**: ~350 ns/event end-to-end (queue → worker → rate +
  security checks) at 4 workers — millions of events/second of headroom
- **Registration Hot Path**: ~230 ns with auto-whitelist enabled, zero
  allocations (in-place whitelist refresh, atomic statistics)
- **Rate Checks**: ~45–95 ns serial; counters sharded across 16 locks for
  contention-free multi-source traffic
- **Memory Efficiency**: pooled event objects, 3 allocs/event in steady state
- **IPTables Integration**: batch operations reduce fork/exec overhead
- **Worker Pool**: sized from CPU count (2–8 workers)

## 🛠 Installation

### Prerequisites

- **Go 1.18+** - Modern Go version with generics support
- **FreeSWITCH** with Event Socket Layer (ESL) enabled
- **IPTables + ipset** - For automatic IP blocking (Linux systems; `apt install ipset` or `dnf install ipset`)
- **Root/Sudo Access** - Required for IPTables rule management

### Quick Start

1. **Clone and Build**:
   ```bash
   git clone https://github.com/voicetel/freeswitch-security.git
   cd freeswitch-security
   make build    # static, stripped binary in bin/
   ```

2. **Configure Application**:
   ```bash
   # The application creates a default config.json on first run
   ./bin/freeswitch-security
   # Edit config.json with your settings, then restart
   ```

3. **Set Permissions** (for IPTables integration):
   ```bash
   # Option 1: Run as root
   sudo ./bin/freeswitch-security

   # Option 2: Grant CAP_NET_ADMIN capability
   sudo setcap cap_net_admin=+ep ./bin/freeswitch-security
   ./bin/freeswitch-security
   ```

## ⚙️ Configuration

### Complete Configuration Example

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": "8080",
    "log_requests": true,
    "log_responses": false,
    "pprof_enabled": false,
    "pprof_addr": "127.0.0.1:6060"
  },
  "freeswitch": {
    "default_domain": "your-domain.com"
  },
  "cache": {
    "enabled": true,
    "security_ttl": "5m",
    "cleanup_interval": "5m"
  },
  "security": {
    "enabled": true,
    "esl_host": "127.0.0.1",
    "esl_port": "8021",
    "esl_password": "ClueCon",
    "esl_allowed_commands": [
      "status",
      "uptime",
      "version",
      "show channels",
      "show registrations"
    ],
    "max_failed_attempts": 5,
    "failed_attempts_window": "10m",
    "auto_block_enabled": true,
    "block_duration": "1h",
    "whitelist_enabled": true,
    "whitelist_ttl": "24h",
    "trusted_networks": [
      "127.0.0.1/8",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "untrusted_networks": [
      "suspicious-provider.com",
      "known-bad-domain.net"
    ],
    "iptables_chain": "FREESWITCH",
    "auto_whitelist_on_success": true,
    "esl_log_level": "info",
    "reconnect_backoff": "5s",
    "max_wrong_call_states": 5,
    "wrong_call_state_window": "10m",
    "rate_limit": {
      "enabled": true,
      "call_rate_limit": 20,
      "call_rate_interval": "1m",
      "registration_limit": 10,
      "registration_window": "1m",
      "auto_block_on_exceed": true,
      "block_duration": "15m",
      "whitelist_bypass": true,
      "cleanup_interval": "5m"
    }
  }
}
```

### Environment Variables

Override any configuration value using environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `SERVER_HOST` | Server bind address | `0.0.0.0` |
| `SERVER_PORT` | Server port | `8080` |
| `SECURITY_ESL_HOST` | FreeSWITCH ESL host | `192.168.1.100` |
| `SECURITY_ESL_PASSWORD` | ESL password | `mySecurePassword` |
| `SECURITY_ESL_ALLOWED_COMMANDS` | Allowed ESL commands (JSON array) | `["status","uptime"]` |
| `SECURITY_MAX_FAILED_ATTEMPTS` | Failed attempts threshold | `10` |
| `SECURITY_AUTO_BLOCK` | Enable auto-blocking | `true` |
| `SECURITY_TRUSTED_NETWORKS` | Trusted networks (JSON array) | `["10.0.0.0/8"]` |
| `SECURITY_IPTABLES_CHAIN` | Chain holding the ipset match-set DROP rule | `INPUT` |
| `SECURITY_IPSET_NAME` | Name of the managed ipset | `freeswitch-security` |
| `SECURITY_DRY_RUN` | Log firewall actions without executing them | `true` |
| `SERVER_PPROF_ENABLED` | Enable pprof diagnostics server | `true` |
| `SERVER_PPROF_ADDR` | pprof bind address (keep loopback) | `127.0.0.1:6060` |

## 📈 Profiling & Performance

Setting `server.pprof_enabled` exposes Go's `net/http/pprof` diagnostics on a
**dedicated, loopback-only** listener (`server.pprof_addr`, default
`127.0.0.1:6060`) — never on the public API port:

```bash
go tool pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=30
```

The benchmark suite includes `BenchmarkEventPipeline_RealisticMix`, a
production-shaped end-to-end pipeline benchmark (~350 ns/event at 4 workers),
and `BenchmarkRegistrationAutoWhitelist`, a canary guarding the registration
hot path (~230 ns; it regresses to ~100 ms if a blocking whitelist call is
ever reintroduced). Validate changes with `benchstat` over `-count=10` runs.

## 🧪 Development & Testing

```bash
make build      # static, stripped binary in bin/
make test       # race-enabled test suite
make coverage   # coverage report (currently ~98% of statements)
make quality    # format check + vet + lint + race tests with coverage
make bench      # benchmark suite (-count=10, benchstat-ready)
make lint       # golangci-lint with the repo configuration
```

The test suite is fully **hermetic**: an in-process FreeSWITCH ESL server
and a faked iptables layer mean tests never touch a real FreeSWITCH, never
modify host firewall state, and need no special privileges. CI runs the
same chain on every push and pull request.

## 🔧 FreeSWITCH Configuration

### Enable Event Socket Module

```xml
<!-- In modules.conf.xml -->
<load module="mod_event_socket"/>
```

### Configure Event Socket

```xml
<!-- In event_socket.conf.xml -->
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="127.0.0.1"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="ClueCon"/>
    <param name="apply-inbound-acl" value="lan"/>
  </settings>
</configuration>
```

## 🌐 REST API Reference

### System Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/system/stats` | System resource usage |
| `GET` | `/security/status` | Security system overview |
| `GET` | `/security/stats` | Detailed security statistics |

### Security Management

#### Whitelist Operations
```bash
# List whitelisted IPs
GET /security/whitelist

# Add IP to whitelist
POST /security/whitelist
{
  "ip": "192.168.1.100",
  "user_id": "1001",
  "domain": "example.com",
  "permanent": false
}

# Batch whitelist operations
POST /security/whitelist/batch
[
  {"ip": "192.168.1.100", "user_id": "1001"},
  {"ip": "192.168.1.101", "user_id": "1002"}
]

# Remove from whitelist
DELETE /security/whitelist/192.168.1.100

# Check whitelist status
GET /security/whitelist/192.168.1.100
```

#### Blacklist Operations
```bash
# List blacklisted IPs
GET /security/blacklist

# Add IP to blacklist
POST /security/blacklist
{
  "ip": "203.0.113.100",
  "reason": "Excessive failed registrations",
  "permanent": false
}

# Batch blacklist operations
POST /security/blacklist/batch
[
  {"ip": "203.0.113.100", "reason": "Brute force"},
  {"ip": "203.0.113.101", "reason": "Toll fraud"}
]

# Remove from blacklist
DELETE /security/blacklist/203.0.113.100
```

### ESL Management

```bash
# Get ESL connection status
GET /security/esl

# Send command to FreeSWITCH
POST /security/esl/command
{
  "command": "status"
}

# Change log level
POST /security/esl/log_level
{
  "level": "debug"
}

# Force reconnection
POST /security/esl/reconnect
```

### Rate Limiting

```bash
# Get rate limiting configuration
GET /security/rate-limit

# View current call rates
GET /security/rate-limit/calls

# View registration rates
GET /security/rate-limit/registrations
```

### Monitoring and Analytics

```bash
# View failed registration attempts
GET /security/failed

# View wrong call state events
GET /security/wrong-call-states

# View IPTables rules
GET /security/iptables

# Cache statistics
GET /cache/stats

# Clear security cache
POST /cache/security/clear
```

## 🛡️ Security Best Practices

### IPTables Integration

The application uses **DROP** instead of **REJECT** for superior security:

- **Stealth Mode**: Silently discards malicious packets
- **Resource Efficiency**: No CPU waste on ICMP responses
- **Reconnaissance Protection**: Attackers can't fingerprint your firewall
- **Timeout-Based Blocking**: Connections timeout rather than fail immediately

### Network Security

1. **Trusted Networks**: Configure RFC 1918 networks appropriately
2. **Reverse Proxy**: Use nginx/HAProxy with TLS for API access
3. **Firewall Rules**: Restrict API access to management networks
4. **Regular Updates**: Keep the application and dependencies updated

### Operational Security

1. **Log Monitoring**: Implement log analysis and alerting
2. **Backup Configuration**: Regular config and whitelist backups
3. **Access Control**: Use strong authentication for API access
4. **Capacity Planning**: Monitor queue sizes and performance metrics

## 📊 Performance Monitoring

### Key Metrics to Monitor

1. **Event Processing Rate**: Events/second throughput
2. **Queue Depths**: Channel utilization and backlog
3. **Memory Usage**: Pool efficiency and GC pressure
4. **Cache Hit Rates**: Lookup performance and efficiency
5. **Response Times**: API endpoint latency
6. **Error Rates**: Failed operations and connectivity issues

### Performance Tuning

```bash
# Check system performance
GET /system/stats

# Cache performance metrics
GET /cache/stats

# ESL connection health
GET /security/esl
```

## 🔍 Troubleshooting

### Common Issues

#### ESL Connection Problems
```bash
# Check connection status
curl http://localhost:8080/security/esl

# Force reconnection
curl -X POST http://localhost:8080/security/esl/reconnect

# Increase log verbosity
curl -X POST http://localhost:8080/security/esl/log_level \
  -H "Content-Type: application/json" \
  -d '{"level":"debug"}'
```

#### High Memory Usage
- Monitor channel statistics for queue buildup
- Check cache hit rates and cleanup intervals
- Verify object pool efficiency in logs

#### Performance Degradation
- Scale worker count based on CPU cores
- Adjust channel buffer sizes
- Optimize cache configuration

### Debug Commands

```bash
# Enable debug logging
export SECURITY_ESL_LOG_LEVEL=debug

# Monitor resource usage
watch -n 1 'curl -s http://localhost:8080/system/stats | jq'
```

## 🚀 Advanced Features

### Bounded Queue Design

Internal queues use generously sized fixed buffers with non-blocking
enqueue. Overflow drops are counted and reported through the stats
endpoints rather than blocking event readers — predictable behavior under
attack-level load, with no resize races.

### Memory Pool Optimization

Event processing uses object pools for low-allocation performance:

- **Pre-allocated Objects**: Reusable event structures via `sync.Pool`
- **Steady State**: 3 allocations per event through the full pipeline
- **Predictable Memory**: fixed-capacity queues bound worst-case usage

### Batch Processing

Optimized batch operations for maximum efficiency:

- **IPTables Commands**: Grouped rule modifications
- **Cache Operations**: Batched writes and deletes
- **Database Updates**: Consolidated security event processing
- **Network Efficiency**: Reduced system call overhead

## 🙌 Contributors

We welcome contributions! Thanks to these awesome people:

- [Michael Mavroudis](https://github.com/mavroudis) - Lead Developer & Architect

## 💖 Sponsors

Proudly supported by:

| Sponsor | Contribution |
|---------|--------------|
| [VoiceTel Communications](http://www.voicetel.com) | Primary development and testing infrastructure |

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🔗 Additional Documentation

- [Detailed Logging Guide](logging.md) - Comprehensive logging configuration and troubleshooting
- [IPTables Security Guide](iptables.md) - Advanced firewall integration and best practices
- [ESL Command API](esl.md) - FreeSWITCH command interface documentation

For support, please visit our [GitHub Issues](https://github.com/voicetel/freeswitch-security/issues) page.
