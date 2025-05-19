# FreeSWITCH Security

This application provides security components for FreeSWITCH with integrated caching. It monitors FreeSWITCH events through the Event Socket Layer (ESL) to detect and prevent security threats including registration flooding, call flooding, and other malicious activities.

## Project Structure

```
├── main.go           # Entry point for the application
├── config.go         # Configuration loading and management
├── cache.go          # Cache management (using BigCache)
├── security.go       # Core security functionality
├── esl.go            # FreeSWITCH Event Socket Layer integration
├── rate.go           # Rate limiting implementation
├── routes.go         # API route definitions
├── logging.go        # Centralized logging system
└── config.json       # Application configuration file
```

## Features

### Security Management
- **IP Whitelisting/Blacklisting**: Track and manage known-good and malicious IPs
- **Auto-blocking**: Automatically block IPs with suspicious behavior using iptables
- **Failed Registration Tracking**: Monitor and respond to failed authentication attempts
- **Wrong Call State Detection**: Identify potential toll fraud or system abuse
- **Untrusted Network Patterns**: Block specific domains or networks known for abuse

### ESL Integration
- **Real-time Event Monitoring**: Process FreeSWITCH events as they occur
- **Automatic Reconnection**: Maintain connection to FreeSWITCH with exponential backoff
- **Comprehensive Event Handling**: Support for registration, call creation, and other events
- **Configurable Logging**: Multiple verbosity levels for troubleshooting

### Rate Limiting
- **Call Rate Limiting**: Restrict the number of calls allowed from a single IP
- **Registration Rate Limiting**: Prevent registration flooding attacks
- **Automatic Cleanup**: Remove expired rate counters to conserve memory
- **Whitelist Bypass**: Allow trusted IPs to bypass rate limits

### High-Performance Caching
- **In-memory Cache**: Fast lookups of security information
- **Configurable TTLs**: Set expiration times for different cache entries
- **Automatic Eviction**: Remove expired items to prevent memory leaks
- **Thread-safe Operations**: Concurrent access support with proper locking

## Installation

### Prerequisites

- Go 1.18 or higher
- FreeSWITCH with Event Socket Layer (ESL) enabled
- iptables (for automatic IP blocking)

### Building from Source

1. Clone the repository:
   ```
   git clone https://github.com/voicetel/freeswitch-security.git
   cd freeswitch-security
   ```

2. Install dependencies:
   ```
   go mod init github.com/voicetel/freeswitch-security
   go mod tidy
   ```

3. Build the application:
   ```
   go build -o freeswitch-security .
   ```

4. Configure the application:
   ```
   cp config.json.example config.json
   # Edit config.json with your settings
   ```

5. Run the application:
   ```
   ./freeswitch-security
   ```

## Configuration

The application uses a JSON configuration file with the following main sections:

### Server Configuration
```json
"server": {
  "host": "127.0.0.1",
  "port": "8080",
  "log_requests": true,
  "log_responses": false
}
```

### FreeSWITCH Configuration
```json
"freeswitch": {
  "default_domain": "example.com"
}
```

### Cache Configuration
```json
"cache": {
  "enabled": true,
  "security_ttl": "5m",
  "cleanup_interval": "5m",
  "max_entries_in_window": 10000,
  "max_entry_size": 500,
  "shard_count": 1024
}
```

### Security Configuration
```json
"security": {
  "enabled": true,
  "esl_host": "127.0.0.1",
  "esl_port": "8021",
  "esl_password": "ClueCon",
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
  "untrusted_networks": ["1.1.1.1", "0.0.0.0"],
  "iptables_chain": "FREESWITCH",
  "auto_whitelist_on_success": true,
  "esl_log_level": "debug",
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
```

## API Endpoints

### Health and Status
- `GET /health` - Health check endpoint
- `GET /security/status` - Overall security status
- `GET /security/stats` - Detailed security statistics
- `GET /cache/stats` - Cache statistics

### Whitelist Management
- `GET /security/whitelist` - List all whitelisted IPs
- `POST /security/whitelist` - Add an IP to the whitelist
- `DELETE /security/whitelist/:ip` - Remove an IP from the whitelist
- `GET /security/whitelist/:ip` - Check if an IP is whitelisted

### Blacklist Management
- `GET /security/blacklist` - List all blacklisted IPs
- `POST /security/blacklist` - Add an IP to the blacklist
- `DELETE /security/blacklist/:ip` - Remove an IP from the blacklist
- `GET /security/blacklist/:ip` - Check if an IP is blacklisted

### Event and Tracking
- `GET /security/failed` - List all tracked failed registration attempts
- `GET /security/wrong-call-states` - List all tracked wrong call state events
- `GET /security/iptables` - List current iptables rules

### ESL Management
- `GET /security/esl` - ESL connection status
- `POST /security/esl/log_level` - Set ESL log level
- `POST /security/esl/reconnect` - Force ESL reconnection

### Rate Limiting
- `GET /security/rate-limit` - Rate limit configuration
- `GET /security/rate-limit/calls` - Current call rate tracking
- `GET /security/rate-limit/registrations` - Current registration rate tracking

### Untrusted Networks
- `GET /security/untrusted-networks` - List untrusted network patterns
- `POST /security/untrusted-networks` - Add an untrusted pattern
- `DELETE /security/untrusted-networks/:pattern` - Remove an untrusted pattern
- `GET /security/untrusted-networks/test/:domain` - Test if domain matches untrusted pattern

## Cache Management
- `POST /cache/security/clear` - Clear security cache

## Environment Variables

The application supports configuration via environment variables, which override the values in config.json:

| Environment Variable | Description |
|----------------------|-------------|
| SERVER_HOST | Server host address |
| SERVER_PORT | Server port |
| SERVER_LOG_REQUESTS | Log API requests |
| SERVER_LOG_RESPONSES | Log API responses |
| FS_DEFAULT_DOMAIN | Default FreeSWITCH domain |
| CACHE_ENABLED | Enable caching |
| CACHE_SECURITY_TTL | Security cache TTL |
| CACHE_CLEANUP_INTERVAL | Cache cleanup interval |
| SECURITY_ENABLED | Enable security features |
| SECURITY_ESL_HOST | ESL host address |
| SECURITY_ESL_PORT | ESL port |
| SECURITY_ESL_PASSWORD | ESL password |
| SECURITY_MAX_FAILED_ATTEMPTS | Max failed attempts before blocking |
| SECURITY_FAILED_WINDOW | Failed attempts window |
| SECURITY_AUTO_BLOCK | Enable auto-blocking |
| SECURITY_BLOCK_DURATION | Block duration |
| SECURITY_ESL_LOG_LEVEL | ESL log level |

## FreeSWITCH ESL Configuration

To use this application with FreeSWITCH, ensure the Event Socket module is enabled and configured to accept connections:

```xml
<!-- In modules.conf.xml -->
<load module="mod_event_socket"/>

<!-- In event_socket.conf.xml -->
<configuration name="event_socket.conf" description="Socket Client">
  <settings>
    <param name="nat-map" value="false"/>
    <param name="listen-ip" value="127.0.0.1"/>
    <param name="listen-port" value="8021"/>
    <param name="password" value="ClueCon"/>
  </settings>
</configuration>
```

## Integrations

### IPTables Integration

The application uses iptables for automatic IP blocking. It creates a dedicated chain (default: `FREESWITCH`) and adds rules to block malicious IPs. Ensure your system has iptables installed and the application has sufficient permissions to manage iptables rules. Additional instructions can be found [here](iptables.md).

## 🙌 Contributors

We welcome, acknowlege, and appreciate contributors. Thanks to these awesome people for making this project possible:

[Michael Mavroudis](https://github.com/mavroudis)

## 💖 Sponsors

We gratefully acknowledge the support of our amazing sponsors:

| Sponsor | Contribution |
|---------|--------------|
| [VoiceTel Communications](http://www.voicetel.com) | Everything :) |

## License

This project is licensed under the MIT License - see the LICENSE file for details.
