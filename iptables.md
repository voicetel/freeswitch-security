# Configuring IPTables for FreeSWITCH Security

This guide explains how to properly configure IPTables to work with the FreeSWITCH Security application. The security application uses IPTables to automatically block malicious IPs based on security events detected through FreeSWITCH's Event Socket Layer.

## Prerequisites

- Linux system with IPTables installed
- Root or sudo access
- Basic understanding of firewall and IPTables rules

## Understanding the IPTables Chain Structure

The FreeSWITCH Security application creates and uses a custom IPTables chain (default: `FREESWITCH`) to manage blocked IPs. This chain is inserted into the `INPUT` chain flow.

```
           ┌─────────┐
Internet → │  INPUT  │ → Further Processing
           └────┬────┘
                │
                ↓
         ┌─────────────┐
         │ FREESWITCH  │ → Blocked IPs are rejected here
         └─────────────┘
```

## Basic Configuration

These configuration samples are only for instructional purposes and totally incomplete. Don't attempt to use in production!

### 1. Set Up IPTables Default Policies

First, establish a secure baseline:

```bash
# Set default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback traffic
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

### 2. Allow Required FreeSWITCH Traffic

Open the necessary ports for FreeSWITCH:

```bash
# SIP UDP ports
sudo iptables -A INPUT -p udp --dport 5060 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5080 -j ACCEPT

# RTP media port range (adjust as needed)
sudo iptables -A INPUT -p udp --dport 16384:32768 -j ACCEPT
```

### 3. Create the FREESWITCH Chain

The security application will create this chain automatically, but you can also set it up manually:

```bash
# Create the FREESWITCH chain
sudo iptables -N FREESWITCH

# Add a jump from INPUT to FREESWITCH
sudo iptables -A INPUT -j FREESWITCH
```

## Application Configuration

In the security application's `config.json`, configure the IPTables settings:

```json
"security": {
  "auto_block_enabled": true,
  "iptables_chain": "FREESWITCH",
  "block_duration": "1h"
}
```

- `auto_block_enabled`: Set to `true` to enable automatic blocking using IPTables
- `iptables_chain`: Name of the IPTables chain to use (default: "FREESWITCH")
- `block_duration`: How long IPs remain blocked before being automatically removed

## Testing the Configuration

1. **Check if the chain exists**:
   ```bash
   sudo iptables -L FREESWITCH
   ```

2. **Manually add and remove test rules**:
   ```bash
   # Block a test IP
   sudo iptables -A FREESWITCH -s 192.0.2.1 -j REJECT --reject-with icmp-host-prohibited

   # Verify it was added
   sudo iptables -L FREESWITCH

   # Remove the test rule
   sudo iptables -D FREESWITCH -s 192.0.2.1 -j REJECT --reject-with icmp-host-prohibited
   ```

3. **Test the API**:
   ```bash
   # Add IP to blacklist via API
   curl -X POST http://127.0.0.1:8080/security/blacklist \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.0.2.1", "reason":"Testing IPTables integration", "permanent":false}'

   # Verify via IPTables
   sudo iptables -L FREESWITCH

   # Remove via API
   curl -X DELETE http://127.0.0.1:8080/security/blacklist/192.0.2.1
   ```

## Conclusion

Properly configured IPTables integration enhances the FreeSWITCH Security application by adding a powerful layer of protection against malicious traffic. Regular monitoring and maintenance of your IPTables rules will ensure optimal security and performance.
