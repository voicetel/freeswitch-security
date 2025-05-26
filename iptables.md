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
         │ FREESWITCH  │ → Blocked IPs are dropped here (silently)
         └─────────────┘
```

## DROP vs REJECT: Security Considerations

The FreeSWITCH Security application uses the `DROP` action instead of `REJECT` for enhanced security:

### Why DROP is Preferred

- **Stealth Operation**: `DROP` silently discards packets without sending any response, making it harder for attackers to detect blocking
- **Resource Conservation**: No CPU cycles wasted generating ICMP error messages for malicious traffic
- **Reconnaissance Prevention**: Attackers cannot use responses to gather information about your firewall configuration
- **Better Security Posture**: Silent dropping is a security best practice for handling malicious traffic

### DROP Behavior
- Packets from blocked IPs are silently discarded
- No response is sent back to the attacker
- Connection attempts timeout rather than immediately failing
- Makes automated attacks and reconnaissance more difficult

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
   # Block a test IP (packets will be silently dropped)
   sudo iptables -A FREESWITCH -s 192.0.2.1 -j DROP

   # Verify it was added
   sudo iptables -L FREESWITCH

   # Remove the test rule
   sudo iptables -D FREESWITCH -s 192.0.2.1 -j DROP
   ```

3. **Test the API**:
   ```bash
   # Add IP to blacklist via API
   curl -X POST http://127.0.0.1:8080/security/blacklist \
     -H "Content-Type: application/json" \
     -d '{"ip":"192.0.2.1", "reason":"Testing IPTables integration", "permanent":false}'

   # Verify via IPTables (should show DROP rule)
   sudo iptables -L FREESWITCH

   # Remove via API
   curl -X DELETE http://127.0.0.1:8080/security/blacklist/192.0.2.1
   ```

## Understanding DROP Behavior in Practice

### What Happens When an IP is Blocked

1. **Immediate Effect**: Packets from the blocked IP are immediately discarded at the kernel level
2. **No Response**: The blocked IP receives no indication that packets were dropped
3. **Connection Timeouts**: Applications on the blocked IP will experience connection timeouts
4. **Stealth Mode**: The blocking is invisible to network scanners and automated tools

### Example Rules Created by the Application

When the application blocks an IP, it creates rules like:

```bash
# Rule added by FreeSWITCH Security application
-A FREESWITCH -s 203.0.113.100 -j DROP
```

### Monitoring Blocked Traffic

You can monitor dropped packets using iptables counters:

```bash
# View rule statistics (shows packet and byte counts)
sudo iptables -L FREESWITCH -v -n

# Reset counters if needed
sudo iptables -Z FREESWITCH
```

## Troubleshooting

### Common Issues

1. **Rules Not Working**: Ensure the FREESWITCH chain is properly linked to INPUT
2. **Permission Denied**: The application needs sufficient privileges to modify iptables
3. **Chain Not Found**: Verify the chain name matches your configuration

### Debugging Commands

```bash
# List all rules with line numbers
sudo iptables -L FREESWITCH --line-numbers

# Show detailed rule information
sudo iptables -S FREESWITCH

# Test if an IP is blocked
sudo iptables -C FREESWITCH -s 192.0.2.1 -j DROP
```

## Security Best Practices

1. **Regular Monitoring**: Check blocked IPs regularly to ensure legitimate traffic isn't affected
2. **Whitelist Management**: Maintain proper whitelists for trusted networks
3. **Log Analysis**: Monitor application logs for blocking patterns
4. **Backup Rules**: Save iptables configuration before making changes
5. **Testing**: Always test blocking rules in a non-production environment first

## Advanced Configuration

### Custom Chain Names

You can use custom chain names by modifying the configuration:

```json
"security": {
  "iptables_chain": "CUSTOM_SECURITY_CHAIN"
}
```

### Integration with Existing Firewalls

If you have existing iptables rules, ensure the FREESWITCH chain is positioned correctly:

```bash
# Insert the jump to FREESWITCH chain at a specific position
sudo iptables -I INPUT 5 -j FREESWITCH
```

## Conclusion

Properly configured IPTables integration with DROP actions enhances the FreeSWITCH Security application by providing a powerful, stealthy layer of protection against malicious traffic. The use of DROP instead of REJECT provides better security through obscurity while conserving system resources. Regular monitoring and maintenance of your IPTables rules will ensure optimal security and performance.
