# IPTables Integration Guide for FreeSWITCH Security

This comprehensive guide explains how to configure IPTables for optimal security integration with the FreeSWITCH Security application. The system uses advanced IPTables techniques including custom chains, batch operations, and stealth blocking to provide enterprise-grade VoIP protection.

## 🏗️ Architecture Overview

The FreeSWITCH Security application implements a sophisticated IPTables integration strategy:

- **Custom Chain Management**: Dedicated `FREESWITCH` chain for security rules
- **Batch Operations**: Efficient bulk rule modifications to reduce system overhead
- **Stealth Blocking**: Uses DROP instead of REJECT for security through obscurity
- **Automatic Cleanup**: Intelligent rule removal when blocks expire
- **Health Monitoring**: Continuous validation of firewall rule integrity

## 🛡️ Security Philosophy: DROP vs REJECT

### Why DROP is Superior for VoIP Security

The application uses the **DROP** target instead of **REJECT** for multiple security advantages:

#### Stealth Operation Benefits
- **Invisible Blocking**: Attackers receive no indication their traffic is blocked
- **Reconnaissance Prevention**: Port scanners can't detect firewall presence
- **Timeout-Based Deterrent**: Connection attempts timeout naturally
- **Reduced Attack Surface**: No ICMP responses to analyze or exploit

#### Resource Efficiency
- **Zero Response Overhead**: No CPU cycles wasted on ICMP generation
- **Bandwidth Conservation**: No outbound traffic for blocked connections
- **Kernel-Level Efficiency**: Packet dropping occurs at the earliest possible stage
- **Scalability**: Handles high-volume attacks without performance degradation

#### Operational Security
- **Log Noise Reduction**: Fewer false positives in network monitoring
- **Passive Defense**: Doesn't reveal defensive capabilities to attackers
- **Compliance Friendly**: Aligns with security best practices for critical infrastructure

### DROP Behavior in Practice

When an IP is blocked with DROP:

```bash
# Attacker perspective - connection hangs indefinitely
telnet your-server.com 5060
# [hangs until timeout - no immediate rejection]

# Legitimate user perspective - normal operation
# No performance impact or visible changes
```

## 🔧 Prerequisites and Requirements

### System Requirements

- **Linux Distribution**: Ubuntu 18.04+, CentOS 7+, Debian 9+, or compatible
- **IPTables Version**: 1.6.0 or newer
- **Kernel Support**: Netfilter framework with stateful connection tracking
- **Permissions**: Root access or CAP_NET_ADMIN capability
- **Memory**: Sufficient kernel memory for rule tables (typically 64MB+)

### Permission Configuration

#### Option 1: Run as Root (Simple)
```bash
sudo ./freeswitch-security
```

#### Option 2: Capability-Based (Recommended)
```bash
# Grant specific network administration capabilities
sudo setcap cap_net_admin=+ep ./freeswitch-security

# Verify capabilities
getcap ./freeswitch-security
# Output: ./freeswitch-security = cap_net_admin+ep

# Run as non-root user
./freeswitch-security
```

#### Option 3: Sudo Configuration (Production)
```bash
# Add to /etc/sudoers.d/freeswitch-security
freeswitch-user ALL=(ALL) NOPASSWD: /sbin/iptables
```

## 🏗️ Chain Architecture

### Understanding the Chain Structure

The application creates a dedicated chain that integrates into the standard IPTables flow:

```
Internet Traffic → INPUT Chain → FREESWITCH Chain → DROP (if blocked)
                      ↓                ↓
              Further Processing    Legitimate Traffic
```

### Chain Creation Process

The application automatically:

1. **Checks Existence**: Verifies if the FREESWITCH chain exists
2. **Creates Chain**: `iptables -N FREESWITCH` if not present
3. **Links Chain**: `iptables -A INPUT -j FREESWITCH` to route traffic
4. **Validates Rules**: Ensures proper integration with existing firewall

### Visual Chain Diagram

```
┌─────────────────┐
│ Internet Traffic │
└─────────┬───────┘
          │
          ▼
┌─────────────────┐     ┌──────────────────┐
│   INPUT Chain   │────▶│ FREESWITCH Chain │
└─────────────────┘     └─────────┬────────┘
          │                       │
          │                       ▼
          │              ┌─────────────────┐
          │              │ Blocked IPs     │
          │              │ (DROP silently) │
          │              └─────────────────┘
          ▼
┌─────────────────┐
│ Accept/Continue │
└─────────────────┘
```

## ⚙️ Configuration Setup

### Application Configuration

Configure IPTables integration in `config.json`:

```json
{
  "security": {
    "auto_block_enabled": true,
    "iptables_chain": "FREESWITCH",
    "block_duration": "1h",
    "trusted_networks": [
      "127.0.0.1/8",
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  }
}
```

### Environment Variable Override

```bash
export SECURITY_AUTO_BLOCK=true
export SECURITY_IPTABLES_CHAIN=CUSTOM_SECURITY
export SECURITY_BLOCK_DURATION=2h
```

## 🔥 Basic Firewall Configuration

### Minimal Security Setup

⚠️ **Warning**: These examples are for instructional purposes only. Do not use in production without proper security review.

```bash
# Set secure default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback (essential for system operation)
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (adjust port as needed)
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
```

### FreeSWITCH-Specific Rules

```bash
# SIP signaling ports
sudo iptables -A INPUT -p udp --dport 5060 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5060 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 5080 -j ACCEPT  # Alternative SIP port

# RTP media port range (adjust to match FreeSWITCH configuration)
sudo iptables -A INPUT -p udp --dport 16384:32768 -j ACCEPT

# WebRTC/WSS (if using)
sudo iptables -A INPUT -p tcp --dport 8081:8082 -j ACCEPT

# FreeSWITCH Security API (restrict to management network)
sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
```

### Custom Chain Integration

```bash
# Create the FREESWITCH chain
sudo iptables -N FREESWITCH

# Insert jump to FREESWITCH chain early in INPUT processing
sudo iptables -I INPUT 1 -j FREESWITCH

# Verify chain integration
sudo iptables -L INPUT --line-numbers
```

## 🧪 Testing and Validation

### Manual Testing Procedures

#### 1. Verify Chain Creation
```bash
# List the FREESWITCH chain
sudo iptables -L FREESWITCH -v -n

# Expected output for empty chain:
# Chain FREESWITCH (1 references)
#  pkts bytes target     prot opt in     out     source               destination
```

#### 2. Test Rule Addition
```bash
# Add a test rule manually
sudo iptables -A FREESWITCH -s 192.0.2.1 -j DROP

# Verify rule was added
sudo iptables -L FREESWITCH -v -n
```

#### 3. Test Application Integration
```bash
# Add IP via API
curl -X POST http://127.0.0.1:8080/security/blacklist \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "192.0.2.100",
    "reason": "Testing IPTables integration",
    "permanent": false
  }'

# Verify rule creation
sudo iptables -L FREESWITCH -v -n | grep 192.0.2.100

# Test blocking (from another machine)
telnet 192.0.2.100 5060
# Should hang indefinitely (no response due to DROP)

# Remove via API
curl -X DELETE http://127.0.0.1:8080/security/blacklist/192.0.2.100

# Verify rule removal
sudo iptables -L FREESWITCH -v -n | grep 192.0.2.100
# Should return no results
```

#### 4. Batch Operation Testing
```bash
# Test batch blacklisting
curl -X POST http://127.0.0.1:8080/security/blacklist/batch \
  -H "Content-Type: application/json" \
  -d '[
    {"ip": "192.0.2.10", "reason": "Batch test 1"},
    {"ip": "192.0.2.11", "reason": "Batch test 2"},
    {"ip": "192.0.2.12", "reason": "Batch test 3"}
  ]'

# Verify all rules were added efficiently
sudo iptables -L FREESWITCH -v -n | grep -E "192\.0\.2\.(10|11|12)"
```

## 🚀 Advanced Configuration

### Custom Chain Names

For environments with existing security tools:

```json
{
  "security": {
    "iptables_chain": "VOIP_SECURITY"
  }
}
```

### Integration with Existing Firewalls

#### UFW Integration
```bash
# Create custom UFW rule for FreeSWITCH chain
sudo ufw route insert 1 allow in on any to any jump FREESWITCH
```

#### FirewallD Integration
```bash
# Add custom chain to firewalld
sudo firewall-cmd --permanent --direct --add-chain ipv4 filter FREESWITCH
sudo firewall-cmd --permanent --direct --add-rule ipv4 filter INPUT 0 -j FREESWITCH
sudo firewall-cmd --reload
```

### High-Availability Configurations

#### Master-Slave Setup
```bash
# On master node - sync rules to slave
iptables-save | ssh slave-node 'iptables-restore'

# Automated sync script
#!/bin/bash
SLAVE_NODES="slave1.example.com slave2.example.com"
for node in $SLAVE_NODES; do
    iptables-save | ssh $node 'iptables-restore'
done
```

#### Load Balancer Integration
```bash
# Allow health check traffic
sudo iptables -I FREESWITCH 1 -s 192.168.1.10 -p tcp --dport 8080 -j ACCEPT

# Rate limit health checks
sudo iptables -A FREESWITCH -p tcp --dport 8080 -m limit --limit 10/min -j ACCEPT
```

## 📊 Monitoring and Maintenance

### Rule Monitoring

#### View Current Blocks
```bash
# List all blocked IPs with packet counts
sudo iptables -L FREESWITCH -v -n

# API method
curl -s http://127.0.0.1:8080/security/iptables | jq '.'
```

#### Monitor Block Effectiveness
```bash
# Count blocked packets
sudo iptables -L FREESWITCH -v -n | awk 'NR>2 {sum+=$1} END {print "Total blocked packets:", sum}'

# Real-time monitoring
watch -n 5 'sudo iptables -L FREESWITCH -v -n'
```

### Performance Monitoring

#### Rule Count Optimization
```bash
# Monitor rule count (should be reasonable)
RULE_COUNT=$(sudo iptables -L FREESWITCH --line-numbers | tail -n +3 | wc -l)
echo "Current FREESWITCH rules: $RULE_COUNT"

# Alert if too many rules (>1000 may impact performance)
if [ $RULE_COUNT -gt 1000 ]; then
    echo "WARNING: High rule count may impact performance"
fi
```

#### Memory Usage
```bash
# Check IPTables memory usage
cat /proc/net/ip_tables_matches
cat /proc/net/ip_tables_targets

# System memory impact
free -h | grep Mem
```

### Automated Maintenance

#### Daily Cleanup Script
```bash
#!/bin/bash
# /etc/cron.daily/freeswitch-security-cleanup

# Remove zero-packet rules (may be expired)
sudo iptables -L FREESWITCH -v -n --line-numbers | \
  awk '$3==0 && NR>2 {print $1}' | \
  tac | \
  while read line; do
    sudo iptables -D FREESWITCH $line
  done

# Log rule count
RULE_COUNT=$(sudo iptables -L FREESWITCH --line-numbers | tail -n +3 | wc -l)
logger "FreeSWITCH Security: $RULE_COUNT active IPTables rules"
```

#### Rule Backup and Restore
```bash
# Backup current rules
sudo iptables-save > /backup/iptables-$(date +%Y%m%d).rules

# Restore from backup
sudo iptables-restore < /backup/iptables-20240115.rules
```

## 🔍 Troubleshooting Guide

### Common Issues and Solutions

#### 1. Chain Not Created

**Symptoms:**
```log
[ESL ERROR] Failed to set up iptables chain: command not found
```

**Diagnosis:**
```bash
# Check if iptables is installed
which iptables
# Should return: /sbin/iptables or /usr/sbin/iptables

# Check if user has permissions
sudo iptables -L >/dev/null 2>&1 && echo "OK" || echo "Permission denied"
```

**Solutions:**
```bash
# Install iptables (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install iptables

# Install iptables (CentOS/RHEL)
sudo yum install iptables-services

# Fix permissions
sudo setcap cap_net_admin=+ep ./freeswitch-security
```

#### 2. Rules Not Working

**Symptoms:**
- Blocked IPs can still connect
- API shows rules but no blocking occurs

**Diagnosis:**
```bash
# Check chain ordering
sudo iptables -L INPUT --line-numbers | grep -A5 -B5 FREESWITCH

# Verify rule placement
sudo iptables -L FREESWITCH -v -n --line-numbers
```

**Solutions:**
```bash
# Move FREESWITCH chain higher in INPUT
sudo iptables -D INPUT -j FREESWITCH
sudo iptables -I INPUT 1 -j FREESWITCH

# Check for conflicting ACCEPT rules above FREESWITCH
sudo iptables -L INPUT --line-numbers
```

#### 3. Performance Issues

**Symptoms:**
```log
[ESL ERROR] IPTables command timeout
[ESL DEBUG] Batch iptables error: exit status 4
```

**Diagnosis:**
```bash
# Check rule count
sudo iptables -L FREESWITCH --line-numbers | wc -l

# Monitor system load during rule operations
top -p $(pgrep freeswitch-security)
```

**Solutions:**
```bash
# Increase batch operation timeout in code
# Implement rule optimization strategies
# Consider using ipset for large IP lists

# Example ipset integration:
sudo ipset create freeswitch-blocked hash:ip
sudo iptables -A FREESWITCH -m set --match-set freeswitch-blocked src -j DROP
```

#### 4. Memory Exhaustion

**Symptoms:**
```bash
iptables: Memory allocation problem
```

**Solutions:**
```bash
# Increase kernel memory limits
echo 'net.netfilter.nf_conntrack_max = 131072' >> /etc/sysctl.conf
echo 'net.netfilter.nf_conntrack_buckets = 32768' >> /etc/sysctl.conf
sysctl -p

# Monitor memory usage
cat /proc/sys/net/netfilter/nf_conntrack_count
cat /proc/sys/net/netfilter/nf_conntrack_max
```

### Debugging Commands

#### Trace Rule Processing
```bash
# Enable IPTables logging for debugging
sudo iptables -I FREESWITCH 1 -j LOG --log-prefix "FREESWITCH-DEBUG: "

# Monitor logs
sudo tail -f /var/log/kern.log | grep FREESWITCH-DEBUG

# Remove debug rule when done
sudo iptables -D FREESWITCH -j LOG --log-prefix "FREESWITCH-DEBUG: "
```

#### Test Specific Rules
```bash
# Test if a specific IP is blocked
sudo iptables -C FREESWITCH -s 192.0.2.1 -j DROP
echo $?  # 0 = rule exists, 1 = rule does not exist

# List rules in creation order
sudo iptables -S FREESWITCH
```

## 🔒 Security Best Practices

### Rule Management

1. **Minimize Rule Count**: Use CIDR blocks instead of individual IPs when possible
2. **Regular Cleanup**: Implement automated removal of expired rules
3. **Monitoring**: Set up alerts for unusual rule count increases
4. **Backup Strategy**: Regular rule backups before major changes

### Access Control

1. **Principle of Least Privilege**: Only grant necessary IPTables permissions
2. **API Security**: Restrict API access to management networks
3. **Audit Logging**: Enable comprehensive logging of rule changes
4. **Change Management**: Document all manual IPTables modifications

### Network Security

```bash
# Restrict management access
sudo iptables -A INPUT -p tcp --dport 8080 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP

# Rate limit API requests
sudo iptables -A INPUT -p tcp --dport 8080 -m limit --limit 30/min -j ACCEPT

# Log suspicious activity
sudo iptables -A INPUT -p tcp --dport 5060 -m limit --limit 1/sec --limit-burst 5 \
  -j LOG --log-prefix "SIP-FLOOD: "
```

## 📈 Performance Optimization

### Batch Operation Tuning

The application uses batch operations to minimize system call overhead:

```go
// Example of batch processing in the application
func (sm *SecurityManager) batchBlockIPs(ips []string) {
    // Group multiple iptables commands into single shell execution
    var commands []string
    for _, ip := range ips {
        cmd := fmt.Sprintf("iptables -A %s -s %s -j DROP",
                          sm.securityConfig.IPTablesChain, ip)
        commands = append(commands, cmd)
    }

    // Execute all commands in one shell invocation
    script := strings.Join(commands, " && ")
    exec.Command("sh", "-c", script).Run()
}
```

### IPSet Integration for Scale

For environments with thousands of blocked IPs:

```bash
# Create ipset for blocked IPs
sudo ipset create freeswitch-blocked hash:ip maxelem 100000

# Use single iptables rule with ipset
sudo iptables -A FREESWITCH -m set --match-set freeswitch-blocked src -j DROP

# Add IPs to set (much faster than individual rules)
sudo ipset add freeswitch-blocked 192.0.2.1
sudo ipset add freeswitch-blocked 192.0.2.2
```

### Rule Optimization Strategies

1. **Most Specific First**: Place most common blocks at top of chain
2. **CIDR Consolidation**: Combine individual IPs into CIDR blocks
3. **Time-Based Cleanup**: Remove stale rules proactively
4. **Memory Monitoring**: Track kernel memory usage

## 🎯 Production Deployment Checklist

### Pre-Deployment

- [ ] Test IPTables functionality in staging environment
- [ ] Verify application has appropriate permissions
- [ ] Configure firewall rules for FreeSWITCH services
- [ ] Set up monitoring and alerting
- [ ] Create rule backup and restore procedures

### Post-Deployment

- [ ] Verify chain creation and integration
- [ ] Test blocking functionality with known bad IPs
- [ ] Monitor system performance impact
- [ ] Set up automated maintenance tasks
- [ ] Document emergency procedures

### Monitoring Setup

```bash
# Create monitoring script
#!/bin/bash
# /usr/local/bin/monitor-freeswitch-security

# Check chain exists
if ! iptables -L FREESWITCH >/dev/null 2>&1; then
    echo "CRITICAL: FREESWITCH chain missing"
    exit 2
fi

# Check rule count
RULE_COUNT=$(iptables -L FREESWITCH --line-numbers | tail -n +3 | wc -l)
if [ $RULE_COUNT -gt 5000 ]; then
    echo "WARNING: High rule count: $RULE_COUNT"
    exit 1
fi

echo "OK: $RULE_COUNT rules active"
exit 0
```

## 🔗 Integration Examples

### Nagios/Icinga Monitoring

```bash
# /etc/nagios/commands.cfg
define command{
    command_name    check_freeswitch_iptables
    command_line    /usr/local/bin/monitor-freeswitch-security
}

# Service definition
define service{
    service_description     FreeSWITCH IPTables
    host_name               voip-server
    check_command           check_freeswitch_iptables
    check_interval          5
}
```

### Prometheus Metrics

```bash
# Custom exporter for IPTables metrics
#!/bin/bash
echo "# HELP freeswitch_iptables_rules_total Total IPTables rules"
echo "# TYPE freeswitch_iptables_rules_total gauge"
RULE_COUNT=$(iptables -L FREESWITCH --line-numbers | tail -n +3 | wc -l)
echo "freeswitch_iptables_rules_total $RULE_COUNT"
```

## 📚 Additional Resources

### Documentation References

- [Netfilter Documentation](https://www.netfilter.org/documentation/)
- [IPTables Manual](https://linux.die.net/man/8/iptables)
- [FreeSWITCH Security Best Practices](https://freeswitch.org/confluence/display/FREESWITCH/Security)

### Related Tools

- **ipset**: High-performance IP sets for large-scale blocking
- **fail2ban**: Complementary intrusion prevention system
- **ufw**: Simplified firewall management
- **firewalld**: Dynamic firewall management

---

## 🔚 Conclusion

The IPTables integration in FreeSWITCH Security provides enterprise-grade protection through:

- **Stealth Blocking**: Silent packet dropping prevents reconnaissance
- **Batch Operations**: Efficient rule management reduces system overhead
- **Automatic Management**: Dynamic rule creation and cleanup
- **Performance Optimization**: Minimal impact on system resources
- **Comprehensive Monitoring**: Full visibility into blocking effectiveness

By following this guide, you can implement a robust, scalable IPTables-based security solution that protects your FreeSWITCH infrastructure while maintaining optimal performance.

For additional support or advanced configuration scenarios, please refer to the main [README.md](README.md) or consult the project's issue tracker.

---

**Related Documentation:**
- [Main README](README.md) - Complete application overview
- [Logging Guide](logging.md) - Comprehensive logging configuration
- [ESL Command API](esl.md) - FreeSWITCH command interface
