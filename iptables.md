# Firewall Integration Guide (ipset + iptables)

This guide explains how FreeSWITCH Security blocks malicious IPs at the kernel
level. As of v1.3.0 the blocking backend is a **kernel ipset** referenced by a
single `iptables` rule, replacing the previous one-rule-per-IP approach.

## 🏗️ Architecture Overview

- **ipset-backed blocking**: blocked IPs live in a kernel `hash:ip` set; the
  firewall ruleset stays a constant size no matter how many IPs are banned.
- **Single match-set rule**: one `iptables` DROP rule matches the whole set,
  inserted at the top of the configured chain (`INPUT` by default).
- **In-kernel ban expiry**: each set entry carries a timeout, so bans expire in
  the kernel automatically — no per-rule cleanup goroutine on the hot path.
- **Stealth blocking**: the rule uses `DROP`, not `REJECT` (see below).
- **Startup hygiene**: on boot the app flushes stale set entries and removes any
  legacy per-IP `Auto-blocked` rules left by pre-v1.3.0 versions, so upgrades
  need no manual firewall cleanup.

```
Internet traffic → INPUT chain
                     │
                     ▼
        ┌───────────────────────────────┐
        │ -m set --match-set <set> src   │ ── match ──▶ DROP (silently)
        │ -j DROP   (one rule)           │
        └───────────────────────────────┘
                     │ no match
                     ▼
              Accept / continue
```

The set is `hash:ip` (`family inet`, IPv4) with `hashsize 4096` and
`maxelem 1000000` — membership tests and updates are O(1).

## 🛡️ Security Philosophy: DROP vs REJECT

The match-set rule uses **DROP** rather than **REJECT**:

- **Stealth**: attackers and port scanners get no response — connections hang
  and time out rather than being actively refused.
- **Resource efficiency**: no ICMP/RST generation, no outbound traffic for
  blocked sources, dropping happens at the earliest kernel stage.
- **Operational security**: fewer monitoring false positives; defensive posture
  is not advertised.

```bash
# Attacker perspective — connection hangs until timeout, no rejection
telnet your-server.example 5060

# Legitimate user perspective — no visible change, no performance impact
```

## 🔧 Prerequisites and Requirements

### System requirements

- **Linux** with the Netfilter framework (Ubuntu 18.04+, Debian 9+, CentOS 7+,
  or compatible).
- **ipset** installed and on `PATH` — this is a runtime dependency:
  ```bash
  sudo apt-get install ipset      # Debian/Ubuntu
  sudo dnf install ipset          # Fedora/RHEL/CentOS
  ```
  The app fails fast with an actionable error if `ipset` is missing while
  auto-blocking is enabled.
- **iptables** 1.6.0+ with the `set` match (`xt_set`, ships with ipset).
- **Privileges**: root or `CAP_NET_ADMIN` to manage the set and the rule.

### Permission configuration

#### Option 1 — run as root (simplest)
```bash
sudo ./bin/freeswitch-security
```

#### Option 2 — capability-based (recommended)
```bash
sudo setcap cap_net_admin=+ep ./bin/freeswitch-security
getcap ./bin/freeswitch-security      # → cap_net_admin+ep
./bin/freeswitch-security
```

#### Option 3 — sudo allowlist (production)
```bash
# /etc/sudoers.d/freeswitch-security
freeswitch-user ALL=(ALL) NOPASSWD: /sbin/ipset, /sbin/iptables
```

## ⚙️ Configuration

```json
{
  "security": {
    "auto_block_enabled": true,
    "iptables_chain": "INPUT",
    "ipset_name": "freeswitch-security",
    "dry_run": false,
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

| Key | Meaning |
|-----|---------|
| `auto_block_enabled` | Master switch for firewall management. When off, no set or rule is created. |
| `iptables_chain` | Chain the match-set DROP rule is inserted into. **Must be a chain the kernel traverses** (`INPUT` by default). |
| `ipset_name` | Name of the managed set (`freeswitch-security` by default). |
| `dry_run` | When true, every `ipset`/`iptables` action is logged but not executed — useful for testing without privileges. |
| `block_duration` | Default ban TTL, applied as the set entry timeout. Permanent bans use a zero (no-expiry) timeout. |

### Environment variable overrides

```bash
export SECURITY_AUTO_BLOCK=true
export SECURITY_IPTABLES_CHAIN=INPUT
export SECURITY_IPSET_NAME=freeswitch-security
export SECURITY_DRY_RUN=false
export SECURITY_BLOCK_DURATION=2h
```

> **Upgrading from < v1.3.0:** the default chain changed from a custom
> `FREESWITCH` chain to `INPUT`. On first start the app removes legacy per-IP
> `Auto-blocked` rules automatically; you can drop the old empty `FREESWITCH`
> chain manually with `iptables -X FREESWITCH` once it is unreferenced.

## 🔥 Host firewall baseline

`auto_block_enabled` only manages the block set — you still need a sane base
policy. Example (instructional; review before production use):

```bash
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT          # SSH

# FreeSWITCH services
sudo iptables -A INPUT -p udp --dport 5060 -j ACCEPT        # SIP
sudo iptables -A INPUT -p tcp --dport 5060 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 16384:32768 -j ACCEPT # RTP

# Security API — restrict to the management network
sudo iptables -A INPUT -p tcp --dport 8088 -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8088 -j DROP
```

The application installs its own match-set DROP rule at position 1 of the
configured chain, so blocked IPs are dropped before any ACCEPT rule below it.

## 🧪 Testing and validation

The app creates the set and rule on startup (when `auto_block_enabled`). To
verify by hand:

```bash
# 1. The set exists
sudo ipset list freeswitch-security | head

# 2. The single match-set rule is present in the chain
sudo iptables -S INPUT | grep -- '--match-set freeswitch-security'
# -A INPUT -m set --match-set freeswitch-security src -j DROP   (at position 1)
```

End-to-end via the API:

```bash
# Block
curl -X POST http://127.0.0.1:8088/security/blacklist \
  -H 'Content-Type: application/json' \
  -d '{"ip":"192.0.2.100","reason":"test","permanent":false}'

# The IP is now a set member (with a countdown timeout)
sudo ipset test freeswitch-security 192.0.2.100   # → "... is in set ..."

# Unblock
curl -X DELETE http://127.0.0.1:8088/security/blacklist/192.0.2.100
sudo ipset test freeswitch-security 192.0.2.100   # → "... is NOT in set ..."
```

The `/security/iptables` endpoint reports set state directly:

```bash
curl -s http://127.0.0.1:8088/security/iptables | jq '.'
# { "chain": "INPUT", "ipset": "freeswitch-security",
#   "blockedIps": ["192.0.2.100"], "count": 1 }
```

## 📊 Monitoring and maintenance

```bash
# Current bans (with per-entry remaining timeout)
sudo ipset list freeswitch-security

# Member count
sudo ipset list freeswitch-security | sed -n 's/^Number of entries: //p'

# Packets dropped by the match-set rule
sudo iptables -L INPUT -v -n | grep -- 'match-set freeswitch-security'
```

There is **no per-rule cleanup to run**: entries expire in the kernel via their
timeout, and the application also removes them from the set when a ban is
lifted or a whitelist entry supersedes it.

### Backup / restore the set

```bash
sudo ipset save freeswitch-security > /backup/fs-ipset-$(date +%Y%m%d).save
sudo ipset restore < /backup/fs-ipset-20260604.save
```

## 🔍 Troubleshooting

#### `ipset is not installed or not on PATH`
The binary is missing or `ipset` isn't installed. Install it (see
Prerequisites) or run with `dry_run: true` to start without firewall changes.

#### Blocked IPs can still connect
Confirm the match-set rule is actually reached:
```bash
sudo iptables -S INPUT | grep -n -- '--match-set freeswitch-security'
```
It must sit above any broad ACCEPT rule. The app inserts at position 1; if a
later manual edit moved it, re-insert it or restart with `auto_block_enabled`.

#### Verify a specific IP / inspect the set
```bash
sudo ipset test freeswitch-security 192.0.2.1   # membership
sudo ipset list freeswitch-security              # all members + timeouts
```

#### Permission denied
```bash
sudo iptables -L >/dev/null 2>&1 && echo OK || echo "need CAP_NET_ADMIN/root"
sudo setcap cap_net_admin=+ep ./bin/freeswitch-security
```

#### Dry-run for safe diagnosis
Set `dry_run: true` (or `SECURITY_DRY_RUN=true`): the app logs every `ipset`
and `iptables` command it *would* run without touching kernel state.

## 🔒 Security best practices

- **Least privilege**: prefer `CAP_NET_ADMIN` over running as root; scope sudo
  to `ipset`/`iptables` only.
- **Restrict the API**: bind to a management interface and firewall port 8088 to
  trusted sources; keep the pprof endpoint loopback-only (the default).
- **Trusted networks**: list management/internal CIDRs in `trusted_networks` so
  the app never blocks them.
- **Complementary tooling**: ipset pairs cleanly with fail2ban (point its action
  at the same set) and host firewall managers (ufw/firewalld) for base policy.

## 📚 References

- [ipset manual](https://ipset.netfilter.org/ipset.man.html)
- [Netfilter documentation](https://www.netfilter.org/documentation/)
- The blocking backend is implemented in `ipset.go` (`IPSetManager`), ported
  from the sibling `opensips-journal-blocker` project to keep the two services'
  firewall behaviour identical.

---

**Related documentation:**
- [Main README](README.md) — application overview
- [Logging Guide](logging.md) — logging configuration
- [ESL Command API](esl.md) — FreeSWITCH command interface
