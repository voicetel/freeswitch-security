# chanDaemon integration (central ban repository)

`freeswitch-security` participates in the VoiceTel fleet's central outbound
IP-ban repository, **chanDaemon** (D39). The model is simple:

- **This node enforces.** When the security manager auto-blocks an IP, the
  kernel ipset (see [iptables.md](iptables.md)) is and remains the source of
  truth for enforcement on this host.
- **chanDaemon mirrors and fans out.** Every enacted ban is *reported* to
  chanDaemon, which resolves the IP to the 10-digit account(s) it serves and
  stores a replicated record so the ban surfaces in the customer portal and
  admin panel. When a customer or operator lifts a ban there, chanDaemon
  pushes the unban back to **this** node's unban endpoint.

Reporting is **best-effort**: a chanDaemon outage never blocks, delays, or
fails a firewall operation. Reports are sent asynchronously and drained at
shutdown.

## What gets reported

Each successful ipset block produces one report `POST` to
`security.chandaemon.report_url`:

```http
POST /api/v1/ip-bans/report
Content-Type: application/json

{
  "ip": "203.0.113.50",
  "reason": "Exceeded max failed registrations (5)",
  "ttl": 3600,
  "blocker": "http://198.51.100.10:8088",
  "service": "freeswitch-security",
  "fromUser": "2017301000"
}
```

| Field | Meaning |
|-------|---------|
| `ip` | The IPv4 address that was blocked. |
| `reason` | The auto-block reason (failed registrations, wrong call states, untrusted domain, or a manual block). |
| `ttl` | Ban lifetime in **seconds**; `0` for a permanent ban, letting chanDaemon apply its 24-hour sticky floor. |
| `blocker` | This node's own base URL (`security.chandaemon.blocker_url`); chanDaemon pushes unbans back here. |
| `service` | Sending-daemon identity (D40), `security.chandaemon.service_name`. |
| `fromUser` | Best-effort SIP From-user for account attribution; omitted when unknown. chanDaemon re-validates it against enabled accounts, so it is never trusted. |

Reporting fires only when bans are actually enforced — that is, when
`auto_block_enabled` is true and the kernel block succeeded. It is suppressed
in `dry_run` (which must produce no external side effects).

## Unban fan-out (receiving)

chanDaemon lifts a ban on this node with an unauthenticated request that must
match byte-for-byte:

```http
DELETE {blocker_url}/api/v1/ips/{ip}/block
```

The handler removes the IP from the blacklist and the kernel ipset
(`RemoveFromBlacklist`). It is idempotent — lifting an IP that is not currently
banned still returns `200` — so a chanDaemon retry is harmless. A malformed IP
returns `400`.

For chanDaemon to reach this endpoint, set `security.chandaemon.blocker_url`
to the externally reachable base URL of this node's API
(`scheme://host:port`). If it is left empty, bans are still reported but
chanDaemon cannot push unbans back.

## Access control (source-IP allow-list)

There is no token. chanDaemon's unban `DELETE` carries no credential, so the
only gate is a **source-IP allow-list** (`security.chandaemon.allowed_api_ips`,
accepting IPs and CIDRs) enforced in Go against the real connection address
(never `X-Forwarded-For`):

- It gates **all** state-changing endpoints (`POST`/`PUT`/`PATCH`/`DELETE`) —
  the unban receiver and the existing `/security/*` and `/cache/*` mutations.
- Read-only `GET`s are always open.
- It defaults to the chanDaemon nodes plus loopback, so the API is restricted
  out of the box. A non-allowed source receives `403`.
- An **empty** list leaves the API unrestricted (single-host / behind an
  authenticating reverse proxy).

For production, also bind the API to localhost or front it with an
authenticating proxy.

## Configuration

```json
"chandaemon": {
  "enabled": true,
  "report_url": "https://ipban.support.voicetel.com/api/v1/ip-bans/report",
  "blocker_url": "",
  "service_name": "freeswitch-security",
  "report_timeout": "5s",
  "allowed_api_ips": ["3.17.211.50", "104.225.13.77", "192.73.246.109", "127.0.0.1", "::1"]
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Master switch for reporting. |
| `report_url` | production ingress | chanDaemon report endpoint; empty disables reporting (standalone mode). |
| `blocker_url` | `""` | This node's own base URL chanDaemon pushes unbans to. Empty: reports work, unban fan-out does not. |
| `service_name` | `freeswitch-security` | Sending-daemon identity (D40). |
| `report_timeout` | `5s` | Per-report POST timeout. |
| `allowed_api_ips` | chanDaemon nodes + loopback | Source IPs/CIDRs allowed to drive state-changing endpoints; empty = unrestricted. |

Every key has a `SECURITY_CHANDAEMON_*` environment-variable override (see the
README's environment-variable table).

## Monitoring

`GET /security/stats` includes two counters when reporting is enabled:

- `reportsSent` — reports chanDaemon accepted (HTTP < 300).
- `reportsFailed` — reports that failed to build, send, or were rejected
  (best-effort; failures are logged and never affect enforcement).
