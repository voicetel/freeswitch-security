# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.2.x   | ✅        |
| < 1.2   | ❌        |

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub's private vulnerability reporting for this repository:
**Security → Report a vulnerability** (or
<https://github.com/voicetel/freeswitch-security/security/advisories/new>).

Include, where possible:

- A description of the issue and its impact
- Steps to reproduce or a proof of concept
- Affected version(s) and configuration

You can expect an acknowledgement within a few business days. Please allow
reasonable time for a fix before any public disclosure.

## Scope Notes

This service manages host firewall state (iptables) and connects to the
FreeSWITCH Event Socket. Deployment hardening expectations:

- Bind the HTTP API to a trusted interface (default `127.0.0.1`)
- Keep the pprof diagnostics listener disabled or loopback-only (the default)
- Restrict the ESL allowed-command list to read-only commands
- Run with the least privilege required to manage the configured iptables chain
