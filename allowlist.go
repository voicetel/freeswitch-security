package main

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"
)

// ipAllowList is a source-IP allow-list for state-changing API endpoints. It is
// the access control for the chanDaemon (D39) unban fan-out: chanDaemon sends an
// unauthenticated DELETE, so the only gate is that its source IP is permitted
// here. Bare IPs are stored as host-length prefixes; CIDRs as their masked
// prefix. A nil/empty list allows everything (the API is unrestricted).
type ipAllowList struct {
	prefixes []netip.Prefix
}

// parseAllowedIPs builds an allow-list from config entries (bare IPs or CIDRs).
// Invalid entries are skipped and reported via the returned error, which names
// every bad entry; the valid entries are still usable. An all-empty input
// returns (nil, nil) — an unrestricted API.
func parseAllowedIPs(entries []string) (*ipAllowList, error) {
	list := &ipAllowList{}

	var bad []string

	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.Contains(entry, "/") {
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				bad = append(bad, entry)

				continue
			}

			list.prefixes = append(list.prefixes, prefix.Masked())

			continue
		}

		addr, err := netip.ParseAddr(entry)
		if err != nil {
			bad = append(bad, entry)

			continue
		}

		list.prefixes = append(list.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	if list.Empty() {
		list = nil
	}

	if len(bad) > 0 {
		return list, fmt.Errorf("%w: %s", ErrInvalidAllowEntry, strings.Join(bad, ", "))
	}

	return list, nil
}

// Empty reports whether the list permits nothing of its own (a nil or
// zero-entry list), which the middleware treats as "unrestricted".
func (l *ipAllowList) Empty() bool {
	return l == nil || len(l.prefixes) == 0
}

// Contains reports whether host (a bare IP string, no port) is permitted.
func (l *ipAllowList) Contains(host string) bool {
	if l == nil {
		return false
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	addr = addr.Unmap()

	for _, prefix := range l.prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

// allowListMiddleware gates state-changing requests (POST/PUT/PATCH/DELETE) on
// the source IP being in list; safe methods (GET/HEAD/OPTIONS) always pass. The
// check uses the real connection address (RemoteAddr), never X-Forwarded-For,
// so it cannot be spoofed by a header. An empty list is a no-op. A non-allowed
// source receives 403 with a plain "forbidden"-style JSON error.
func allowListMiddleware(list *ipAllowList) gin.HandlerFunc {
	return func(c *gin.Context) {
		if list.Empty() {
			c.Next()

			return
		}

		switch c.Request.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			c.Next()

			return
		}

		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			host = c.Request.RemoteAddr
		}

		if !list.Contains(host) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				respKeyError: "source IP not permitted for this operation",
			})

			return
		}

		c.Next()
	}
}
