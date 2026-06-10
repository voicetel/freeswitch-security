package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// chanDaemon (D39) ban reporting. When the firewall blocks an IP, chanDaemon
// resolves it to the 10-digit account(s) it serves and stores the ban so it
// surfaces in the customer portal; a customer (or operator) unban then pushes
// back to this node's DELETE /api/v1/ips/:ip/block endpoint. Reporting is
// best-effort and never blocks or fails a firewall operation: the kernel ipset
// remains the source of truth for enforcement, chanDaemon only mirrors it for
// visibility and unban fan-out.

// reportBody is the JSON chanDaemon's /api/v1/ip-bans/report expects. The wire
// keys are camelCase to match the chanDaemon server. ttl is in seconds; a
// non-positive ttl lets chanDaemon apply its own 24-hour sticky floor.
type reportBody struct {
	IP       string `json:"ip"`
	Reason   string `json:"reason"`
	TTL      int64  `json:"ttl"`
	Blocker  string `json:"blocker"`
	Service  string `json:"service"`
	FromUser string `json:"fromUser,omitempty"`
}

// ChanDaemonReporter POSTs ban reports to chanDaemon asynchronously. endpoint is
// the chanDaemon report URL; self is this node's own base URL (scheme://host:port)
// that chanDaemon records as the reporter so it can push unbans back; service is
// the sending-daemon identity (D40) included in every report.
type ChanDaemonReporter struct {
	endpoint string
	self     string
	service  string
	client   *http.Client
	wg       sync.WaitGroup

	// Counters for monitoring the chanDaemon path (exposed via Stats and the
	// /security/stats response).
	sent   atomic.Uint64
	failed atomic.Uint64
}

// NewChanDaemonReporter builds a reporter. self is this node's base URL (recorded
// so chanDaemon can push unbans back); service is the sending-daemon identity
// (e.g. "freeswitch-security"); timeout bounds each report POST.
func NewChanDaemonReporter(endpoint, self, service string, timeout time.Duration) *ChanDaemonReporter {
	return &ChanDaemonReporter{
		endpoint: endpoint,
		self:     self,
		service:  service,
		client:   &http.Client{Timeout: timeout},
	}
}

// Report fires the POST in the background so the firewall path is never delayed
// by the network. Wait drains in-flight reports at shutdown.
func (r *ChanDaemonReporter) Report(ip, fromUser, reason string, ttl time.Duration) {
	r.wg.Add(1)

	go func() {
		defer r.wg.Done()

		r.post(ip, fromUser, reason, ttl)
	}()
}

// Stats returns the cumulative count of (sent, failed) ban reports, for
// monitoring the chanDaemon path.
func (r *ChanDaemonReporter) Stats() (uint64, uint64) {
	return r.sent.Load(), r.failed.Load()
}

// Wait blocks until all in-flight reports have finished (graceful shutdown).
func (r *ChanDaemonReporter) Wait() { r.wg.Wait() }

// post performs one report; all failures are logged, never propagated.
func (r *ChanDaemonReporter) post(ip, fromUser, reason string, ttl time.Duration) {
	logger := GetLogger()

	secs := int64(0)
	if ttl > 0 {
		secs = int64(ttl / time.Second)
	}

	buf, err := json.Marshal(reportBody{
		IP: ip, Reason: reason, TTL: secs, Blocker: r.self, Service: r.service, FromUser: fromUser,
	})
	if err != nil {
		r.failed.Add(1)
		logger.Error("ban report marshal failed for %s: %v", ip, err)

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.client.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(buf))
	if err != nil {
		r.failed.Add(1)
		logger.Error("ban report request build failed for %s: %v", ip, err)

		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		r.failed.Add(1)
		logger.Error("ban report to %s failed for %s: %v", r.endpoint, ip, err)

		return
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusMultipleChoices {
		r.failed.Add(1)
		logger.Error("ban report for %s rejected by %s: HTTP %d", ip, r.endpoint, resp.StatusCode)

		return
	}

	r.sent.Add(1)
	logger.Debug("reported ban of %s to chanDaemon", ip)
}

// reportableUser returns the SIP From-user to attach to a ban report, or "" when
// there is no real user to attribute (empty or the unknownUser placeholder).
// chanDaemon re-validates the value against enabled accounts, so an unhelpful
// placeholder is dropped rather than sent.
func reportableUser(userID string) string {
	if userID == unknownUser {
		return ""
	}

	return userID
}
