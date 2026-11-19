package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/fiorix/go-eventsocket/eventsocket"
)

// ESL CVE guard. FreeSWITCH publishes exploit markers for several CVEs as
// plain ESL events, and this daemon already inspects every event on its
// worker path. When an event matches a known CVE exploit signature, the
// sending endpoint is banned immediately: the blacklist entry and the kernel
// ipset add are applied synchronously rather than through the 100ms batch
// ticker, because these events are rare and the next packet of an exploit
// chain can be the one that executes code.
//
// Signatures tracked here:
//
//   - CVE-2026-116779 (9.8, CISA KEV, exploited in the wild): an inbound SIP
//     MESSAGE whose To user selects the "api" chat proto reaches
//     switch_api_execute() and runs a FreeSWITCH API/OS command with the
//     daemon's privileges. The MESSAGE event exposes the selector as a
//     to_user / to value with the literal "api+" prefix (case-insensitive,
//     matching the chat interface registry). Fixed in 1.11.3.
//
//   - CVE-2026-116786 (8.8): a SIP REFER injects channel variables through
//     the raw sip_invite_params block; the demonstrated chain sets
//     execute_on_originate to the "system" dialplan application, which runs
//     an OS command on the originated leg before answer. The leg's
//     CHANNEL_CREATE event carries both the raw sip_invite_params and the
//     applied execute_on_originate variable. Fixed in 1.11.2.
//
// The guard is a compensating control, not the fix: an ESL event fires after
// the offending request already reached FreeSWITCH, so it cannot undo the
// first packet. It exists to (a) instantly ban the endpoint so every
// follow-up message of the chain dies in the kernel, (b) propagate the ban
// fleet-wide through chanDaemon, and (c) make exploitation attempts visible
// in stats and logs. Upgrading FreeSWITCH (>= 1.11.3 closes everything
// tracked here) remains the required remediation.

// FreeSWITCH event and header names observed by the CVE guard.
const (
	// eventNameMessage is the first-class instant-message event fired for
	// inbound chat messages across protocols (SIP MESSAGE, verto, ...).
	eventNameMessage = "MESSAGE"

	// CVE-2026-116779: the chat-proto selector prefix that routes the rest
	// of the To user straight into switch_api_execute().
	cve116779ID        = "CVE-2026-116779"
	cve116779ProtoMark = "api+"

	// CVE-2026-116786: channel variables the REFER injection lands in.
	cve116786ID = "CVE-2026-116786"

	// ESL header names. FreeSWITCH emits these lowercase; the eventsocket
	// library canonicalizes header keys MIME-style ("from_sip_ip" arrives as
	// "From_sip_ip"), so the canonical spellings below are the only ones
	// production events carry. The matches use single exact lookups (no
	// fallback variants) because CHANNEL_CREATE is a hot path and MESSAGE
	// can be attacker-flooded.
	hdrMESSAGEToUser    = "To_user"
	hdrMESSAGETo        = "To"
	hdrMESSAGEFromSIPIP = "From_sip_ip"
	hdrMESSAGEFromUser  = "From_user"

	hdrVarExecuteOnOriginate = "Variable_execute_on_originate"
	hdrVarSIPInviteParams    = "Variable_sip_invite_params"
)

// cve116779MessageMatch reports whether an ESL MESSAGE event carries the
// CVE-2026-116779 exploit marker: the To user selecting the api chat proto.
// When matched, sourceIP is the SIP peer that sent the message.
func cve116779MessageMatch(ev *eventsocket.Event) (string, string, bool) {
	toUser := strings.ToLower(strings.TrimSpace(ev.Get(hdrMESSAGEToUser)))
	to := strings.ToLower(strings.TrimSpace(ev.Get(hdrMESSAGETo)))

	if !strings.HasPrefix(toUser, cve116779ProtoMark) && !strings.HasPrefix(to, cve116779ProtoMark) {
		return "", "", false
	}

	ip := strings.TrimSpace(ev.Get(hdrMESSAGEFromSIPIP))
	if !validIP(ip) {
		return "", "", false
	}

	return ip, ev.Get(hdrMESSAGEFromUser), true
}

// cve116786ChannelCreateMatch reports whether a CHANNEL_CREATE event carries
// the CVE-2026-116786 REFER variable-injection markers. The demonstrated
// chain injects execute_on_originate=system into the sip_invite_params block;
// both the raw block and the applied variable are checked.
func cve116786ChannelCreateMatch(ev *eventsocket.Event) (string, string, bool) {
	executeOnOriginate := strings.ToLower(strings.TrimSpace(ev.Get(hdrVarExecuteOnOriginate)))
	inviteParams := strings.ToLower(ev.Get(hdrVarSIPInviteParams))

	injected := executeOnOriginate == "system" ||
		strings.HasPrefix(executeOnOriginate, "system ") ||
		strings.Contains(inviteParams, "execute_on_originate=system") ||
		strings.Contains(inviteParams, "api_hangup_hook=system")

	if !injected {
		return "", "", false
	}

	ip := strings.TrimSpace(ev.Get(hdrVarNetworkIP))
	if !validIP(ip) {
		return "", "", false
	}

	return ip, ev.Get(hdrVarFromUser), true
}

// handleCVEMessageEvent is the MESSAGE-event arm of the CVE guard.
func (w *EventWorker) handleCVEMessageEvent(ev *eventsocket.Event) {
	if !w.manager.cveProtectionEnabled {
		return
	}

	ip, fromUser, ok := cve116779MessageMatch(ev)
	if !ok {
		return
	}

	w.blockCVESource(ip, fromUser, cve116779ID+": inbound SIP MESSAGE selected the api chat proto")
}

// cveChannelCreateGuard is the CHANNEL_CREATE arm of the CVE guard. On a
// match the source endpoint is banned and the channel is torn down; the
// caller then skips its normal handling of the channel.
func (w *EventWorker) cveChannelCreateGuard(ev *eventsocket.Event, pe *ProcessedEvent) bool {
	if !w.manager.cveProtectionEnabled {
		return false
	}

	ip, fromUser, ok := cve116786ChannelCreateMatch(ev)
	if !ok {
		return false
	}

	w.blockCVESource(ip, fromUser, cve116786ID+": REFER channel-variable injection markers")
	w.terminateCall(pe, "cve-"+cve116786ID)

	return true
}

// blockCVESource bans one endpoint for a CVE exploit attempt. The ban is
// synchronous (see SecurityManager.BlockIPImmediate) so the kernel drop rule
// is in place before the next packet of the attempt arrives.
func (w *EventWorker) blockCVESource(ip, fromUser, reason string) {
	sm := w.manager.securityManager
	if sm == nil {
		return
	}

	if !validIP(ip) {
		w.logger.Error("Worker #%d: CVE event carried unusable source IP %q", w.id, ip)

		return
	}

	if sm.BlockIPImmediate(ip, reason, reportableUser(fromUser)) {
		w.logger.Info("Worker #%d: CVE guard banned %s: %s", w.id, ip, reason)
	}
}

// checkFreeSWITCHVersion fingerprints the connected FreeSWITCH via the
// `version` API and records which tracked CVEs it is still vulnerable to.
// This is informational — the active defense is the event-based CVE ban (and
// patching) — so failures are logged at debug level and never disturb the
// connection.
func (em *ESLManager) checkFreeSWITCHVersion(client *eventsocket.Connection) {
	logger := GetLogger()

	ev, err := em.send(client, "api version")
	if err != nil {
		logger.Debug("FreeSWITCH version check failed: %v", err)

		return
	}

	text := eventReplyText(ev)

	major, minor, patch, ok := parseFreeSWITCHVersion(text)
	if !ok {
		logger.Debug("Could not parse a FreeSWITCH version from %q", text)

		return
	}

	version := fmt.Sprintf("%d.%d.%d", major, minor, patch)
	vulnerable := vulnerableCVEsForVersion(major, minor, patch)

	em.fsVersionMu.Lock()
	em.fsVersion = version
	em.fsVulnerableCVEs = vulnerable
	em.fsVersionMu.Unlock()

	if len(vulnerable) > 0 {
		logger.Info("FreeSWITCH %s is vulnerable to %v; the ESL CVE guard bans exploit attempts, but upgrading to >= 1.11.3 is required",
			version, vulnerable)
	} else {
		logger.Info("FreeSWITCH version %s is not vulnerable to the tracked FreeSWITCH CVEs", version)
	}
}

// cveFixRelease couples a FreeSWITCH fix release with the remotely
// exploitable CVEs it closes. Releases are listed newest-first; a version
// older than a release is vulnerable to every CVE that release fixed.
type cveFixRelease struct {
	major, minor, patch int
	cves                []string
}

// trackedCVEFixReleases returns the FreeSWITCH fix releases the CVE guard
// knows about. It is a function (not a package var) so the table is rebuilt
// per call and stays out of the global namespace.
func trackedCVEFixReleases() []cveFixRelease {
	return []cveFixRelease{
		{
			major: 1, minor: 11, patch: 3,
			cves: []string{cve116779ID},
		},
		{
			major: 1, minor: 11, patch: 2,
			cves: []string{
				"CVE-2026-116572",
				"CVE-2026-116573",
				"CVE-2026-116783",
				"CVE-2026-116784",
				"CVE-2026-116785",
				cve116786ID,
				"CVE-2026-116790",
			},
		},
	}
}

// vulnerableCVEsForVersion returns the tracked CVEs a FreeSWITCH release is
// still vulnerable to, in fix-release order.
func vulnerableCVEsForVersion(major, minor, patch int) []string {
	var vulnerable []string

	for _, release := range trackedCVEFixReleases() {
		if versionOlderThan(major, minor, patch, release.major, release.minor, release.patch) {
			vulnerable = append(vulnerable, release.cves...)
		}
	}

	return vulnerable
}

// versionOlderThan compares two semantic-version triples.
func versionOlderThan(major, minor, patch, otherMajor, otherMinor, otherPatch int) bool {
	if major != otherMajor {
		return major < otherMajor
	}

	if minor != otherMinor {
		return minor < otherMinor
	}

	return patch < otherPatch
}

// parseFreeSWITCHVersion extracts the "X.Y.Z" release from the `version`
// API output ("FreeSWITCH Version 1.11.3 -release 64bit (git-...)").
func parseFreeSWITCHVersion(s string) (int, int, int, bool) {
	fields := strings.Fields(s)

	for i := 0; i+1 < len(fields); i++ {
		if !strings.EqualFold(fields[i], "Version") {
			continue
		}

		ver := fields[i+1]
		if dash := strings.IndexByte(ver, '-'); dash >= 0 {
			ver = ver[:dash]
		}

		parts := strings.Split(ver, ".")
		if len(parts) != 3 {
			return 0, 0, 0, false
		}

		var nums [3]int

		for idx, part := range parts {
			num, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				return 0, 0, 0, false
			}

			nums[idx] = num
		}

		return nums[0], nums[1], nums[2], true
	}

	return 0, 0, 0, false
}
