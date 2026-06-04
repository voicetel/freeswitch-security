package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// commandRunner executes an external command and returns its combined output.
// It is a field on IPSetManager so tests can substitute a fake runner instead
// of shelling out to the real ipset/iptables binaries.
type commandRunner func(name string, args ...string) ([]byte, error)

func execRunner(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// IPSetManager blocks IPs using a kernel ipset that is referenced by a single
// iptables DROP rule. Membership changes are O(1) and never touch iptables, and
// per-IP bans expire in-kernel via the entry timeout.
type IPSetManager struct {
	setName        string
	chain          string
	defaultTimeout time.Duration
	dryRun         bool
	logger         *Logger
	run            commandRunner
	lookPath       func(string) (string, error)
}

// NewIPSetManager creates a new ipset-backed blocker. defaultTimeout is the ban
// duration applied to the set and used when a per-IP TTL is not supplied.
func NewIPSetManager(chain, setName string, defaultTimeout time.Duration, dryRun bool, log *Logger) *IPSetManager {
	return &IPSetManager{
		setName:        setName,
		chain:          chain,
		defaultTimeout: defaultTimeout,
		dryRun:         dryRun,
		logger:         log,
		run:            execRunner,
		lookPath:       exec.LookPath,
	}
}

// EnsureSetup creates the ipset (if absent) and installs the single iptables
// DROP rule that matches the set. Both operations are idempotent.
func (m *IPSetManager) EnsureSetup() error {
	timeout := timeoutSeconds(m.defaultTimeout)
	createArgs := []string{
		"create", m.setName, "hash:ip", "family", "inet",
		"hashsize", "4096", "maxelem", "1000000",
		"timeout", strconv.Itoa(timeout), "-exist",
	}
	jumpMatch := []string{"-m", "set", "--match-set", m.setName, "src", "-j", "DROP"}
	jumpCheck := append([]string{"-C", m.chain}, jumpMatch...)
	jumpInsert := append([]string{"-I", m.chain, "1"}, jumpMatch...)

	if m.dryRun {
		m.logger.Info("DRY RUN: Would execute: ipset %s", strings.Join(createArgs, " "))
		m.logger.Info("DRY RUN: Would ensure iptables jump rule: iptables %s", strings.Join(jumpInsert, " "))
		return nil
	}

	// Fail fast with a clear, actionable message if the ipset binary is missing.
	if _, err := m.lookPath("ipset"); err != nil {
		return fmt.Errorf("ipset is not installed or not on PATH: %w "+
			"(install it with 'apt-get install ipset' or 'dnf install ipset')", err)
	}

	if out, err := m.run("ipset", createArgs...); err != nil {
		return fmt.Errorf("failed to create ipset %q: %v: %s", m.setName, err, strings.TrimSpace(string(out)))
	}

	// Add the DROP rule only if it is not already present, so repeated startups
	// do not stack duplicate jump rules.
	if _, err := m.run("iptables", jumpCheck...); err != nil {
		if out, ierr := m.run("iptables", jumpInsert...); ierr != nil {
			return fmt.Errorf("failed to add iptables jump rule for set %q: %v: %s", m.setName, ierr, strings.TrimSpace(string(out)))
		}
		m.logger.Info("Inserted iptables DROP rule for ipset %q in chain %s", m.setName, m.chain)
	}

	m.logger.Info("ipset %q ready (chain %s, default ban timeout %ds)", m.setName, m.chain, timeout)
	return nil
}

// BlockIP adds an IP to the set with the given ban TTL. A non-positive ttl adds
// the entry without a timeout (a permanent ban). The operation is idempotent.
func (m *IPSetManager) BlockIP(ip, reason string, ttl time.Duration) error {
	if err := checkIPv4(ip); err != nil {
		return err
	}

	timeout := timeoutSeconds(ttl)
	args := []string{"add", m.setName, ip, "timeout", strconv.Itoa(timeout), "-exist"}

	if m.dryRun {
		m.logger.Info("DRY RUN: Would execute: ipset %s", strings.Join(args, " "))
		return nil
	}

	if out, err := m.run("ipset", args...); err != nil {
		return fmt.Errorf("failed to block IP %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}

	m.logger.Info("Successfully blocked IP %s for %ds (%s)", ip, timeout, reason)
	return nil
}

// UnblockIP removes an IP from the set. It is a no-op if the IP is absent.
func (m *IPSetManager) UnblockIP(ip string) error {
	if err := checkIPv4(ip); err != nil {
		return err
	}

	args := []string{"del", m.setName, ip, "-exist"}

	if m.dryRun {
		m.logger.Info("DRY RUN: Would execute: ipset %s", strings.Join(args, " "))
		return nil
	}

	if out, err := m.run("ipset", args...); err != nil {
		return fmt.Errorf("failed to unblock IP %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}

	m.logger.Info("Successfully unblocked IP %s", ip)
	return nil
}

// IsBlocked reports whether the IP is currently present in the set. It uses
// `ipset test`, which exits 0 when the entry is present and 1 when it is not;
// any other failure is returned as an error. In dry-run mode (no real set) it
// always reports false.
func (m *IPSetManager) IsBlocked(ip string) (bool, error) {
	if err := checkIPv4(ip); err != nil {
		return false, err
	}

	if m.dryRun {
		return false, nil
	}

	out, err := m.run("ipset", "test", m.setName, ip)
	if err == nil {
		return true, nil
	}

	// "not in set" is reported as exit status 1 with a "... is NOT in set ..."
	// message; treat that as a clean negative rather than an error.
	output := string(out)
	if strings.Contains(output, "NOT in set") {
		return false, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}

	return false, fmt.Errorf("failed to test IP %s in ipset %q: %v: %s", ip, m.setName, err, strings.TrimSpace(output))
}

// CleanupAutoBlocked clears bans left over from a previous run: it flushes the
// ipset and also removes any legacy per-IP "Auto-blocked" iptables rules written
// by older (pre-ipset) versions, so an upgrade needs no manual firewall cleanup.
// It returns the total number of entries/rules removed.
func (m *IPSetManager) CleanupAutoBlocked() (int, error) {
	if m.dryRun {
		m.logger.Info("DRY RUN: Would flush ipset %q and remove legacy Auto-blocked iptables rules", m.setName)
		return 0, nil
	}

	count := 0
	if ips, err := m.ListBlockedIPs(); err == nil {
		count = len(ips)
	}

	if out, err := m.run("ipset", "flush", m.setName); err != nil {
		return 0, fmt.Errorf("failed to flush ipset %q: %v: %s", m.setName, err, strings.TrimSpace(string(out)))
	}

	legacy, err := m.removeLegacyAutoBlockedRules()
	if err != nil {
		// Don't fail startup over legacy cleanup; the set + jump rule are already
		// in place. Report what we managed to remove.
		m.logger.Error("Failed to remove some legacy Auto-blocked rules: %v", err)
	}
	if legacy > 0 {
		m.logger.Info("Removed %d legacy per-IP Auto-blocked iptables rule(s)", legacy)
	}

	return count + legacy, nil
}

// removeLegacyAutoBlockedRules deletes per-IP DROP rules tagged with the
// "Auto-blocked" comment that older versions inserted directly into the chain.
// It is scoped strictly to that comment, so it never touches the ipset match rule
// or any unrelated firewall rules.
func (m *IPSetManager) removeLegacyAutoBlockedRules() (int, error) {
	out, err := m.run("iptables", "-S", m.chain)
	if err != nil {
		return 0, fmt.Errorf("failed to list %s rules: %v: %s", m.chain, err, strings.TrimSpace(string(out)))
	}

	removed := 0
	var firstErr error
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "Auto-blocked") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "-A" {
			continue
		}
		fields[0] = "-D" // turn the "-A <chain> ..." spec into a delete
		if _, derr := m.run("iptables", fields...); derr != nil {
			if firstErr == nil {
				firstErr = derr
			}
			continue
		}
		removed++
	}

	return removed, firstErr
}

// ListBlockedIPs returns the IPs currently in the set.
func (m *IPSetManager) ListBlockedIPs() ([]string, error) {
	out, err := m.run("ipset", "list", m.setName)
	if err != nil {
		return nil, fmt.Errorf("failed to list ipset %q: %v: %s", m.setName, err, strings.TrimSpace(string(out)))
	}

	var blockedIPs []string
	inMembers := false
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Members are listed after a "Members:" header; each line begins with
		// the IP, optionally followed by "timeout <seconds>".
		if !inMembers {
			if line == "Members:" {
				inMembers = true
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 && isValidIP(fields[0]) {
			blockedIPs = append(blockedIPs, fields[0])
		}
	}

	return blockedIPs, nil
}

// timeoutSeconds converts a ban duration to whole seconds for ipset. A
// non-positive duration maps to 0, which ipset treats as "no timeout".
func timeoutSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// checkIPv4 validates that ip is a usable IPv4 address. The set uses the inet
// family, so IPv6 addresses are rejected with a clear error.
func checkIPv4(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	if parsed.To4() == nil {
		return fmt.Errorf("IPv6 address not supported by inet ipset: %s", ip)
	}
	return nil
}

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}
