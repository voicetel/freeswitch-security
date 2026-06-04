package main

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// newIPSetTestLogger returns a quiet logger for the ipset manager tests.
func newIPSetTestLogger() *Logger {
	l := &Logger{}
	l.SetLogLevel(LogLevelError)

	return l
}

// recordingRunner captures the commands a manager would execute and returns
// programmable responses, so tests never touch the real ipset/iptables binaries.
type recordingRunner struct {
	calls []string
	fn    func(name string, args []string) ([]byte, error)
}

func (r *recordingRunner) run(name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if r.fn != nil {
		return r.fn(name, args)
	}
	return nil, nil
}

func (r *recordingRunner) findCall(substr string) (string, bool) {
	for _, c := range r.calls {
		if strings.Contains(c, substr) {
			return c, true
		}
	}
	return "", false
}

func newTestManager(r *recordingRunner) *IPSetManager {
	m := NewIPSetManager("INPUT", "fs-test", 60*time.Minute, false, newIPSetTestLogger())
	m.run = r.run
	m.lookPath = func(string) (string, error) { return "/usr/sbin/ipset", nil }
	return m
}

func TestNewIPSetManagerDefaults(t *testing.T) {
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	if m.run == nil {
		t.Fatal("expected a default command runner to be set")
	}
	if m.setName != "fs-test" || m.chain != "INPUT" || !m.dryRun {
		t.Fatalf("unexpected manager fields: %+v", m)
	}
}

func TestEnsureSetupInsertsJumpRuleWhenMissing(t *testing.T) {
	// iptables -C fails (rule absent) -> manager must run iptables -I.
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "iptables" && len(args) > 0 && args[0] == "-C" {
			return nil, fmt.Errorf("rule not found")
		}
		return nil, nil
	}}
	if err := newTestManager(r).EnsureSetup(); err != nil {
		t.Fatalf("EnsureSetup returned error: %v", err)
	}

	create, ok := r.findCall("ipset create fs-test hash:ip family inet")
	if !ok {
		t.Fatalf("expected ipset create call, calls=%v", r.calls)
	}
	for _, want := range []string{"timeout 3600", "-exist"} {
		if !strings.Contains(create, want) {
			t.Errorf("create call %q missing %q", create, want)
		}
	}
	if _, ok := r.findCall("iptables -I INPUT 1 -m set --match-set fs-test src -j DROP"); !ok {
		t.Fatalf("expected iptables insert call, calls=%v", r.calls)
	}
}

func TestEnsureSetupSkipsInsertWhenRulePresent(t *testing.T) {
	// All commands succeed, so iptables -C reports the rule already exists.
	r := &recordingRunner{}
	if err := newTestManager(r).EnsureSetup(); err != nil {
		t.Fatalf("EnsureSetup returned error: %v", err)
	}
	if _, ok := r.findCall("iptables -I"); ok {
		t.Fatalf("did not expect an insert when the rule already exists, calls=%v", r.calls)
	}
}

func TestEnsureSetupDryRunRunsNothing(t *testing.T) {
	r := &recordingRunner{}
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	m.run = r.run
	if err := m.EnsureSetup(); err != nil {
		t.Fatalf("EnsureSetup returned error: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run must not execute commands, calls=%v", r.calls)
	}
}

func TestEnsureSetupMissingIpset(t *testing.T) {
	r := &recordingRunner{}
	m := newTestManager(r)
	m.lookPath = func(string) (string, error) { return "", fmt.Errorf("not found in PATH") }

	err := m.EnsureSetup()
	if err == nil || !strings.Contains(err.Error(), "ipset is not installed") {
		t.Fatalf("expected missing-ipset error, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("must not run any commands when ipset is missing, calls=%v", r.calls)
	}
}

func TestEnsureSetupCreateError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("kernel error"), fmt.Errorf("boom")
	}}
	if err := newTestManager(r).EnsureSetup(); err == nil {
		t.Fatal("expected EnsureSetup to fail when ipset create fails")
	}
}

func TestEnsureSetupInsertError(t *testing.T) {
	// ipset create succeeds, iptables -C reports the rule absent, and iptables -I
	// then fails -> EnsureSetup must surface the insert error.
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "iptables" && len(args) > 0 {
			return []byte("iptables failure"), fmt.Errorf("exit 1")
		}
		return nil, nil
	}}
	if err := newTestManager(r).EnsureSetup(); err == nil {
		t.Fatal("expected EnsureSetup to fail when the iptables insert fails")
	}
}

func TestBlockIP(t *testing.T) {
	tests := []struct {
		name        string
		ttl         time.Duration
		wantTimeout string
	}{
		{"finite ttl", 60 * time.Second, "timeout 60"},
		{"sub-second ttl rounds up", 500 * time.Millisecond, "timeout 1"},
		{"zero ttl is permanent", 0, "timeout 0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := &recordingRunner{}
			if err := newTestManager(r).BlockIP("203.0.113.5", "TEST", tc.ttl); err != nil {
				t.Fatalf("BlockIP returned error: %v", err)
			}
			call, ok := r.findCall("ipset add fs-test 203.0.113.5")
			if !ok {
				t.Fatalf("expected ipset add call, calls=%v", r.calls)
			}
			if !strings.Contains(call, tc.wantTimeout) || !strings.Contains(call, "-exist") {
				t.Errorf("add call %q missing %q or -exist", call, tc.wantTimeout)
			}
		})
	}
}

func TestBlockIPInvalid(t *testing.T) {
	r := &recordingRunner{}
	if err := newTestManager(r).BlockIP("not-an-ip", "TEST", time.Minute); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if len(r.calls) != 0 {
		t.Fatalf("must not run commands for invalid IP, calls=%v", r.calls)
	}
}

func TestBlockIPRejectsIPv6(t *testing.T) {
	r := &recordingRunner{}
	err := newTestManager(r).BlockIP("2001:db8::1", "TEST", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("expected IPv6 rejection error, got %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("must not run commands for IPv6, calls=%v", r.calls)
	}
}

func TestBlockIPDryRun(t *testing.T) {
	r := &recordingRunner{}
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	m.run = r.run
	if err := m.BlockIP("203.0.113.5", "TEST", time.Minute); err != nil {
		t.Fatalf("BlockIP returned error: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run must not execute commands, calls=%v", r.calls)
	}
}

func TestBlockIPRunError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("set full"), fmt.Errorf("exit 1")
	}}
	if err := newTestManager(r).BlockIP("203.0.113.5", "TEST", time.Minute); err == nil {
		t.Fatal("expected BlockIP to propagate runner error")
	}
}

func TestExecRunner(t *testing.T) {
	if _, err := execRunner("true"); err != nil {
		t.Errorf("execRunner(true) error: %v", err)
	}
	if _, err := execRunner("false"); err == nil {
		t.Error("execRunner(false) should error")
	}
}

func TestUnblockIP(t *testing.T) {
	r := &recordingRunner{}
	if err := newTestManager(r).UnblockIP("203.0.113.5"); err != nil {
		t.Fatalf("UnblockIP returned error: %v", err)
	}
	if _, ok := r.findCall("ipset del fs-test 203.0.113.5 -exist"); !ok {
		t.Fatalf("expected ipset del call, calls=%v", r.calls)
	}
}

func TestUnblockIPInvalid(t *testing.T) {
	r := &recordingRunner{}
	if err := newTestManager(r).UnblockIP("nope"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if len(r.calls) != 0 {
		t.Fatalf("must not run commands for invalid IP, calls=%v", r.calls)
	}
}

func TestUnblockIPDryRun(t *testing.T) {
	r := &recordingRunner{}
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	m.run = r.run
	if err := m.UnblockIP("203.0.113.5"); err != nil {
		t.Fatalf("UnblockIP returned error: %v", err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run must not execute commands, calls=%v", r.calls)
	}
}

func TestUnblockIPRunError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("no such set"), fmt.Errorf("exit 1")
	}}
	if err := newTestManager(r).UnblockIP("203.0.113.5"); err == nil {
		t.Fatal("expected UnblockIP to propagate runner error")
	}
}

func TestIsBlockedInSet(t *testing.T) {
	// ipset test exits 0 (no error) when the entry is present.
	r := &recordingRunner{}
	blocked, err := newTestManager(r).IsBlocked("203.0.113.5")
	if err != nil {
		t.Fatalf("IsBlocked returned error: %v", err)
	}
	if !blocked {
		t.Error("expected IP to be reported as blocked")
	}
	if _, ok := r.findCall("ipset test fs-test 203.0.113.5"); !ok {
		t.Fatalf("expected ipset test call, calls=%v", r.calls)
	}
}

func TestIsBlockedNotInSet(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("203.0.113.5 is NOT in set fs-test"), fmt.Errorf("exit status 1")
	}}
	blocked, err := newTestManager(r).IsBlocked("203.0.113.5")
	if err != nil {
		t.Fatalf("IsBlocked returned error: %v", err)
	}
	if blocked {
		t.Error("expected IP to be reported as not blocked")
	}
}

func TestIsBlockedExitStatus1(t *testing.T) {
	// A real ExitError with code 1 and no "NOT in set" text must still be read as
	// "not blocked" via the errors.As exit-code branch.
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return exec.Command("false").CombinedOutput()
	}}
	blocked, err := newTestManager(r).IsBlocked("203.0.113.5")
	if err != nil {
		t.Fatalf("IsBlocked returned error: %v", err)
	}
	if blocked {
		t.Error("expected IP to be reported as not blocked")
	}
}

func TestIsBlockedError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("The set with the given name does not exist"), fmt.Errorf("exit status 2")
	}}
	if _, err := newTestManager(r).IsBlocked("203.0.113.5"); err == nil {
		t.Fatal("expected error when ipset test fails for a non-membership reason")
	}
}

func TestIsBlockedInvalid(t *testing.T) {
	r := &recordingRunner{}
	if _, err := newTestManager(r).IsBlocked("nope"); err == nil {
		t.Fatal("expected error for invalid IP")
	}
	if len(r.calls) != 0 {
		t.Fatalf("must not run commands for invalid IP, calls=%v", r.calls)
	}
}

func TestIsBlockedIPv6(t *testing.T) {
	r := &recordingRunner{}
	if _, err := newTestManager(r).IsBlocked("2001:db8::1"); err == nil {
		t.Fatal("expected error for IPv6")
	}
}

func TestIsBlockedDryRun(t *testing.T) {
	r := &recordingRunner{}
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	m.run = r.run
	blocked, err := m.IsBlocked("203.0.113.5")
	if err != nil || blocked {
		t.Fatalf("dry run IsBlocked should be (false, nil), got (%v, %v)", blocked, err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run must not execute commands, calls=%v", r.calls)
	}
}

func TestCleanupAutoBlocked(t *testing.T) {
	members := "Name: fs-test\nType: hash:ip\nHeader: family inet\nMembers:\n203.0.113.5 timeout 120\n203.0.113.6 timeout 80\n"
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if len(args) > 0 && args[0] == "list" {
			return []byte(members), nil
		}
		return nil, nil
	}}
	count, err := newTestManager(r).CleanupAutoBlocked()
	if err != nil {
		t.Fatalf("CleanupAutoBlocked returned error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
	if _, ok := r.findCall("ipset flush fs-test"); !ok {
		t.Fatalf("expected flush call, calls=%v", r.calls)
	}
}

func TestCleanupAutoBlockedDryRun(t *testing.T) {
	r := &recordingRunner{}
	m := NewIPSetManager("INPUT", "fs-test", time.Minute, true, newIPSetTestLogger())
	m.run = r.run
	count, err := m.CleanupAutoBlocked()
	if err != nil || count != 0 {
		t.Fatalf("dry run cleanup should be no-op, got count=%d err=%v", count, err)
	}
	if len(r.calls) != 0 {
		t.Fatalf("dry run must not execute commands, calls=%v", r.calls)
	}
}

func TestCleanupAutoBlockedFlushError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if len(args) > 0 && args[0] == "flush" {
			return []byte("no such set"), fmt.Errorf("exit 1")
		}
		return nil, nil
	}}
	if _, err := newTestManager(r).CleanupAutoBlocked(); err == nil {
		t.Fatal("expected error when flush fails")
	}
}

// legacyChainDump mimics `iptables -S INPUT` with two legacy Auto-blocked rules,
// the ipset match rule, and an unrelated rule that must be left untouched.
const legacyChainDump = "-P INPUT ACCEPT\n" +
	"-A INPUT -s 47.254.151.115/32 -m comment --comment Auto-blocked-1780451149 -j DROP\n" +
	"-A INPUT -m set --match-set fs-test src -j DROP\n" +
	"-A INPUT -s 185.243.5.80/32 -m comment --comment Auto-blocked-1780448607 -j DROP\n" +
	"-A INPUT -p tcp --dport 22 -j ACCEPT\n"

func TestRemoveLegacyAutoBlockedRules(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "iptables" && len(args) > 1 && args[0] == "-S" {
			return []byte(legacyChainDump), nil
		}
		return nil, nil
	}}
	removed, err := newTestManager(r).removeLegacyAutoBlockedRules()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if removed != 2 {
		t.Errorf("expected 2 legacy rules removed, got %d", removed)
	}
	// The two Auto-blocked rules are deleted...
	if _, ok := r.findCall("iptables -D INPUT -s 47.254.151.115/32"); !ok {
		t.Errorf("expected delete of first legacy rule, calls=%v", r.calls)
	}
	// ...but the match-set rule and the SSH ACCEPT rule are not.
	if _, ok := r.findCall("--match-set fs-test src -j DROP"); ok {
		if c, _ := r.findCall("-D INPUT -m set"); c != "" {
			t.Errorf("must not delete the ipset match rule: %s", c)
		}
	}
	if _, ok := r.findCall("--dport 22"); ok {
		t.Error("must not touch unrelated ACCEPT rules")
	}
}

func TestRemoveLegacyAutoBlockedRulesListError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("iptables unavailable"), fmt.Errorf("exit 1")
	}}
	if _, err := newTestManager(r).removeLegacyAutoBlockedRules(); err == nil {
		t.Fatal("expected error when iptables -S fails")
	}
}

func TestRemoveLegacyAutoBlockedRulesDeleteError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "iptables" && len(args) > 1 && args[0] == "-S" {
			return []byte(legacyChainDump), nil
		}
		if name == "iptables" && len(args) > 0 && args[0] == "-D" {
			return []byte("no such rule"), fmt.Errorf("exit 1")
		}
		return nil, nil
	}}
	removed, err := newTestManager(r).removeLegacyAutoBlockedRules()
	if err == nil {
		t.Fatal("expected the delete error to be surfaced")
	}
	if removed != 0 {
		t.Errorf("expected 0 removed when deletes fail, got %d", removed)
	}
}

func TestCleanupAutoBlockedRemovesLegacyRules(t *testing.T) {
	members := "Name: fs-test\nType: hash:ip\nMembers:\n203.0.113.5 timeout 120\n"
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "ipset" && len(args) > 0 && args[0] == "list" {
			return []byte(members), nil
		}
		if name == "iptables" && len(args) > 1 && args[0] == "-S" {
			return []byte(legacyChainDump), nil
		}
		return nil, nil
	}}
	count, err := newTestManager(r).CleanupAutoBlocked()
	if err != nil {
		t.Fatalf("CleanupAutoBlocked error: %v", err)
	}
	if count != 3 { // 1 ipset entry + 2 legacy rules
		t.Errorf("expected total 3 removed, got %d", count)
	}
}

func TestCleanupAutoBlockedLegacyErrorDoesNotFail(t *testing.T) {
	// Flush succeeds but the legacy iptables listing fails; cleanup must log and
	// continue rather than failing startup.
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		if name == "iptables" {
			return []byte("iptables unavailable"), fmt.Errorf("exit 1")
		}
		return nil, nil
	}}
	if _, err := newTestManager(r).CleanupAutoBlocked(); err != nil {
		t.Errorf("legacy cleanup failure should not fail CleanupAutoBlocked, got %v", err)
	}
}

func TestListBlockedIPs(t *testing.T) {
	out := "Name: fs-test\nType: hash:ip\nRevision: 4\nHeader: family inet hashsize 4096\nSize in memory: 200\nReferences: 1\nMembers:\n\n203.0.113.5 timeout 120\nnot-an-ip junk\n203.0.113.6\n"
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte(out), nil
	}}
	ips, err := newTestManager(r).ListBlockedIPs()
	if err != nil {
		t.Fatalf("ListBlockedIPs returned error: %v", err)
	}
	want := []string{"203.0.113.5", "203.0.113.6"}
	if len(ips) != len(want) {
		t.Fatalf("expected %v, got %v", want, ips)
	}
	for i := range want {
		if ips[i] != want[i] {
			t.Errorf("index %d: expected %s, got %s", i, want[i], ips[i])
		}
	}
}

func TestListBlockedIPsError(t *testing.T) {
	r := &recordingRunner{fn: func(name string, args []string) ([]byte, error) {
		return []byte("set not found"), fmt.Errorf("exit 1")
	}}
	if _, err := newTestManager(r).ListBlockedIPs(); err == nil {
		t.Fatal("expected error when ipset list fails")
	}
}

func TestTimeoutSeconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int
	}{
		{0, 0},
		{-5 * time.Second, 0},
		{500 * time.Millisecond, 1},
		{60 * time.Second, 60},
		{90 * time.Minute, 5400},
	}
	for _, tc := range tests {
		if got := timeoutSeconds(tc.in); got != tc.want {
			t.Errorf("timeoutSeconds(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestCheckIPv4(t *testing.T) {
	if err := checkIPv4("192.0.2.1"); err != nil {
		t.Errorf("expected valid IPv4 to pass, got %v", err)
	}
	if err := checkIPv4("garbage"); err == nil {
		t.Error("expected invalid IP to fail")
	}
	if err := checkIPv4("2001:db8::1"); err == nil {
		t.Error("expected IPv6 to fail")
	}
}
