package main

import (
	"context"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"sync"
	"testing"
)

// The iptables helpers spawn processes through the execCommand seam. For the
// whole test binary we replace that seam with a dispatcher (installed in
// TestMain, before any test runs) so no test can ever touch the host's real
// iptables state.
//
// Tests opt into specific behavior by registering a handler under a unique
// chain name; the dispatcher routes an invocation to the handler whose chain
// name appears in the argv. Unmatched invocations fail with exit code 1 and
// empty output, which models "chain/rule does not exist" and a missing or
// unprivileged iptables binary.

// Common fake iptables outputs shared by the behavior tests.
const (
	fakeOutPermissionDenied = "Permission denied (you must be root)"
	fakeOutResourceBusy     = "Resource temporarily unavailable"
)

// iptablesBehavior maps an iptables argv to (combined output, exit code).
type iptablesBehavior func(args []string) (string, int)

var (
	fakeExecMu        sync.RWMutex
	fakeExecBehaviors = map[string]iptablesBehavior{}
)

// registerIptablesBehavior installs fn for invocations mentioning chain and
// removes it when the test finishes. Chain names must be unique per test so
// parallel tests cannot observe each other's behavior.
func registerIptablesBehavior(tb testing.TB, chain string, fn iptablesBehavior) {
	tb.Helper()

	fakeExecMu.Lock()
	if _, dup := fakeExecBehaviors[chain]; dup {
		fakeExecMu.Unlock()
		tb.Fatalf("iptables behavior for chain %q already registered", chain)

		return
	}

	fakeExecBehaviors[chain] = fn
	fakeExecMu.Unlock()

	tb.Cleanup(func() {
		fakeExecMu.Lock()
		delete(fakeExecBehaviors, chain)
		fakeExecMu.Unlock()
	})
}

// dispatchIptables resolves the behavior for the given argv.
func dispatchIptables(args []string) (string, int) {
	fakeExecMu.RLock()
	defer fakeExecMu.RUnlock()

	for chain, fn := range fakeExecBehaviors {
		if slices.Contains(args, chain) {
			return fn(args)
		}
	}

	return "", 1
}

// fakeExecCommand is the test-binary-wide replacement for execCommand. It
// emits the scripted output/exit-code through a tiny shell so the production
// code still exercises its real CombinedOutput()/Run() paths.
func fakeExecCommand(name string, args ...string) *exec.Cmd {
	if name != "iptables" {
		return exec.CommandContext(context.Background(), name, args...)
	}

	out, code := dispatchIptables(args)

	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", `printf '%s' "$FAKE_IPTABLES_OUT"; exit "$FAKE_IPTABLES_CODE"`)

	cmd.Env = append(os.Environ(),
		"FAKE_IPTABLES_OUT="+out,
		"FAKE_IPTABLES_CODE="+strconv.Itoa(code))

	return cmd
}
