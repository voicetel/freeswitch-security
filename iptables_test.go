package main

import (
	"strings"
	"sync"
	"testing"
)

// argsHaveFlag reports whether the iptables argv starts with the given flag.
func argsHaveFlag(args []string, flag string) bool {
	return len(args) > 0 && args[0] == flag
}

func TestRunIptablesWithRetry_XtablesLockRetry(t *testing.T) {
	t.Parallel()

	const chain = "TEST_RETRY_LOCK"

	var (
		mu    sync.Mutex
		calls int
	)

	registerIptablesBehavior(t, chain, func(_ []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		calls++

		if calls == 1 {
			return "Another app is currently holding the xtables lock", 4
		}

		return "", 0
	})

	out, err := runIptablesWithRetry("-S", chain)
	if err != nil {
		t.Fatalf("expected success after lock retry, got err=%v out=%s", err, out)
	}

	mu.Lock()
	defer mu.Unlock()

	if calls != 2 {
		t.Errorf("expected 2 attempts (1 lock + 1 success), got %d", calls)
	}
}

func TestRunIptablesWithRetry_NonRetryableFailure(t *testing.T) {
	t.Parallel()

	const chain = "TEST_RETRY_FATAL"

	var (
		mu    sync.Mutex
		calls int
	)

	registerIptablesBehavior(t, chain, func(_ []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		calls++

		return "No chain/target/match by that name", 1
	})

	out, err := runIptablesWithRetry("-S", chain)
	if err == nil {
		t.Fatal("expected error for non-retryable failure")
	}

	if !strings.Contains(string(out), "No chain") {
		t.Errorf("expected output to be preserved, got %q", out)
	}

	mu.Lock()
	defer mu.Unlock()

	if calls != 1 {
		t.Errorf("non-retryable failure must not retry; got %d attempts", calls)
	}
}

func TestEnsureIPTablesChain_AlreadyExists(t *testing.T) {
	t.Parallel()

	const chain = "TEST_ENSURE_EXISTS"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		if argsHaveFlag(args, "-L") {
			return "", 0 // chain exists
		}

		return "", 1
	})

	err := ensureIPTablesChain(chain)
	if err != nil {
		t.Errorf("ensureIPTablesChain on existing chain: %v", err)
	}
}

func TestEnsureIPTablesChain_Creates(t *testing.T) {
	t.Parallel()

	const chain = "TEST_ENSURE_CREATE"

	var (
		mu      sync.Mutex
		created bool
		linked  bool
	)

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case argsHaveFlag(args, "-L"):
			return "", 1 // chain missing
		case argsHaveFlag(args, "-N"):
			created = true

			return "", 0
		case argsHaveFlag(args, "-A"):
			linked = true

			return "", 0
		default:
			return "", 1
		}
	})

	err := ensureIPTablesChain(chain)
	if err != nil {
		t.Fatalf("ensureIPTablesChain: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !created || !linked {
		t.Errorf("expected chain creation and INPUT link; created=%v linked=%v", created, linked)
	}
}

func TestEnsureIPTablesChain_ToleratesConcurrentCreate(t *testing.T) {
	t.Parallel()

	const chain = "TEST_ENSURE_RACE"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		switch {
		case argsHaveFlag(args, "-L"):
			return "", 1
		case argsHaveFlag(args, "-N"):
			// Lost the race with another process; not an error.
			return "iptables: Chain already exists.", 1
		case argsHaveFlag(args, "-A"):
			return "", 0
		default:
			return "", 1
		}
	})

	err := ensureIPTablesChain(chain)
	if err != nil {
		t.Errorf("expected 'Chain already exists' to be tolerated: %v", err)
	}
}

func TestEnsureIPTablesChain_CreateFails(t *testing.T) {
	t.Parallel()

	const chain = "TEST_ENSURE_CREATE_FAIL"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		if argsHaveFlag(args, "-N") {
			return fakeOutPermissionDenied, 1
		}

		return "", 1
	})

	err := ensureIPTablesChain(chain)
	if err == nil {
		t.Error("expected error when chain creation fails")
	}
}

func TestEnsureIPTablesChain_LinkFails(t *testing.T) {
	t.Parallel()

	const chain = "TEST_ENSURE_LINK_FAIL"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		switch {
		case argsHaveFlag(args, "-N"):
			return "", 0
		case argsHaveFlag(args, "-A"):
			return fakeOutPermissionDenied, 1
		default:
			return "", 1
		}
	})

	err := ensureIPTablesChain(chain)
	if err == nil {
		t.Error("expected error when INPUT link fails")
	}
}

func TestBlockIPWithIptables_AlreadyBlocked(t *testing.T) {
	t.Parallel()

	const chain = "TEST_BLOCK_DUP"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		if argsHaveFlag(args, "-C") {
			return "", 0 // rule already present
		}

		return "", 1
	})

	err := blockIPWithIptables("203.0.113.1", chain)
	if err != nil {
		t.Errorf("already-blocked IP must not error: %v", err)
	}
}

func TestBlockIPWithIptables_Blocks(t *testing.T) {
	t.Parallel()

	const chain = "TEST_BLOCK_OK"

	var (
		mu       sync.Mutex
		appended bool
	)

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case argsHaveFlag(args, "-C"):
			return "", 1 // not yet blocked
		case argsHaveFlag(args, "-A"):
			appended = true

			return "", 0
		default:
			return "", 1
		}
	})

	err := blockIPWithIptables("203.0.113.2", chain)
	if err != nil {
		t.Fatalf("blockIPWithIptables: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !appended {
		t.Error("expected -A DROP rule to be installed")
	}
}

func TestBlockIPWithIptables_Fails(t *testing.T) {
	t.Parallel()

	const chain = "TEST_BLOCK_FAIL"

	registerIptablesBehavior(t, chain, func(_ []string) (string, int) {
		return fakeOutPermissionDenied, 1
	})

	err := blockIPWithIptables("203.0.113.3", chain)
	if err == nil {
		t.Error("expected error when -A fails")
	}
}

func TestUnblockIPWithIptables_NotBlocked(t *testing.T) {
	t.Parallel()

	const chain = "TEST_UNBLOCK_MISSING"

	registerIptablesBehavior(t, chain, func(_ []string) (string, int) {
		return "", 1 // -C says rule absent
	})

	err := unblockIPWithIptables("203.0.113.4", chain)
	if err != nil {
		t.Errorf("unblocking an absent rule must be a no-op: %v", err)
	}
}

func TestUnblockIPWithIptables_Unblocks(t *testing.T) {
	t.Parallel()

	const chain = "TEST_UNBLOCK_OK"

	var (
		mu      sync.Mutex
		deleted bool
	)

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case argsHaveFlag(args, "-C"):
			return "", 0 // rule exists
		case argsHaveFlag(args, "-D"):
			deleted = true

			return "", 0
		default:
			return "", 1
		}
	})

	err := unblockIPWithIptables("203.0.113.5", chain)
	if err != nil {
		t.Fatalf("unblockIPWithIptables: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !deleted {
		t.Error("expected -D to be invoked")
	}
}

func TestUnblockIPWithIptables_RuleVanished(t *testing.T) {
	t.Parallel()

	cases := []struct {
		chain  string
		output string
	}{
		{"TEST_UNBLOCK_BADRULE", "iptables: Bad rule (does a matching rule exist in that chain?)."},
		{"TEST_UNBLOCK_NOMATCH", "does a matching rule exist in that chain?"},
	}

	for _, tc := range cases {
		registerIptablesBehavior(t, tc.chain, func(args []string) (string, int) {
			if argsHaveFlag(args, "-C") {
				return "", 0 // claims to exist...
			}

			return tc.output, 1 // ...but vanishes before -D
		})

		err := unblockIPWithIptables("203.0.113.6", tc.chain)
		if err != nil {
			t.Errorf("chain %s: rule-vanished must be treated as success: %v", tc.chain, err)
		}
	}
}

func TestUnblockIPWithIptables_DeleteFails(t *testing.T) {
	t.Parallel()

	const chain = "TEST_UNBLOCK_FAIL"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		if argsHaveFlag(args, "-C") {
			return "", 0
		}

		return fakeOutResourceBusy, 1
	})

	err := unblockIPWithIptables("203.0.113.7", chain)
	if err == nil {
		t.Error("expected error when -D fails for a real reason")
	}
}

func TestGetIPTablesRules(t *testing.T) {
	t.Parallel()

	const chain = "TEST_LIST_OK"

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		if argsHaveFlag(args, "-S") {
			return "-N " + chain + "\n-A " + chain + " -s 203.0.113.9/32 -j DROP\n", 0
		}

		return "", 1
	})

	rules, err := getIPTablesRules(chain)
	if err != nil {
		t.Fatalf("getIPTablesRules: %v", err)
	}

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (empty lines skipped), got %d: %v", len(rules), rules)
	}

	if !strings.Contains(rules[1], "DROP") {
		t.Errorf("unexpected rule content: %v", rules)
	}
}

func TestGetIPTablesRules_Error(t *testing.T) {
	t.Parallel()

	_, err := getIPTablesRules("TEST_LIST_UNREGISTERED")
	if err == nil {
		t.Error("expected error for unknown chain")
	}
}

func TestGetIPTablesInfo(t *testing.T) {
	t.Parallel()

	const chain = "TEST_INFO_OK"

	registerIptablesBehavior(t, chain, func(_ []string) (string, int) {
		return "-N " + chain + "\n", 0
	})

	sm := newTestSecurityManager(t)
	sm.cfg.IPTablesChain = chain

	info, err := sm.GetIPTablesInfo()
	if err != nil {
		t.Fatalf("GetIPTablesInfo: %v", err)
	}

	if info["chain"] != chain {
		t.Errorf("chain = %v, want %s", info["chain"], chain)
	}

	rules, ok := info["rules"].([]string)
	if !ok || len(rules) != 1 {
		t.Errorf("unexpected rules payload: %#v", info["rules"])
	}
}

func TestGetIPTablesInfo_Error(t *testing.T) {
	t.Parallel()

	sm := newTestSecurityManager(t)
	sm.cfg.IPTablesChain = "TEST_INFO_UNREGISTERED"

	_, err := sm.GetIPTablesInfo()
	if err == nil {
		t.Error("expected error when listing fails")
	}
}

func TestBatchBlockIPs(t *testing.T) {
	t.Parallel()

	const chain = "TEST_BATCH_BLOCK"

	var (
		mu      sync.Mutex
		blocked []string
	)

	registerIptablesBehavior(t, chain, func(args []string) (string, int) {
		mu.Lock()
		defer mu.Unlock()

		switch {
		case argsHaveFlag(args, "-C"):
			return "", 1
		case argsHaveFlag(args, "-A"):
			// args: -A chain -s ip -j DROP
			if len(args) >= 4 && args[3] == "203.0.113.66" {
				return "Permission denied", 1 // one IP fails; loop must continue
			}

			blocked = append(blocked, args[3])

			return "", 0
		default:
			return "", 1
		}
	})

	sm := newTestSecurityManager(t)
	sm.cfg.IPTablesChain = chain

	sm.batchBlockIPs(nil) // empty input: early return, no exec
	sm.batchBlockIPs([]string{"203.0.113.65", "203.0.113.66", "203.0.113.67"})

	mu.Lock()
	defer mu.Unlock()

	if len(blocked) != 2 {
		t.Errorf("expected 2 successful blocks despite mid-batch failure, got %v", blocked)
	}
}
