package main

import (
	"errors"
	"time"
)

// Fake ipset/iptables outputs and error shared by the SecurityManager tests
// that script firewall-command failures.
const (
	fakeOutResourceBusy     = "Resource temporarily unavailable"
	fakeOutPermissionDenied = "Permission denied (you must be root)"
)

var errFakeIPSet = errors.New("fake ipset failure")

// testIPSetName is the set name used by the SecurityManager test fixtures.
const testIPSetName = "fs-test"

// newTestIPSet returns an IPSetManager wired to a no-op runner so SecurityManager
// tests exercise the real BlockIP/UnblockIP code paths without ever invoking the
// host ipset/iptables binaries. Tests that need to observe or script firewall
// commands replace the returned manager's run field with a recordingRunner.
func newTestIPSet() *IPSetManager {
	m := NewIPSetManager("TEST", testIPSetName, time.Hour, false, newIPSetTestLogger())
	m.run = func(_ string, _ ...string) ([]byte, error) { return nil, nil }
	m.lookPath = func(string) (string, error) { return "/usr/sbin/ipset", nil }

	return m
}
