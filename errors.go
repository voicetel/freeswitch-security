package main

import "errors"

// Sentinel errors. Wrap these with fmt.Errorf("... %w ...", err) to attach
// context; callers can match with errors.Is.
var (
	// ErrCacheInit indicates the cache manager could not be created.
	ErrCacheInit = errors.New("failed to initialize cache")

	// ErrInvalidIP indicates a malformed IP address.
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrIPInTrustedNetwork indicates an attempt to blacklist an IP that lives
	// within a configured trusted CIDR.
	ErrIPInTrustedNetwork = errors.New("cannot blacklist IP in trusted network")

	// ErrIPWhitelisted indicates an attempt to blacklist an IP currently on
	// the whitelist.
	ErrIPWhitelisted = errors.New("cannot blacklist whitelisted IP")

	// ErrTimeoutQueueing indicates a queue send timed out.
	ErrTimeoutQueueing = errors.New("timeout queueing request")

	// ErrTimeoutWaiting indicates the result-await timed out.
	ErrTimeoutWaiting = errors.New("timeout waiting for result")

	// ErrUntrustedPatternExists indicates a duplicate-add of an untrusted pattern.
	ErrUntrustedPatternExists = errors.New("untrusted pattern already exists")

	// ErrUntrustedPatternMissing indicates the pattern was not found.
	ErrUntrustedPatternMissing = errors.New("untrusted pattern not found")

	// ErrUnknownStatusType indicates an internal status request with an
	// unrecognized type.
	ErrUnknownStatusType = errors.New("unknown status type")

	// ErrESLNotConnected indicates a command was attempted while disconnected.
	ErrESLNotConnected = errors.New("not connected to FreeSWITCH ESL")

	// ErrESLCommandNotAllowed indicates an ESL command did not match the allowlist.
	ErrESLCommandNotAllowed = errors.New("command not allowed")
)
