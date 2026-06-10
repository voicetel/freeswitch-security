# freeswitch-security — build / test / lint workflow.
#
# `make build` produces a static, stripped, path-trimmed binary: CGO is
# disabled (this service has no cgo dependencies), symbols and DWARF debug
# info are stripped (-s -w), and -trimpath removes local filesystem paths.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GO      ?= go
BIN_DIR := bin
BINARY  := $(BIN_DIR)/freeswitch-security

# Build-time version metadata, injected into package main via -ldflags -X.
# VERSION is the git tag (or a -dirty/commit fallback); override by setting it
# on the command line (e.g. `make build VERSION=v1.5.3`).
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X main.version=$(VERSION) \
	-X main.gitCommit=$(GIT_COMMIT) \
	-X main.buildTime=$(BUILD_TIME)

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

.PHONY: build run clean fmt vet lint test coverage quality bench

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

run: build
	./$(BINARY)

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html
	rm -f freeswitch-security freeswitch-security.test

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

# The race detector requires cgo; re-enable it per-target.
test:
	CGO_ENABLED=1 $(GO) test -race ./...

coverage:
	CGO_ENABLED=1 $(GO) test -race -covermode=atomic -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

# Full quality chain: formatting check (non-mutating), vet, lint, race
# tests with coverage.
quality:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt: needs formatting:"; echo "$$unformatted"; exit 1; \
	fi
	$(MAKE) vet lint coverage

bench:
	CGO_ENABLED=1 $(GO) test . -run='^$$' -bench=. -benchmem -benchtime=0.3s -count=10
