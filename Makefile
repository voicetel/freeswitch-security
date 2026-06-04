# freeswitch-security — build / test / lint workflow.
#
# `make build` produces a static, stripped, path-trimmed binary: CGO is
# disabled (this service has no cgo dependencies), symbols and DWARF debug
# info are stripped (-s -w), -trimpath removes local filesystem paths, and
# -buildvcs=false keeps VCS metadata out of the binary.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GO      ?= go
BIN_DIR := bin
BINARY  := $(BIN_DIR)/freeswitch-security

GOFLAGS ?= -buildvcs=false -trimpath
LDFLAGS := -ldflags "-s -w"

# No cgo dependencies: force it off so the binary is static and builds are
# unaffected by the host toolchain.
export CGO_ENABLED := 0

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

.PHONY: build run clean fmt vet lint test coverage quality bench

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY) .

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
