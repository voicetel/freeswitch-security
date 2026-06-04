package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStartPprof_ServesEndpoints(t *testing.T) {
	t.Parallel()

	srv, err := startPprof("127.0.0.1:0")
	if err != nil {
		t.Fatalf("startPprof: %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(ctx)
	})

	// Index must answer on the bound (ephemeral) address.
	resp, err := httpGet(t, "http://"+srv.Addr+"/debug/pprof/cmdline")
	if err != nil {
		t.Fatalf("GET cmdline: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("cmdline status = %d", resp.StatusCode)
	}

	_, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		t.Errorf("reading cmdline body: %v", readErr)
	}

	resp2, err := httpGet(t, "http://"+srv.Addr+"/debug/pprof/")
	if err != nil {
		t.Fatalf("GET index: %v", err)
	}

	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Errorf("index status = %d", resp2.StatusCode)
	}
}

func TestStartPprof_BindError(t *testing.T) {
	t.Parallel()

	_, err := startPprof("256.256.256.256:0")
	if err == nil {
		t.Error("expected bind error for invalid address")
	}
}

func TestStartPprof_DefaultAddr(t *testing.T) {
	t.Parallel()

	// Empty addr falls back to 127.0.0.1:6060. The port may legitimately be
	// busy on a developer machine; both outcomes are valid — what matters is
	// that the default is applied (a bind error must mention it).
	srv, err := startPprof("")
	if err != nil {
		if !strings.Contains(err.Error(), "6060") {
			t.Errorf("bind error does not reference the default port: %v", err)
		}

		return
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = srv.Shutdown(ctx)
	}()

	if !strings.HasSuffix(srv.Addr, ":6060") {
		t.Errorf("Addr = %q, want default port 6060", srv.Addr)
	}
}

// httpGet issues a context-bound GET against a test server.
func httpGet(t *testing.T, url string) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}

	return resp, nil
}
