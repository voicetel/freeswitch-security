package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// defaultPprofAddr is the loopback-only default for the diagnostics server.
const defaultPprofAddr = "127.0.0.1:6060"

// startPprof exposes the pprof diagnostics endpoints on a dedicated mux bound
// to addr. The handlers are registered explicitly (never on http.DefaultServeMux
// and never on the public API listener) so profiling data cannot leak through
// the service's public surface. The listener is created synchronously so bind
// errors surface to the caller; the serve loop runs in the background.
//
// The returned server has Addr set to the actual bound address (useful when
// addr requests an ephemeral port) and is stopped via its Shutdown method.
// An empty addr falls back to defaultPprofAddr.
func startPprof(addr string) (*http.Server, error) {
	if addr == "" {
		addr = defaultPprofAddr
	}

	var lc net.ListenConfig

	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("pprof listen on %s: %w", addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() { _ = srv.Serve(ln) }()

	return srv, nil
}
