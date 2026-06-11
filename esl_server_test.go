package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/fiorix/go-eventsocket/eventsocket"
	"github.com/gin-gonic/gin"
)

// fakeESL is a minimal in-process FreeSWITCH event-socket server. It speaks
// just enough of the wire protocol for the eventsocket client used by
// ESLManager: auth handshake, command/reply for every command, and
// text/event-plain event delivery.
type fakeESL struct {
	tb         testing.TB
	ln         net.Listener
	password   string
	rejectAuth bool
	replyError bool
	apiBody    string // when set, "api ..." commands get an api/response with this body

	mu       sync.Mutex
	conns    []net.Conn
	commands []string
}

func newFakeESL(tb testing.TB) *fakeESL {
	tb.Helper()

	var lc net.ListenConfig

	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("fake ESL listen: %v", err)
	}

	srv := &fakeESL{tb: tb, ln: ln, password: testESLPassword}

	go srv.acceptLoop()

	tb.Cleanup(srv.close)

	return srv
}

func (s *fakeESL) hostPort() (string, string) {
	host, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		s.tb.Fatalf("split fake ESL addr: %v", err)
	}

	return host, port
}

func (s *fakeESL) close() {
	_ = s.ln.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.conns {
		_ = c.Close()
	}
}

func (s *fakeESL) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}

		s.mu.Lock()
		s.conns = append(s.conns, conn)
		s.mu.Unlock()

		go s.handle(conn)
	}
}

// readESLCommand reads one client command: lines up to the first empty line.
func readESLCommand(reader *bufio.Reader) (string, error) {
	var cmd string

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading ESL command line: %w", err)
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return cmd, nil
		}

		if cmd == "" {
			cmd = line
		}
	}
}

// writef serializes all writes to a connection so server replies and
// test-injected events never interleave mid-message.
func (s *fakeESL) writef(conn net.Conn, format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fmt.Fprintf(conn, format, args...)
}

func (s *fakeESL) handle(conn net.Conn) {
	reader := bufio.NewReader(conn)

	s.writef(conn, "Content-Type: auth/request\n\n")

	cmd, err := readESLCommand(reader)
	if err != nil {
		return
	}

	if s.rejectAuth || cmd != "auth "+s.password {
		s.writef(conn, "Content-Type: command/reply\nReply-Text: -ERR invalid\n\n")
		_ = conn.Close()

		return
	}

	s.writef(conn, "Content-Type: command/reply\nReply-Text: +OK accepted\n\n")

	for {
		cmd, err := readESLCommand(reader)
		if err != nil {
			return
		}

		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		s.mu.Unlock()

		switch {
		case s.apiBody != "" && strings.HasPrefix(cmd, "api "):
			s.writef(conn, "Content-Type: api/response\nContent-Length: %d\n\n%s", len(s.apiBody), s.apiBody)
		case s.replyError:
			s.writef(conn, "Content-Type: command/reply\nReply-Text: -ERR denied\n\n")
		default:
			s.writef(conn, "Content-Type: command/reply\nReply-Text: +OK %s\n\n", cmd)
		}
	}
}

// sendEvent pushes a text/event-plain message to the most recent connection.
func (s *fakeESL) sendEvent(headers map[string]string) {
	var sb strings.Builder
	for k, v := range headers {
		fmt.Fprintf(&sb, "%s: %s\n", k, v)
	}

	sb.WriteString("\n")
	body := sb.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.conns) == 0 {
		s.tb.Error("sendEvent: no connection")

		return
	}

	conn := s.conns[len(s.conns)-1]
	fmt.Fprintf(conn, "Content-Type: text/event-plain\nContent-Length: %d\n\n%s", len(body), body)
}

// commandSeen reports whether any received command contains substr.
func (s *fakeESL) commandSeen(substr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, c := range s.commands {
		if strings.Contains(c, substr) {
			return true
		}
	}

	return false
}

// newServerESLManager builds an ESLManager wired to the fake server and runs
// its real connection loop and worker pool.
func newServerESLManager(tb testing.TB, srv *fakeESL, workers, queueSize int) *ESLManager {
	tb.Helper()

	sm := newTestSecurityManager(tb)
	rm := newTestRateManager(tb, sm, defaultTestRateConfig())
	host, port := srv.hostPort()

	ctx, cancel := context.WithCancel(context.Background())
	em := &ESLManager{
		securityManager: sm,
		eslConfig: ESLConfig{
			Host:             host,
			Port:             port,
			Password:         testESLPassword,
			LogLevel:         logLevelErrorStr,
			ReconnectBackoff: "50ms",
			WorkerCount:      workers,
		},
		eslDisconnected: make(chan bool, 1),
		rateManager:     rm,
		queueSize:       queueSize,
		workerCount:     workers,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()

	em.readersWg.Add(1)
	go em.startESLConnection()

	tb.Cleanup(em.Shutdown)

	return em
}

func TestESLManager_ConnectSubscribeProcess(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 2, 64)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected to fake ESL server")
	}

	// subscribeToEvents must have registered all four event subscriptions.
	if !waitFor(func() bool { return srv.commandSeen(eventSubRegisterFail) }) {
		t.Error("expected register_failure subscription")
	}

	if !srv.commandSeen(eventNameChannelCreate) {
		t.Error("expected CHANNEL_CREATE subscription")
	}

	// Deliver a failed-registration event through the real read path and
	// verify it flows queue → worker → security manager.
	srv.sendEvent(map[string]string{
		hdrEventName:     eventNameCustom,
		hdrEventSubclass: eventSubRegisterFail,
		hdrNetworkIP:     "203.0.113.150",
		hdrToUser:        testUserVictim,
		hdrToHost:        testDomainVictim,
	})

	if !waitFor(func() bool {
		_, ok := em.securityManager.GetFailedAttempts()["203.0.113.150"]

		return ok
	}) {
		t.Error("event did not flow through queue/worker into security manager")
	}

	if em.statistics.EventsProcessed.Load() == 0 {
		t.Error("EventsProcessed not incremented")
	}

	stats := em.GetESLStats()
	if stats["connected"] != true {
		t.Errorf("GetESLStats connected = %v, want true", stats["connected"])
	}
}

func TestESLManager_SendCommand(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	// Allowed command (config.json allows testCmdStatus).
	resp, err := em.SendCommand(testCmdStatus)
	if err != nil {
		t.Fatalf("SendCommand(status): %v", err)
	}

	if !strings.Contains(resp, "+OK") {
		t.Errorf("unexpected response %q", resp)
	}

	// Disallowed command never reaches the wire.
	_, denyErr := em.SendCommand("reload mod_sofia")
	if denyErr == nil {
		t.Error("expected ErrESLCommandNotAllowed for disallowed command")
	}

	if srv.commandSeen("reload") {
		t.Error("disallowed command must not be sent to the server")
	}
}

func TestESLManager_SendCommand_NotConnected(t *testing.T) {
	t.Parallel()

	em := &ESLManager{}

	_, err := em.SendCommand(testCmdStatus)
	if err == nil {
		t.Error("expected ErrESLNotConnected")
	}
}

func TestESLManager_Reconnect(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	em.ReconnectESL()

	// Connection drops, then the loop redials after the 50ms backoff.
	if !waitFor(func() bool { return !em.IsConnected() }) {
		t.Fatal("expected disconnect after ReconnectESL")
	}

	if !waitFor(em.IsConnected) {
		t.Fatal("manager did not reconnect after forced disconnect")
	}
}

func TestESLManager_ReconnectESL_NotConnected(t *testing.T) {
	t.Parallel()

	em := &ESLManager{}
	em.ReconnectESL() // must be a silent no-op
}

func TestESLManager_AuthFailureRetries(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.rejectAuth = true

	em := newServerESLManager(t, srv, 1, 8)

	// The loop must keep retrying (and counting errors) without connecting.
	if !waitFor(func() bool { return em.statistics.ConnectionErrors.Load() >= 2 }) {
		t.Fatal("expected repeated auth failures to be counted")
	}

	if em.IsConnected() {
		t.Error("manager must not report connected after auth failure")
	}
}

func TestESLManager_QueueFullDropsEvents(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	// No workers and an unbuffered queue: every delivered event must be
	// dropped by readEvents' non-blocking enqueue.
	em := newServerESLManager(t, srv, 0, 0)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	srv.sendEvent(map[string]string{
		hdrEventName: evHeartbeat,
	})

	if !waitFor(func() bool { return em.statistics.EventsDropped.Load() > 0 }) {
		t.Error("expected event to be dropped with no workers and zero-capacity queue")
	}
}

func TestESLManager_ShutdownIdempotent(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	em.Shutdown()
	em.Shutdown() // second call must return immediately

	if em.IsConnected() {
		// connected flag is left as-is by Shutdown; the connection itself is
		// closed. Nothing to assert beyond "no panic / no deadlock".
		t.Log("note: connected flag not cleared by Shutdown (by design)")
	}
}

func TestESLManager_AccessorsAndLogLevel(t *testing.T) {
	t.Parallel()

	const accessorHost = "192.0.2.1"

	em := &ESLManager{eslConfig: ESLConfig{Host: accessorHost, Port: "8021"}}

	if em.Host() != accessorHost || em.Port() != "8021" {
		t.Errorf("Host/Port = %q/%q", em.Host(), em.Port())
	}

	if em.IsConnected() {
		t.Error("zero-value manager must not be connected")
	}

	old := GetLogger().GetLogLevel()
	defer GetLogger().SetLogLevel(old)

	em.SetESLLogLevel("ERROR") // case-insensitive

	if got := GetLogger().GetLogLevel(); got != LogLevelError {
		t.Errorf("SetESLLogLevel: level = %d, want %d", got, LogLevelError)
	}

	stats := em.GetESLStats()
	if stats["host"] != accessorHost || stats["queueCapacity"] != 0 {
		t.Errorf("unexpected stats: %v", stats)
	}
}

// TestESLManager_CommandReplyErrors connects to a server that answers every
// command with -ERR, covering the subscribe-error and Send-error branches.
func TestESLManager_CommandReplyErrors(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.replyError = true

	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	// Subscriptions were attempted (and rejected) during connect.
	if !waitFor(func() bool { return srv.commandSeen(eventNameChannelCreate) }) {
		t.Fatal("expected subscription attempts")
	}

	_, cmdErr := em.SendCommand(testCmdStatus)
	if cmdErr == nil {
		t.Error("expected error when the server rejects the api command")
	}
}

// TestESLManager_KillsRateLimitedCall covers the uuid_kill path: a second
// call from the same IP exceeds the limit and the call is terminated through
// the live connection.
func TestESLManager_KillsRateLimitedCall(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 16)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	// No events are in flight yet, so tightening the limit is race-free.
	em.rateManager.cfg.CallRateLimit = 1

	channelCreate := func(uuid string) map[string]string {
		return map[string]string{
			hdrEventName:    eventNameChannelCreate,
			hdrVarNetworkIP: "203.0.113.180",
			hdrVarFromUser:  testSpammer,
			hdrVarFromHost:  "spam.example",
			hdrUniqueID:     uuid,
		}
	}

	srv.sendEvent(channelCreate("uuid-ok-1"))
	srv.sendEvent(channelCreate("uuid-kill-1"))

	if !waitFor(func() bool { return srv.commandSeen("uuid_kill uuid-kill-1") }) {
		t.Error("expected rate-limited call to be killed via uuid_kill")
	}
}

// TestESLManager_KillsUntrustedCall covers the untrusted-domain INVITE filter:
// a CHANNEL_CREATE whose From-host matches an untrusted pattern is torn down via
// uuid_kill and the source IP is blacklisted.
func TestESLManager_KillsUntrustedCall(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 16)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	// newTestSecurityManager loads testUntrustedDomain ("evil.example") as an
	// untrusted pattern; this IP is outside the trusted 10.0.0.0/8.
	srv.sendEvent(map[string]string{
		hdrEventName:    eventNameChannelCreate,
		hdrVarNetworkIP: "203.0.113.190",
		hdrVarFromUser:  testSpammer,
		hdrVarFromHost:  testUntrustedDomain,
		hdrUniqueID:     "uuid-untrusted-1",
	})

	if !waitFor(func() bool { return srv.commandSeen("uuid_kill uuid-untrusted-1") }) {
		t.Error("expected untrusted-domain call to be killed via uuid_kill")
	}

	if !waitFor(func() bool { return em.securityManager.IsIPBlacklisted("203.0.113.190") }) {
		t.Error("expected untrusted-domain call to blacklist the source IP")
	}
}

// TestRouteESLCommand_Connected covers the success path of the /esl/command
// route end-to-end: route → processor → live ESL connection.
func TestRouteESLCommand_Connected(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	sm := newTestSecurityManager(t)
	rp := newTestRequestProcessor(t, sm, em)

	router := gin.New()
	g := router.Group("/security")
	registerESLRoutes(g, em, rp)

	rec := doJSON(t, router, "POST", "/security/esl/command", `{"command":"status"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("command status=%d body=%s", rec.Code, rec.Body)
	}

	if !strings.Contains(rec.Body.String(), "+OK") {
		t.Errorf("unexpected body: %s", rec.Body)
	}
}

// TestESLManager_SendCommand_BodyFallback covers the api/response path where
// the reply has a body instead of a Reply-Text header.
func TestESLManager_SendCommand_BodyFallback(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.apiBody = "FreeSWITCH is ready"

	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	resp, err := em.SendCommand(testCmdStatus)
	if err != nil {
		t.Fatalf("SendCommand: %v", err)
	}

	if resp != "FreeSWITCH is ready" {
		t.Errorf("response = %q, want api body", resp)
	}
}

// TestESLManager_KillError covers the uuid_kill error branch: the server
// rejects the kill command.
func TestESLManager_KillError(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.replyError = true

	em := newServerESLManager(t, srv, 1, 16)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	em.rateManager.cfg.CallRateLimit = 1

	channelCreate := func(uuid string) map[string]string {
		return map[string]string{
			hdrEventName:    eventNameChannelCreate,
			hdrVarNetworkIP: "203.0.113.181",
			hdrVarFromUser:  testSpammer,
			hdrUniqueID:     uuid,
		}
	}

	srv.sendEvent(channelCreate("uuid-a"))
	srv.sendEvent(channelCreate("uuid-b"))

	// The kill is attempted and rejected; the worker logs and carries on.
	if !waitFor(func() bool { return srv.commandSeen("uuid_kill uuid-b") }) {
		t.Error("expected uuid_kill attempt despite server rejection")
	}
}

// TestESLManager_BogusBackoffFallsBack covers the reconnect-backoff parse
// failure branch (falls back to 5s) on an otherwise healthy connection.
func TestESLManager_BogusBackoff(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())
	host, port := srv.hostPort()

	ctx, cancel := context.WithCancel(context.Background())
	em := &ESLManager{
		securityManager: sm,
		eslConfig: ESLConfig{
			Host:             host,
			Port:             port,
			Password:         testESLPassword,
			ReconnectBackoff: testBogusValue, // parse error → 5s default
			WorkerCount:      1,
		},
		eslDisconnected: make(chan bool, 1),
		rateManager:     rm,
		queueSize:       8,
		workerCount:     1,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()

	em.readersWg.Add(1)
	go em.startESLConnection()

	t.Cleanup(em.Shutdown)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected despite bogus backoff config")
	}
}

// TestESLManager_CancelWhileConnected drives the ctx.Done arm of the
// post-connect select: the context is canceled while the connection is
// healthy (no read error has fired yet).
func TestESLManager_CancelWhileConnected(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	em.cancel() // connection stays open: the loop must exit via ctx.Done

	// Shutdown (via cleanup) must not hang; an explicit call here surfaces
	// problems inside the test body instead.
	em.Shutdown()
}

// TestESLManager_ReconnectSignalOverflow covers ReconnectESL's non-blocking
// send: a pending disconnect signal makes the new send hit the default arm.
func TestESLManager_ReconnectSignalOverflow(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	// Occupy the single-slot signal buffer, then force a reconnect.
	em.eslDisconnected <- true

	em.ReconnectESL() // second signal is dropped via the default arm

	if !waitFor(em.IsConnected) {
		t.Fatal("manager did not reconnect")
	}
}

// TestESLManager_ShutdownFlagStopsLoops sets the shutdown flag directly and
// then wakes both loops: readEvents exits through its flag check after the
// next event, and the connect loop exits through its loop-top flag check
// after the disconnect round-trip.
func TestESLManager_ShutdownFlagStopsLoops(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	em := newServerESLManager(t, srv, 1, 8)

	if !waitFor(em.IsConnected) {
		t.Fatal("manager never connected")
	}

	em.shutdown.Store(true)

	// Wake the blocked reader; it processes this event, then sees the flag.
	srv.sendEvent(map[string]string{hdrEventName: evHeartbeat})

	if !waitFor(func() bool { return !em.IsConnected() }) {
		t.Fatal("connect loop did not observe the shutdown flag")
	}

	// The CAS in Shutdown is already consumed, so tear down manually and
	// prove every goroutine exits: readers first, then close the queue to
	// release the workers.
	em.cancel()
	em.readersWg.Wait()
	em.closeWorkerQueues()
	em.workersWg.Wait()
}

// TestESLManager_ShutdownDuringDialBackoff cancels the manager while it sits
// in the long backoff after a failed dial, covering that select's ctx arm.
func TestESLManager_ShutdownDuringDialBackoff(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)
	srv.rejectAuth = true

	sm := newTestSecurityManager(t)
	rm := newTestRateManager(t, sm, defaultTestRateConfig())
	host, port := srv.hostPort()

	ctx, cancel := context.WithCancel(context.Background())
	em := &ESLManager{
		securityManager: sm,
		eslConfig: ESLConfig{
			Host:             host,
			Port:             port,
			Password:         testESLPassword,
			ReconnectBackoff: "30s", // long enough that the loop is parked in it
			WorkerCount:      1,
		},
		eslDisconnected: make(chan bool, 1),
		rateManager:     rm,
		queueSize:       8,
		workerCount:     1,
		eventPool:       NewEventPool(),
		ctx:             ctx,
		cancel:          cancel,
	}

	em.startWorkerPool()

	em.readersWg.Add(1)
	go em.startESLConnection()

	if !waitFor(func() bool { return em.statistics.ConnectionErrors.Load() >= 1 }) {
		t.Fatal("expected a failed dial attempt")
	}

	em.Shutdown() // must interrupt the 30s backoff via ctx.Done
}

// TestReconnectESL_SignalBufferFull drives ReconnectESL's non-blocking send
// default arm deterministically: no connect loop is draining the channel and
// the single buffer slot is pre-filled.
func TestReconnectESL_SignalBufferFull(t *testing.T) {
	t.Parallel()

	srv := newFakeESL(t)

	client, err := eventsocket.Dial(srv.ln.Addr().String(), testESLPassword)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	em := &ESLManager{eslDisconnected: make(chan bool, 1)}
	em.eslClient = client
	em.connected.Store(true)

	em.eslDisconnected <- true // occupy the only buffer slot

	em.ReconnectESL() // close + drop the second signal via default

	if em.IsConnected() {
		t.Error("ReconnectESL must clear the connected flag")
	}
}
