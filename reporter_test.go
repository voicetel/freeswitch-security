package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// capturedReport is one report body received by a fake chanDaemon, with the raw
// wire bytes so tests can assert the exact camelCase JSON keys.
type capturedReport struct {
	body reportBody
	raw  string
	ct   string
}

// fakeChanDaemon spins up an httptest server that decodes report bodies onto a
// buffered channel and answers with status. It returns the server and the
// channel; the caller defers srv.Close.
func fakeChanDaemon(tb testing.TB, status int) (*httptest.Server, <-chan capturedReport) {
	tb.Helper()

	ch := make(chan capturedReport, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)

		var b reportBody

		_ = json.Unmarshal(raw, &b)
		ch <- capturedReport{body: b, raw: string(raw), ct: req.Header.Get("Content-Type")}

		wr.WriteHeader(status)
	}))

	tb.Cleanup(srv.Close)

	return srv, ch
}

func TestChanDaemonReporter_Report(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusOK)

	rep := NewChanDaemonReporter(srv.URL, "http://sbc-tx:8088", projectName, 2*time.Second)
	rep.Report("9.9.9.9", "2017301000", "Exceeded max failed registrations (5)", 90*time.Second)
	rep.Wait()

	select {
	case got := <-ch:
		if got.body.IP != "9.9.9.9" {
			t.Errorf("ip = %q", got.body.IP)
		}

		if got.body.Reason != "Exceeded max failed registrations (5)" {
			t.Errorf("reason = %q", got.body.Reason)
		}

		if got.body.FromUser != "2017301000" {
			t.Errorf("fromUser = %q, want 2017301000", got.body.FromUser)
		}

		if got.body.TTL != 90 {
			t.Errorf("ttl = %d, want 90 (seconds)", got.body.TTL)
		}

		if got.body.Blocker != "http://sbc-tx:8088" {
			t.Errorf("blocker = %q", got.body.Blocker)
		}

		if got.body.Service != projectName {
			t.Errorf("service = %q, want %q", got.body.Service, projectName)
		}

		if got.ct != "application/json" {
			t.Errorf("content-type = %q", got.ct)
		}

		// The chanDaemon server decodes camelCase fromUser; guard the wire key.
		if !strings.Contains(got.raw, `"fromUser"`) || strings.Contains(got.raw, `"from_user"`) {
			t.Errorf("wire body must use camelCase fromUser, got: %s", got.raw)
		}
	default:
		t.Fatal("fake chanDaemon received no report")
	}

	sent, failed := rep.Stats()
	if sent != 1 || failed != 0 {
		t.Errorf("stats = (sent %d, failed %d), want (1, 0)", sent, failed)
	}
}

func TestChanDaemonReporter_NonPositiveTTL(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusOK)

	rep := NewChanDaemonReporter(srv.URL, "", projectName, 2*time.Second)
	// A permanent ban (ttl 0) must serialize to 0 so chanDaemon applies its floor.
	rep.Report("9.9.9.9", "", "ip block", 0)
	rep.Wait()

	got := <-ch
	if got.body.TTL != 0 {
		t.Errorf("ttl = %d, want 0", got.body.TTL)
	}

	// fromUser is omitempty: an empty user must not appear on the wire.
	if strings.Contains(got.raw, "fromUser") {
		t.Errorf("empty fromUser must be omitted, got: %s", got.raw)
	}
}

func TestChanDaemonReporter_ServerError(t *testing.T) {
	t.Parallel()

	srv, ch := fakeChanDaemon(t, http.StatusInternalServerError)

	rep := NewChanDaemonReporter(srv.URL, "", projectName, 2*time.Second)
	rep.Report("9.9.9.9", "", "ip block", time.Minute)
	rep.Wait()

	<-ch // drain the received request

	sent, failed := rep.Stats()
	if sent != 0 || failed != 1 {
		t.Errorf("stats = (sent %d, failed %d), want (0, 1) on 500", sent, failed)
	}
}

func TestChanDaemonReporter_Unreachable(t *testing.T) {
	t.Parallel()

	srv, _ := fakeChanDaemon(t, http.StatusOK)
	endpoint := srv.URL
	srv.Close() // close before reporting so the dial fails

	rep := NewChanDaemonReporter(endpoint, "", projectName, 200*time.Millisecond)
	rep.Report("9.9.9.9", "", "ip block", time.Minute)
	rep.Wait()

	if sent, failed := rep.Stats(); sent != 0 || failed != 1 {
		t.Errorf("stats = (sent %d, failed %d), want (0, 1) when unreachable", sent, failed)
	}
}

func TestChanDaemonReporter_BadEndpoint(t *testing.T) {
	t.Parallel()

	// A space in the host makes http.NewRequestWithContext fail to build.
	rep := NewChanDaemonReporter("http://exa mple.com/report", "", projectName, time.Second)
	rep.Report("9.9.9.9", "", "ip block", time.Minute)
	rep.Wait()

	if sent, failed := rep.Stats(); sent != 0 || failed != 1 {
		t.Errorf("stats = (sent %d, failed %d), want (0, 1) on bad endpoint", sent, failed)
	}
}

func TestReportableUser(t *testing.T) {
	t.Parallel()

	if got := reportableUser(unknownUser); got != "" {
		t.Errorf("reportableUser(unknownUser) = %q, want empty", got)
	}

	if got := reportableUser("2017301000"); got != "2017301000" {
		t.Errorf("reportableUser(real) = %q, want 2017301000", got)
	}
}
