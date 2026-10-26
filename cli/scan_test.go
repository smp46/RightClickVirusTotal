package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rcvt/internal/cmdline"
	"rcvt/internal/vttest"
)

func scanOpts(t *testing.T) cmdline.Options {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, []byte("sample"), 0644); err != nil {
		t.Fatal(err)
	}
	return cmdline.Options{APIKey: testKey, FilePath: path}
}

// runScan fails the test if the scan panics, exits or never finishes.
func runScan(t *testing.T, srv *vttest.Server) (int, string) {
	t.Helper()
	pollInterval = time.Millisecond
	srv.Start(t)
	opts := scanOpts(t)

	type result struct {
		code int
		out  string
	}
	done := make(chan result, 1)
	go func() {
		code, out := run(t, opts)
		done <- result{code, out}
	}()
	select {
	case r := <-done:
		return r.code, r.out
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not finish")
		return 0, ""
	}
}

func TestScanKnownFile(t *testing.T) {
	code, out := runScan(t, &vttest.Server{Known: true})
	if code != 0 || !strings.Contains(out, "Malicious: 2") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
}

func TestScanUploadsAndWaits(t *testing.T) {
	code, out := runScan(t, &vttest.Server{AnalysisStatus: "completed"})
	if code != 0 || !strings.Contains(out, "Undetected: 4") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
}

func TestScanAnalysisRequestFails(t *testing.T) {
	code, out := runScan(t, &vttest.Server{})
	if code == 0 || !strings.Contains(out, "boom") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
}

func TestScanMissingStats(t *testing.T) {
	code, out := runScan(t, &vttest.Server{Known: true, NoStats: true})
	if code == 0 || !strings.Contains(out, "Error") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
}
