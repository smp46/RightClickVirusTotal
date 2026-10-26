package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rcvt/internal/cmdline"
	"rcvt/internal/vttest"

	vt "github.com/VirusTotal/vt-go"
)

// setupScan points the GUI's globals at a fake server and a temp file, as
// start() would after a successful launch.
func setupScan(t *testing.T, srv *vttest.Server) *App {
	t.Helper()
	pollInterval = time.Millisecond
	srv.Start(t)

	file_path = filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(file_path, []byte("sample"), 0644); err != nil {
		t.Fatal(err)
	}
	a := NewApp(cmdline.Options{})
	client = vt.NewClient(strings.Repeat("ab12", 16))
	file_hash = a.hashFile(file_path)
	file_url = vt.URL("files/%s", file_hash)
	file_object = nil
	return a
}

// within fails the test if f panics or does not return in time.
func within(t *testing.T, f func()) {
	t.Helper()
	done := make(chan any, 1)
	go func() {
		defer func() { done <- recover() }()
		f()
	}()
	select {
	case p := <-done:
		if p != nil {
			t.Fatalf("panic: %v", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not finish")
	}
}

func TestGUIScanFlow(t *testing.T) {
	a := setupScan(t, &vttest.Server{AnalysisStatus: "completed"})
	within(t, func() {
		if r := a.StartFileScan(); !r.Success {
			t.Fatalf("StartFileScan: %s", r.Message)
		}
		if r := a.CheckAnalysisStatus(); !r.Success {
			t.Fatalf("CheckAnalysisStatus: %s", r.Message)
		}
		if !a.ConfirmAnalysisSuccess() {
			t.Fatal("ConfirmAnalysisSuccess = false")
		}
		if r := a.GetAnalysisResults(); !r.Success || r.Stats.Malicious != 2 {
			t.Fatalf("GetAnalysisResults = %+v", r)
		}
	})
}

func TestGUIAnalysisRequestFails(t *testing.T) {
	a := setupScan(t, &vttest.Server{})
	within(t, func() {
		if r := a.StartFileScan(); !r.Success {
			t.Fatalf("StartFileScan: %s", r.Message)
		}
		r := a.CheckAnalysisStatus()
		if r.Success || !strings.Contains(r.Message, "boom") {
			t.Errorf("CheckAnalysisStatus = %+v, want failure mentioning the API error", r)
		}
	})
}

func TestGUIResultsWithoutFileObject(t *testing.T) {
	a := setupScan(t, &vttest.Server{})
	within(t, func() {
		if r := a.GetAnalysisResults(); r.Success {
			t.Errorf("GetAnalysisResults = %+v, want failure", r)
		}
	})
}
