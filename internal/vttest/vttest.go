// Package vttest provides a fake VirusTotal API server for tests.
package vttest

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	vt "github.com/VirusTotal/vt-go"
)

const statsJSON = `{"harmless":1,"malicious":2,"suspicious":3,"undetected":4}`

// Server fakes the endpoints rcvt uses. Its fields control the responses.
type Server struct {
	// Known makes the file lookup succeed straight away.
	Known bool
	// AnalysisStatus is returned by the analysis endpoint; "" makes it fail.
	AnalysisStatus string
	// NoStats omits last_analysis_stats from the file object.
	NoStats bool

	mu       sync.Mutex
	uploaded bool
}

// Start runs the server and points vt-go at it for the duration of the test.
func (s *Server) Start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(s.handle))
	vt.SetHost(srv.URL)
	t.Cleanup(func() {
		srv.Close()
		vt.SetHost("https://www.virustotal.com")
	})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")

	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v3/files/"):
		if !s.Known && !(s.uploaded && s.AnalysisStatus == "completed") {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":"NotFoundError","message":"File not found"}}`)
			return
		}
		attrs := `"last_analysis_stats":` + statsJSON
		if s.NoStats {
			attrs = `"size":1`
		}
		fmt.Fprintf(w, `{"data":{"type":"file","id":"x","attributes":{%s}}}`, attrs)

	case r.Method == http.MethodPost && r.URL.Path == "/api/v3/files":
		s.uploaded = true
		fmt.Fprint(w, `{"data":{"type":"analysis","id":"an1"}}`)

	case r.Method == http.MethodGet && r.URL.Path == "/api/v3/analyses/an1":
		if s.AnalysisStatus == "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":{"code":"InternalError","message":"boom"}}`)
			return
		}
		fmt.Fprintf(w, `{"data":{"type":"analysis","id":"an1","attributes":{"status":%q}}}`, s.AnalysisStatus)

	default:
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, `{"error":{"code":"NotFoundError","message":"unexpected %s %s"}}`, r.Method, r.URL.Path)
	}
}
