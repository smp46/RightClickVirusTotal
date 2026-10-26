package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"rcvt/internal/cmdline"
)

var testKey = strings.Repeat("ab12", 16)

func run(t *testing.T, opts cmdline.Options) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := Run(opts, strings.NewReader(""), &out)
	return code, out.String()
}

func TestRunHelp(t *testing.T) {
	code, out := run(t, cmdline.Options{Action: cmdline.ActionHelp, APIKey: testKey})
	if code != 0 {
		t.Errorf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out, "Usage:") {
		t.Errorf("help output missing usage:\n%s", out)
	}
	if strings.Contains(out, "Checking File") {
		t.Errorf("help should not start a scan:\n%s", out)
	}
}

func TestRunVersion(t *testing.T) {
	code, out := run(t, cmdline.Options{Action: cmdline.ActionVersion})
	if code != 0 || strings.TrimSpace(out) != VERSION {
		t.Errorf("got (%d, %q), want (0, %q)", code, out, VERSION)
	}
}

func TestRunNoArgsShowsHelp(t *testing.T) {
	code, out := run(t, cmdline.Options{})
	if code != 0 || !strings.Contains(out, "Usage:") {
		t.Errorf("got (%d, %q), want help and exit 0", code, out)
	}
}

func TestRunScanValidation(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope.exe")
	tests := []struct {
		name string
		opts cmdline.Options
		msg  string
	}{
		{"missing key", cmdline.Options{FilePath: "file.exe"}, "API key"},
		{"missing file", cmdline.Options{APIKey: testKey}, "file path"},
		{"nonexistent file", cmdline.Options{APIKey: testKey, FilePath: missing}, "nope.exe"},
		{"directory", cmdline.Options{APIKey: testKey, FilePath: t.TempDir()}, "directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out := run(t, tt.opts)
			if code == 0 {
				t.Errorf("exit code = 0, want non-zero")
			}
			if !strings.Contains(out, tt.msg) {
				t.Errorf("output %q does not mention %q", out, tt.msg)
			}
			if strings.Contains(out, "Uploading") {
				t.Errorf("should fail before contacting VirusTotal:\n%s", out)
			}
		})
	}
}
