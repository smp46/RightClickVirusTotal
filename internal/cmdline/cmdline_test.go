package cmdline

import (
	"strings"
	"testing"
)

var key = strings.Repeat("ab12", 16)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want Options
	}{
		{"no args", nil, Options{Action: ActionScan}},
		{"key and file", []string{key, "file.exe"}, Options{Action: ActionScan, APIKey: key, FilePath: "file.exe"}},
		{"file and key swapped", []string{"file.exe", key}, Options{Action: ActionScan, APIKey: key, FilePath: "file.exe"}},
		{"key only", []string{key}, Options{Action: ActionScan, APIKey: key}},
		{"file only", []string{"file.exe"}, Options{Action: ActionScan, FilePath: "file.exe"}},
		{"key-shaped file name after key", []string{key, strings.Repeat("f", 64)}, Options{Action: ActionScan, APIKey: key, FilePath: strings.Repeat("f", 64)}},

		{"-h", []string{"-h"}, Options{Action: ActionHelp}},
		{"--help", []string{"--help"}, Options{Action: ActionHelp}},
		{"help", []string{"help"}, Options{Action: ActionHelp}},
		{"-h after key (alias)", []string{key, "-h"}, Options{Action: ActionHelp, APIKey: key}},
		{"-h after key and file", []string{key, "file.exe", "-h"}, Options{Action: ActionHelp, APIKey: key, FilePath: "file.exe"}},

		{"-v", []string{"-v"}, Options{Action: ActionVersion}},
		{"--version", []string{"--version"}, Options{Action: ActionVersion}},
		{"version", []string{"version"}, Options{Action: ActionVersion}},

		{"--install", []string{"--install"}, Options{Action: ActionInstall}},
		{"install", []string{"install"}, Options{Action: ActionInstall}},
		{"install after key (alias)", []string{key, "install"}, Options{Action: ActionInstall, APIKey: key}},

		{"gui first", []string{"gui", key, "file.exe"}, Options{Action: ActionScan, ForceGUI: true, APIKey: key, FilePath: "file.exe"}},
		{"gui last", []string{key, "file.exe", "gui"}, Options{Action: ActionScan, ForceGUI: true, APIKey: key, FilePath: "file.exe"}},
		{"--gui", []string{"--gui", key}, Options{Action: ActionScan, ForceGUI: true, APIKey: key}},
		{"--cli", []string{"--cli", key, "file.exe"}, Options{Action: ActionScan, ForceCLI: true, APIKey: key, FilePath: "file.exe"}},

		{"nautilus shortcut", []string{"gui", key, "shortcut"}, Options{Action: ActionScan, ForceGUI: true, Shortcut: true, APIKey: key}},
		{"windows elevated shortcut", []string{"gui", key, `C:\a b\f.exe`, "shortcut"}, Options{Action: ActionScan, ForceGUI: true, Shortcut: true, APIKey: key, FilePath: `C:\a b\f.exe`}},

		{"double dash allows dash file", []string{key, "--", "-h"}, Options{Action: ActionScan, APIKey: key, FilePath: "-h"}},
		{"double dash allows keyword file", []string{key, "--", "gui"}, Options{Action: ActionScan, APIKey: key, FilePath: "gui"}},
		{"lone dash is a path", []string{key, "-"}, Options{Action: ActionScan, APIKey: key, FilePath: "-"}},
		{"key whitespace trimmed", []string{" " + key + "\n", "f"}, Options{Action: ActionScan, APIKey: key, FilePath: "f"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.args)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("Parse(%q)\n got  %+v\n want %+v", tt.args, got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		msg  string
	}{
		{"unknown flag", []string{key, "--frobnicate"}, "unknown option"},
		{"too many args", []string{key, "a", "b"}, "too many arguments"},
		{"no key among two", []string{"a", "b"}, "API key"},
		{"gui and cli", []string{"--gui", "--cli"}, "--gui and --cli"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.args)
			if err == nil {
				t.Fatalf("Parse(%q) expected error containing %q", tt.args, tt.msg)
			}
			if !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("Parse(%q) error %q, want it to contain %q", tt.args, err, tt.msg)
			}
		})
	}
}

func TestIsAPIKey(t *testing.T) {
	if !IsAPIKey(key) {
		t.Errorf("IsAPIKey(%q) = false", key)
	}
	for _, s := range []string{"", "abc", strings.Repeat("z", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if IsAPIKey(s) {
			t.Errorf("IsAPIKey(%q) = true", s)
		}
	}
}

func TestUseGUI(t *testing.T) {
	tests := []struct {
		name       string
		opts       Options
		hasConsole bool
		want       bool
	}{
		{"terminal scan defaults to CLI", Options{APIKey: key, FilePath: "f"}, true, false},
		{"no console (double click / file manager) defaults to GUI", Options{APIKey: key, FilePath: "f"}, false, true},
		{"no args in terminal shows CLI help", Options{}, true, false},
		{"gui forces GUI in terminal", Options{ForceGUI: true}, true, true},
		{"--cli forces CLI without console", Options{ForceCLI: true}, false, false},
		{"shortcut implies GUI", Options{Shortcut: true}, true, true},
		{"help is always CLI", Options{Action: ActionHelp}, false, false},
		{"version is always CLI", Options{Action: ActionVersion, ForceGUI: true}, false, false},
		{"install is always CLI", Options{Action: ActionInstall}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.UseGUI(tt.hasConsole); got != tt.want {
				t.Errorf("UseGUI(%v) = %v, want %v", tt.hasConsole, got, tt.want)
			}
		})
	}
}
