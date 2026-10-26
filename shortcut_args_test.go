package main

import (
	"testing"

	"rcvt/internal/cmdline"
)

func TestContextMenuCommand(t *testing.T) {
	got := contextMenuCommand(`C:\Program Files\RCVT\rcvt.exe`, testKey)
	want := `"C:\Program Files\RCVT\rcvt.exe" gui ` + testKey + ` "%1"`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// The registry command must launch the GUI and parse back to the clicked file.
func TestContextMenuCommandParses(t *testing.T) {
	opts, err := cmdline.Parse([]string{"gui", testKey, `C:\some file.exe`})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.UseGUI(false) || opts.APIKey != testKey || opts.FilePath != `C:\some file.exe` {
		t.Errorf("unexpected options %+v", opts)
	}
}

func TestElevationArgs(t *testing.T) {
	tests := []struct {
		name, key, file, want string
	}{
		{"no file", testKey, "", "gui shortcut " + testKey},
		{"simple file", testKey, `C:\f.exe`, `gui shortcut ` + testKey + ` C:\f.exe`},
		{"file with spaces", testKey, `C:\my files\f.exe`, `gui shortcut ` + testKey + ` "C:\my files\f.exe"`},
		{"file with quote", testKey, `C:\a"b.exe`, `gui shortcut ` + testKey + ` C:\a\"b.exe`},
		{"dash file is protected", testKey, `-h`, `gui shortcut ` + testKey + ` -- -h`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := elevationArgs(tt.key, tt.file); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// What the elevated process receives must parse to a "finish shortcut" launch
// that still carries the key; the old code dropped it.
func TestElevationArgsRoundTrip(t *testing.T) {
	opts, err := cmdline.Parse([]string{"gui", "shortcut", testKey, `C:\my files\f.exe`})
	if err != nil {
		t.Fatal(err)
	}
	plan := planStartup(opts, fakeSys("windows", false, nil))
	if !plan.FinishShortcut || plan.APIKey != testKey {
		t.Errorf("unexpected plan %+v", plan)
	}
}

func TestEscapeWindowsArg(t *testing.T) {
	tests := map[string]string{
		``:           `""`,
		`plain`:      `plain`,
		`a b`:        `"a b"`,
		`a"b`:        `a\"b`,
		`C:\dir\`:    `C:\dir\`,
		`C:\my dir\`: `"C:\my dir\\"`,
		`a\\"b`:      `a\\\\\"b`,
		"tab\there":  "\"tab\there\"",
	}
	for in, want := range tests {
		if got := escapeWindowsArg(in); got != want {
			t.Errorf("escapeWindowsArg(%q) = %q, want %q", in, got, want)
		}
	}
}
