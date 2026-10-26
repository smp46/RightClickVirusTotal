package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rcvt/internal/cmdline"
)

var testKey = strings.Repeat("ab12", 16)

func fakeSys(goos string, nautilus bool, env map[string]string) startupSys {
	return startupSys{
		GOOS:          goos,
		UsingNautilus: func() bool { return nautilus },
		Getenv:        func(k string) string { return env[k] },
	}
}

func TestPlanStartup(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "sample.exe")
	other := filepath.Join(dir, "other.exe")
	os.WriteFile(file, []byte("x"), 0644)
	os.WriteFile(other, []byte("y"), 0644)
	missing := filepath.Join(dir, "missing.exe")

	nautilusEnv := map[string]string{"NAUTILUS_SCRIPT_SELECTED_FILE_PATHS": file + "\n" + other + "\n"}

	tests := []struct {
		name string
		opts cmdline.Options
		sys  startupSys
		want startupPlan
	}{
		{"linux scan", cmdline.Options{APIKey: testKey, FilePath: file}, fakeSys("linux", false, nil),
			startupPlan{APIKey: testKey, FilePath: file}},
		{"linux nautilus offers shortcut", cmdline.Options{APIKey: testKey, FilePath: file}, fakeSys("linux", true, nil),
			startupPlan{APIKey: testKey, FilePath: file, OfferShortcut: true}},
		{"windows offers shortcut", cmdline.Options{APIKey: testKey, FilePath: file}, fakeSys("windows", false, nil),
			startupPlan{APIKey: testKey, FilePath: file, OfferShortcut: true}},
		{"key only still offers shortcut", cmdline.Options{APIKey: testKey}, fakeSys("windows", false, nil),
			startupPlan{APIKey: testKey, OfferShortcut: true, Error: "No file path provided."}},
		{"missing key", cmdline.Options{FilePath: file}, fakeSys("linux", false, nil),
			startupPlan{FilePath: file, Error: "Missing API key."}},
		{"no args", cmdline.Options{}, fakeSys("linux", false, nil),
			startupPlan{Error: "No arguments provided. Please provide the API key and file path."}},
		{"missing file", cmdline.Options{APIKey: testKey, FilePath: missing}, fakeSys("linux", false, nil),
			startupPlan{APIKey: testKey, FilePath: missing, Error: "Cannot read file: " + missing}},
		{"directory", cmdline.Options{APIKey: testKey, FilePath: dir}, fakeSys("linux", false, nil),
			startupPlan{APIKey: testKey, FilePath: dir, Error: "Cannot scan a directory: " + dir}},

		{"nautilus shortcut takes first selected file", cmdline.Options{APIKey: testKey, Shortcut: true}, fakeSys("linux", true, nautilusEnv),
			startupPlan{APIKey: testKey, FilePath: file}},
		{"nautilus shortcut works when default file manager detection fails", cmdline.Options{APIKey: testKey, Shortcut: true}, fakeSys("linux", false, nautilusEnv),
			startupPlan{APIKey: testKey, FilePath: file}},
		{"nautilus shortcut without selection", cmdline.Options{APIKey: testKey, Shortcut: true}, fakeSys("linux", true, nil),
			startupPlan{APIKey: testKey, Error: "Shortcut error: No file was selected in Nautilus."}},

		{"windows elevated finish with file", cmdline.Options{APIKey: testKey, FilePath: file, Shortcut: true}, fakeSys("windows", false, nil),
			startupPlan{APIKey: testKey, FilePath: file, FinishShortcut: true}},
		{"windows elevated finish without file", cmdline.Options{APIKey: testKey, Shortcut: true}, fakeSys("windows", false, nil),
			startupPlan{APIKey: testKey, FinishShortcut: true, Error: "No file path provided."}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := planStartup(tt.opts, tt.sys); got != tt.want {
				t.Errorf("planStartup()\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}
