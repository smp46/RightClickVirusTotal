package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"rcvt/internal/cmdline"
)

func lookPathFor(installed ...string) func(string) (string, error) {
	return func(name string) (string, error) {
		for _, i := range installed {
			if i == name {
				return "/usr/bin/" + name, nil
			}
		}
		return "", errors.New("not found")
	}
}

func names(fms []fileManager) []string {
	var out []string
	for _, fm := range fms {
		out = append(out, fm.Name)
	}
	return out
}

func TestDetectFileManagers(t *testing.T) {
	if got := names(detectFileManagers(lookPathFor())); len(got) != 0 {
		t.Errorf("nothing installed: got %v", got)
	}
	got := strings.Join(names(detectFileManagers(lookPathFor("dolphin", "nemo", "thunar"))), ",")
	if got != "Nemo,Dolphin" {
		t.Errorf("got %s, want Nemo,Dolphin", got)
	}
	got = strings.Join(names(detectFileManagers(lookPathFor("nautilus", "caja", "nemo", "dolphin"))), ",")
	if got != "Nautilus,Caja,Nemo,Dolphin" {
		t.Errorf("got %s", got)
	}
}

func fm(t *testing.T, name string) fileManager {
	t.Helper()
	for _, f := range fileManagers {
		if f.Name == name {
			return f
		}
	}
	t.Fatalf("no file manager %q", name)
	return fileManager{}
}

func TestMenuPaths(t *testing.T) {
	home := "/home/u"
	want := map[string]string{
		"Nautilus": "/home/u/.local/share/nautilus/scripts/Scan with VirusTotal",
		"Caja":     "/home/u/.config/caja/scripts/Scan with VirusTotal",
		"Nemo":     "/home/u/.local/share/nemo/actions/rcvt-scan.nemo_action",
		"Dolphin":  "/home/u/.local/share/kio/servicemenus/rcvt-scan.desktop",
	}
	for name, path := range want {
		if got := fm(t, name).Path(home); got != path {
			t.Errorf("%s path = %s, want %s", name, got, path)
		}
	}
}

func TestDolphinServiceMenu(t *testing.T) {
	got := fm(t, "Dolphin").Content(`/opt/my apps/rcvt`, testKey)
	for _, line := range []string{
		"[Desktop Entry]",
		"Type=Service",
		"MimeType=all/allfiles;",
		"Actions=scanWithVirusTotal;",
		"[Desktop Action scanWithVirusTotal]",
		"Name=Scan with VirusTotal",
		`Exec="/opt/my apps/rcvt" gui ` + testKey + ` %f`,
	} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("service menu missing %q:\n%s", line, got)
		}
	}
}

func TestNemoAction(t *testing.T) {
	got := fm(t, "Nemo").Content(`/opt/my apps/rcvt`, testKey)
	for _, line := range []string{
		"[Nemo Action]",
		"Name=Scan with VirusTotal",
		`Exec='/opt/my apps/rcvt' gui ` + testKey + ` %F`,
		"Selection=s",
		"Extensions=nodirs;",
	} {
		if !strings.Contains(got, line+"\n") {
			t.Errorf("nemo action missing %q:\n%s", line, got)
		}
	}
}

func TestDesktopExecQuote(t *testing.T) {
	tests := map[string]string{
		`/usr/bin/rcvt`:  `"/usr/bin/rcvt"`,
		`/opt/a b/rcvt`:  `"/opt/a b/rcvt"`,
		`/opt/a"b/rcvt`:  `"/opt/a\\"b/rcvt"`,
		`/opt/$x/rcvt`:   `"/opt/\\$x/rcvt"`,
		"/opt/a`b/rcvt":  "\"/opt/a\\\\`b/rcvt\"",
		`/opt/a\b/rcvt`:  `"/opt/a\\\\b/rcvt"`,
		`/opt/100%/rcvt`: `"/opt/100%%/rcvt"`,
	}
	for in, want := range tests {
		if got := desktopExecQuote(in); got != want {
			t.Errorf("desktopExecQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		`/usr/bin/rcvt`: `'/usr/bin/rcvt'`,
		`/opt/a b`:      `'/opt/a b'`,
		`/opt/it's`:     `'/opt/it'\''s'`,
		`/opt/$x`:       `'/opt/$x'`,
	}
	for in, want := range tests {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeRCVT writes an executable that records its arguments, one per line,
// in a path containing awkward characters, and returns both paths.
func fakeRCVT(t *testing.T) (exe, argsFile string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts")
	}
	dir := filepath.Join(t.TempDir(), `it's a "dir" $HOME`)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	argsFile = filepath.Join(t.TempDir(), "args")
	exe = filepath.Join(dir, "rcvt")
	script := "#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done > " + shellQuote(argsFile) + "\n"
	if err := os.WriteFile(exe, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return exe, argsFile
}

// runMenuScript runs a generated file manager script the way the file
// manager would and returns the arguments rcvt received.
func runMenuScript(t *testing.T, name, envVar, selection string) []string {
	t.Helper()
	exe, argsFile := fakeRCVT(t)
	script := filepath.Join(t.TempDir(), "menu")
	if err := os.WriteFile(script, []byte(fm(t, name).Content(exe, testKey)), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(script)
	cmd.Env = append(os.Environ(), envVar+"="+selection)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

func TestNautilusScriptRuns(t *testing.T) {
	args := runMenuScript(t, "Nautilus", "NAUTILUS_SCRIPT_SELECTED_FILE_PATHS", "/tmp/a b.exe\n")
	opts, err := cmdline.Parse(args)
	if err != nil {
		t.Fatalf("Parse(%q): %v", args, err)
	}
	// Nautilus keeps the existing contract: the GUI reads the selection
	// from the environment.
	if !opts.ForceGUI || !opts.Shortcut || opts.APIKey != testKey || opts.FilePath != "" {
		t.Errorf("args %q parsed to %+v", args, opts)
	}
}

func TestCajaScriptRuns(t *testing.T) {
	args := runMenuScript(t, "Caja", "CAJA_SCRIPT_SELECTED_FILE_PATHS", "/tmp/-weird $name.exe\n/tmp/second.exe\n")
	opts, err := cmdline.Parse(args)
	if err != nil {
		t.Fatalf("Parse(%q): %v", args, err)
	}
	if !opts.ForceGUI || opts.APIKey != testKey || opts.FilePath != "/tmp/-weird $name.exe" {
		t.Errorf("args %q parsed to %+v", args, opts)
	}
}

func TestInstallMenus(t *testing.T) {
	home := t.TempDir()
	fms := []fileManager{fm(t, "Nemo"), fm(t, "Dolphin")}

	if menusInstalled(fms, home) {
		t.Error("menusInstalled before install")
	}
	if err := installMenus(fms, home, "/opt/rcvt", testKey); err != nil {
		t.Fatal(err)
	}
	if !menusInstalled(fms, home) {
		t.Error("menusInstalled after install = false")
	}
	for _, f := range fms {
		info, err := os.Stat(f.Path(home))
		if err != nil {
			t.Fatal(err)
		}
		// Dolphin ignores service menus in the home directory unless they
		// are executable; scripts need it to run at all.
		if info.Mode().Perm()&0100 == 0 {
			t.Errorf("%s menu is not executable: %v", f.Name, info.Mode())
		}
	}
	if menusInstalled([]fileManager{fm(t, "Nemo"), fm(t, "Caja")}, home) {
		t.Error("menusInstalled should be false when one is missing")
	}
	if menusInstalled(nil, home) {
		t.Error("menusInstalled with no file managers should be false")
	}
}

func TestInstallMenusReportsErrors(t *testing.T) {
	home := t.TempDir()
	// A file where a directory is needed makes MkdirAll fail.
	os.WriteFile(filepath.Join(home, ".local"), nil, 0644)
	err := installMenus([]fileManager{fm(t, "Dolphin")}, home, "/opt/rcvt", testKey)
	if err == nil || !strings.Contains(err.Error(), "Dolphin") {
		t.Errorf("err = %v, want an error naming Dolphin", err)
	}
}
