package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rcvt/internal/cmdline"
)

func TestAliasFor(t *testing.T) {
	home := "/home/u"
	exe := "/opt/my apps/rcvt"
	tests := []struct {
		name     string
		env      installEnv
		existing []string
		wantPath string
		wantLine string
	}{
		{"bash", installEnv{Shell: "/bin/bash", GOOS: "linux"}, nil,
			"/home/u/.bashrc", `alias rcvt='"/opt/my apps/rcvt" ` + testKey + `'`},
		{"bash aliases dir", installEnv{Shell: "/usr/bin/bash", GOOS: "linux"}, []string{"/home/u/.config/bashrc/10-aliases"},
			"/home/u/.config/bashrc/10-aliases", `alias rcvt='"/opt/my apps/rcvt" ` + testKey + `'`},
		{"zsh", installEnv{Shell: "/bin/zsh", GOOS: "darwin"}, nil,
			"/home/u/.zshrc", `alias rcvt='"/opt/my apps/rcvt" ` + testKey + `'`},
		{"zsh aliases dir", installEnv{Shell: "/bin/zsh", GOOS: "linux"}, []string{"/home/u/.config/zshrc/25-aliases"},
			"/home/u/.config/zshrc/25-aliases", `alias rcvt='"/opt/my apps/rcvt" ` + testKey + `'`},
		{"fish", installEnv{Shell: "/usr/bin/fish", GOOS: "linux"}, nil,
			"/home/u/.config/fish/conf.d/rcvt.fish", `function rcvt; "/opt/my apps/rcvt" ` + testKey + ` $argv; end`},
		{"windows powershell", installEnv{GOOS: "windows"}, nil,
			filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			`function rcvt { & "/opt/my apps/rcvt" ` + testKey + ` @args }`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := tt.env
			env.Home, env.Exe = home, exe
			env.Exists = func(p string) bool {
				for _, e := range tt.existing {
					if p == e {
						return true
					}
				}
				return false
			}
			path, line, err := aliasFor(env, testKey)
			if err != nil {
				t.Fatal(err)
			}
			if path != tt.wantPath || line != tt.wantLine {
				t.Errorf("got\n  %s\n  %s\nwant\n  %s\n  %s", path, line, tt.wantPath, tt.wantLine)
			}
		})
	}

	if _, _, err := aliasFor(installEnv{Shell: "/bin/tcsh", GOOS: "linux", Exists: func(string) bool { return false }}, testKey); err == nil {
		t.Error("expected an error for an unsupported shell")
	}
}

func testEnv(t *testing.T) installEnv {
	t.Helper()
	return installEnv{
		Shell:  "/bin/bash",
		GOOS:   "linux",
		Home:   t.TempDir(),
		Exe:    "/opt/rcvt",
		Exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
	}
}

// runInstall fails the test instead of hanging if install loops on input.
func runInstall(t *testing.T, opts cmdline.Options, input string, env installEnv) (int, string) {
	t.Helper()
	var buf bytes.Buffer
	done := make(chan int, 1)
	go func() {
		out = &buf
		done <- installWith(opts, strings.NewReader(input), env)
	}()
	select {
	case code := <-done:
		return code, buf.String()
	case <-time.After(2 * time.Second):
		t.Fatal("install did not return (stuck waiting for input?)")
		return 0, ""
	}
}

func readRC(t *testing.T, env installEnv) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(env.Home, ".bashrc"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallWritesAlias(t *testing.T) {
	env := testEnv(t)
	code, output := runInstall(t, cmdline.Options{Action: cmdline.ActionInstall}, testKey+"\ny\n", env)
	if code != 0 {
		t.Fatalf("exit code %d, output:\n%s", code, output)
	}
	want := "alias rcvt='\"/opt/rcvt\" " + testKey + "'\n"
	if got := readRC(t, env); got != want {
		t.Errorf(".bashrc = %q, want %q", got, want)
	}
}

func TestInstallUsesKeyFromArgs(t *testing.T) {
	env := testEnv(t)
	code, output := runInstall(t, cmdline.Options{Action: cmdline.ActionInstall, APIKey: testKey}, "y\n", env)
	if code != 0 || !strings.Contains(readRC(t, env), testKey) {
		t.Fatalf("exit code %d, rc %q, output:\n%s", code, readRC(t, env), output)
	}
	if strings.Contains(output, "API Key:") {
		t.Errorf("should not prompt for a key that was given:\n%s", output)
	}
}

func TestInstallAppendsOnNewLine(t *testing.T) {
	env := testEnv(t)
	rc := filepath.Join(env.Home, ".bashrc")
	os.WriteFile(rc, []byte("export FOO=1"), 0644)
	runInstall(t, cmdline.Options{APIKey: testKey}, "y\n", env)
	got := readRC(t, env)
	if !strings.HasPrefix(got, "export FOO=1\nalias rcvt=") || !strings.HasSuffix(got, "\n") {
		t.Errorf(".bashrc = %q", got)
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	env := testEnv(t)
	runInstall(t, cmdline.Options{APIKey: testKey}, "y\n", env)
	code, output := runInstall(t, cmdline.Options{APIKey: testKey}, "y\n", env)
	if code != 0 {
		t.Errorf("exit code %d", code)
	}
	if n := strings.Count(readRC(t, env), "alias rcvt="); n != 1 {
		t.Errorf("alias written %d times, output:\n%s", n, output)
	}
}

func TestInstallCreatesFishConfDir(t *testing.T) {
	env := testEnv(t)
	env.Shell = "/usr/bin/fish"
	code, output := runInstall(t, cmdline.Options{APIKey: testKey}, "y\n", env)
	if code != 0 {
		t.Fatalf("exit code %d, output:\n%s", code, output)
	}
	if _, err := os.Stat(filepath.Join(env.Home, ".config", "fish", "conf.d", "rcvt.fish")); err != nil {
		t.Error(err)
	}
}

func TestInstallDeclined(t *testing.T) {
	env := testEnv(t)
	code, output := runInstall(t, cmdline.Options{APIKey: testKey}, "n\n", env)
	if code != 0 || readRC(t, env) != "" {
		t.Errorf("exit code %d, rc %q", code, readRC(t, env))
	}
	if !strings.Contains(output, "alias rcvt=") {
		t.Errorf("should print the alias for manual setup:\n%s", output)
	}
}

func TestInstallEOF(t *testing.T) {
	for _, input := range []string{"", "not-a-key\n", testKey + "\n"} {
		env := testEnv(t)
		code, _ := runInstall(t, cmdline.Options{}, input, env)
		if code == 0 {
			t.Errorf("input %q: exit code 0, want failure", input)
		}
		if readRC(t, env) != "" {
			t.Errorf("input %q: wrote alias without confirmation", input)
		}
	}
}

func TestInstallRetriesInvalidKey(t *testing.T) {
	env := testEnv(t)
	code, output := runInstall(t, cmdline.Options{}, "short\n"+testKey+"\ny\n", env)
	if code != 0 || !strings.Contains(readRC(t, env), testKey) {
		t.Errorf("exit code %d, output:\n%s", code, output)
	}
}
