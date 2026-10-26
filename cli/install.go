package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"rcvt/internal/cmdline"
)

// installEnv holds everything install needs from the system, so tests can
// substitute it.
type installEnv struct {
	Shell  string
	GOOS   string
	Home   string
	Exe    string
	Exists func(path string) bool
}

func currentInstallEnv() (installEnv, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return installEnv{}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return installEnv{}, err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return installEnv{
		Shell:  os.Getenv("SHELL"),
		GOOS:   runtime.GOOS,
		Home:   home,
		Exe:    exe,
		Exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
	}, nil
}

// aliasFor returns the startup file to append to and the line that defines
// an rcvt command with the API key baked in.
func aliasFor(env installEnv, key string) (path, line string, err error) {
	if env.GOOS == "windows" {
		path = filepath.Join(env.Home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1")
		return path, fmt.Sprintf(`function rcvt { & "%s" %s @args }`, env.Exe, key), nil
	}

	posixAlias := fmt.Sprintf(`alias rcvt='"%s" %s'`, env.Exe, key)
	switch filepath.Base(env.Shell) {
	case "bash":
		path = filepath.Join(env.Home, ".bashrc")
		if p := filepath.Join(env.Home, ".config", "bashrc", "10-aliases"); env.Exists(p) {
			path = p
		}
		return path, posixAlias, nil
	case "zsh":
		path = filepath.Join(env.Home, ".zshrc")
		if p := filepath.Join(env.Home, ".config", "zshrc", "25-aliases"); env.Exists(p) {
			path = p
		}
		return path, posixAlias, nil
	case "fish":
		path = filepath.Join(env.Home, ".config", "fish", "conf.d", "rcvt.fish")
		return path, fmt.Sprintf(`function rcvt; "%s" %s $argv; end`, env.Exe, key), nil
	}
	return "", "", fmt.Errorf("unsupported shell %q (supported: bash, zsh, fish, PowerShell)", env.Shell)
}

func install(opts cmdline.Options, in io.Reader) int {
	env, err := currentInstallEnv()
	if err != nil {
		fmt.Fprintf(out, "%s[!] Error: %s%s\n", Red, err, Reset)
		return 1
	}
	return installWith(opts, in, env)
}

var errNoInput = errors.New("no input, aborting")

func installWith(opts cmdline.Options, in io.Reader, env installEnv) int {
	reader := bufio.NewReader(in)
	readLine := func(prompt string) (string, error) {
		fmt.Fprint(out, prompt)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(out)
			return "", errNoInput
		}
		return strings.TrimSpace(line), nil
	}
	fail := func(err error) int {
		fmt.Fprintf(out, "%s[!] Error: %s%s\n", Red, err, Reset)
		return 1
	}

	fmt.Fprintln(out, "\nThis creates an `rcvt` command with your API key built in,")
	fmt.Fprintln(out, "so you can just type `rcvt <File>` in the future.")

	key := opts.APIKey
	for !cmdline.IsAPIKey(key) {
		if key != "" {
			fmt.Fprintln(out, "That doesn't look like a VirusTotal API key (64 hex characters).")
		}
		var err error
		if key, err = readLine("Please enter your VirusTotal API Key: "); err != nil {
			return fail(err)
		}
	}

	path, line, err := aliasFor(env, key)
	if err != nil {
		return fail(err)
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fail(err)
	}
	if strings.Contains(string(existing), line) {
		fmt.Fprintf(out, "The alias is already in %s\n", path)
		return 0
	}

	fmt.Fprintf(out, "\nAppending to %s:\n  %s\n", path, line)
	confirm, err := readLine("Proceed? (y/N): ")
	if err != nil {
		return fail(err)
	}
	if strings.ToLower(confirm) != "y" {
		fmt.Fprintln(out, "No changes made. To add it yourself, put this line in your shell startup file:")
		fmt.Fprintln(out, line)
		return 0
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fail(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fail(err)
	}
	defer f.Close()

	if len(existing) > 0 && !strings.HasSuffix(string(existing), "\n") {
		line = "\n" + line
	}
	if _, err := f.WriteString(line + "\n"); err != nil {
		return fail(err)
	}

	fmt.Fprintf(out, "\nAlias added! Open a new shell to use `rcvt`.\n")
	return 0
}
