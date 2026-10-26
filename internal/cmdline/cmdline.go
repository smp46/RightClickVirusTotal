// Package cmdline parses the command line shared by the CLI and GUI modes.
//
// Keywords and flags may appear anywhere before a "--" separator. Everything
// else is positional: an API key and/or a file path, in either order.
package cmdline

import (
	"errors"
	"fmt"
	"strings"
)

type Action int

const (
	ActionScan Action = iota
	ActionHelp
	ActionVersion
	ActionInstall
)

type Options struct {
	Action   Action
	ForceGUI bool
	ForceCLI bool
	// Shortcut is set when launched from an installed right click shortcut.
	Shortcut bool
	APIKey   string
	FilePath string
}

func Parse(args []string) (Options, error) {
	opts := Options{Action: ActionScan}
	var positionals []string

	setAction := func(a Action) {
		// Help wins over everything, otherwise the first action given sticks.
		if opts.Action == ActionScan || a == ActionHelp {
			opts.Action = a
		}
	}

	for i, arg := range args {
		if arg == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		switch arg {
		case "gui", "--gui":
			opts.ForceGUI = true
		case "--cli":
			opts.ForceCLI = true
		case "shortcut", "--shortcut":
			opts.Shortcut = true
		case "-h", "--help", "help":
			setAction(ActionHelp)
		case "-v", "--version", "version":
			setAction(ActionVersion)
		case "install", "--install":
			setAction(ActionInstall)
		default:
			if len(arg) > 1 && strings.HasPrefix(arg, "-") {
				return opts, fmt.Errorf("unknown option %q (use -- before a file name starting with '-')", arg)
			}
			positionals = append(positionals, arg)
		}
	}

	if opts.ForceGUI && opts.ForceCLI {
		return opts, errors.New("--gui and --cli cannot be used together")
	}

	switch len(positionals) {
	case 0:
	case 1:
		if p := strings.TrimSpace(positionals[0]); IsAPIKey(p) {
			opts.APIKey = p
		} else {
			opts.FilePath = positionals[0]
		}
	case 2:
		first, second := strings.TrimSpace(positionals[0]), strings.TrimSpace(positionals[1])
		switch {
		case IsAPIKey(first):
			opts.APIKey, opts.FilePath = first, positionals[1]
		case IsAPIKey(second):
			opts.APIKey, opts.FilePath = second, positionals[0]
		default:
			return opts, errors.New("expected a VirusTotal API key (64 hex characters) and a file path")
		}
	default:
		return opts, fmt.Errorf("too many arguments: %q", positionals)
	}

	return opts, nil
}

// IsAPIKey reports whether s looks like a VirusTotal API key.
func IsAPIKey(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// UseGUI decides which interface to launch. Without an explicit choice the
// GUI is used when there is no console to print to, e.g. when launched from
// a file manager or by double clicking.
func (o Options) UseGUI(hasConsole bool) bool {
	switch {
	case o.Action != ActionScan:
		return false
	case o.ForceGUI:
		return true
	case o.ForceCLI:
		return false
	case o.Shortcut:
		return true
	default:
		return !hasConsole
	}
}
