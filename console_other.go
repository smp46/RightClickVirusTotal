//go:build !windows

package main

import (
	"os"

	"golang.org/x/term"
)

// hasConsole reports whether CLI output would be visible. Arguments given
// without a terminal (scripts, pipes, cron) still count as CLI usage; only a
// bare launch, such as a double click in a file manager, falls back to the GUI.
func hasConsole() bool {
	return len(os.Args) > 1 ||
		term.IsTerminal(int(os.Stdin.Fd())) ||
		term.IsTerminal(int(os.Stdout.Fd()))
}
