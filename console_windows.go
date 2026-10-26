package main

import (
	"os"

	"golang.org/x/term"
)

func hasConsole() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) || term.IsTerminal(int(os.Stdout.Fd()))
}
