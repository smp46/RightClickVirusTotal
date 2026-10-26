package main

import (
	"fmt"
	"strings"
)

// contextMenuCommand is the registry command run when a file is right
// clicked in Explorer. %1 is replaced with the clicked file.
func contextMenuCommand(exe, apiKey string) string {
	return fmt.Sprintf(`"%s" gui %s "%%1"`, exe, apiKey)
}

// elevationArgs is the command line for the elevated relaunch that finishes
// adding the context menu entry.
func elevationArgs(apiKey, filePath string) string {
	args := []string{"gui", "shortcut", apiKey}
	if filePath != "" {
		if strings.HasPrefix(filePath, "-") {
			args = append(args, "--")
		}
		args = append(args, escapeWindowsArg(filePath))
	}
	return strings.Join(args, " ")
}

// escapeWindowsArg quotes s so CommandLineToArgvW reads it back unchanged.
// It mirrors syscall.EscapeArg, which only exists on Windows builds.
func escapeWindowsArg(s string) string {
	if s == "" {
		return `""`
	}
	needsBackslash := strings.ContainsAny(s, `"\`)
	hasSpace := strings.ContainsAny(s, " \t")
	if !needsBackslash && !hasSpace {
		return s
	}
	if !needsBackslash {
		return `"` + s + `"`
	}

	var b strings.Builder
	if hasSpace {
		b.WriteByte('"')
	}
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes+1))
			slashes = 0
		default:
			slashes = 0
		}
		b.WriteByte(c)
	}
	if hasSpace {
		b.WriteString(strings.Repeat(`\`, slashes))
		b.WriteByte('"')
	}
	return b.String()
}
