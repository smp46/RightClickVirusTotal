package main

import (
	"os"
	"strings"

	"rcvt/internal/cmdline"
)

// startupPlan is what the GUI should do, worked out from the parsed
// arguments before any file is read or VirusTotal is contacted.
type startupPlan struct {
	APIKey         string
	FilePath       string
	Error          string
	OfferShortcut  bool
	FinishShortcut bool
}

type startupSys struct {
	GOOS string
	// CanAddShortcut reports whether a right click menu can be installed.
	CanAddShortcut func() bool
	Getenv         func(string) string
}

func planStartup(opts cmdline.Options, sys startupSys) startupPlan {
	plan := startupPlan{APIKey: opts.APIKey, FilePath: opts.FilePath}

	switch {
	case opts.Shortcut && sys.GOOS == "linux" && plan.FilePath == "":
		// Launched from the Nautilus script, which passes the selection
		// (one path per line) through the environment.
		for _, line := range strings.Split(sys.Getenv("NAUTILUS_SCRIPT_SELECTED_FILE_PATHS"), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				plan.FilePath = line
				break
			}
		}
		if plan.FilePath == "" {
			plan.Error = "Shortcut error: No file was selected in Nautilus."
			return plan
		}
	case opts.Shortcut && sys.GOOS == "windows":
		// Relaunched elevated to finish adding the context menu entry.
		plan.FinishShortcut = true
	default:
		plan.OfferShortcut = sys.GOOS == "windows" || (sys.GOOS == "linux" && sys.CanAddShortcut())
	}

	switch {
	case plan.APIKey == "" && plan.FilePath == "":
		plan.Error = "No arguments provided. Please provide the API key and file path."
	case plan.APIKey == "":
		plan.Error = "Missing API key."
	case plan.FilePath == "":
		plan.Error = "No file path provided."
	default:
		if info, err := os.Stat(plan.FilePath); err != nil {
			plan.Error = "Cannot read file: " + plan.FilePath
		} else if info.IsDir() {
			plan.Error = "Cannot scan a directory: " + plan.FilePath
		}
	}
	return plan
}
