package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func (a *App) AddRightClickShortcut(apiKey string) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("FATAL: Could not get user home directory: %v", err)
	}
	nautilusScriptsDir := filepath.Join(homeDir, ".local", "share", "nautilus", "scripts")
	if err := os.MkdirAll(nautilusScriptsDir, 0755); err != nil {
		log.Fatalf("FATAL: Could not create Nautilus scripts directory at %s: %v", nautilusScriptsDir, err)
	}
	executablePath, err := os.Executable()
	if err != nil {
		log.Fatalf("FATAL: Could not determine the path of this executable: %v", err)
	}
	scriptContent := fmt.Sprintf(`#!/bin/bash
		"%s" gui "%s" shortcut
		`, executablePath, apiKey)
	scriptFilePath := filepath.Join(nautilusScriptsDir, "Scan with VirusTotal")
	err = os.WriteFile(scriptFilePath, []byte(scriptContent), 0755)
	if err != nil {
		log.Fatalf("FATAL: Failed to write script file to %s: %v", scriptFilePath, err)
	}
}

func (a *App) ShortcutExists() bool {
	homeDir, _ := os.UserHomeDir()
	nautilusScriptsDir := filepath.Join(homeDir, ".local", "share", "nautilus", "scripts")
	scriptFilePath := filepath.Join(nautilusScriptsDir, "Scan with VirusTotal")

	if _, err := os.Stat(scriptFilePath); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func UsingNautilus() bool {
	cmd := exec.Command("xdg-mime", "query", "default", "inode/directory")

	output, err := cmd.Output()
	result := strings.TrimSpace(string(output))
	if err != nil {
		return false
	}
	return result == "org.gnome.Nautilus.desktop"
}
