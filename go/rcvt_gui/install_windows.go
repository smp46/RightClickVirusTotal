package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func (a *App) AddRightClickShortcut(apiKey string) error {
	if !checkAdmin() {
		becomeAdmin()
		return
	}

	path := getExecutablePath()
	if path == "" {
		return error.New("failed to get executable path")
	}
	return addRegKeys(executablePath, apiKey)
}

func (a *App) ShortcutExists() bool {
	key, err := registry.OpenKey(
		registry.CLASSES_ROOT,
		`*\shell\Upload to VirusTotal`,
		registry.KEY_READ|registry.WOW64_64KEY,
	)
	defer key.Close()

	if err != nil {
		return false
	}
	return true
}

func addRegKeys(executablePath, apiKey string) error {
	// Create the main key for the context menu entry.
	vtKey, _, err := registry.CreateKey(
		registry.CLASSES_ROOT,
		`*\shell\Upload to VirusTotal`,
		registry.KEY_WRITE|registry.WOW64_64KEY,
	)
	if err != nil {
		return fmt.Errorf("failed to create main context menu key: %w", err)
	}
	defer vtKey.Close()

	// Set the icon for the context menu entry.
	err = vtKey.SetStringValue("Icon", executablePath)
	if err != nil {
		return fmt.Errorf("failed to set icon value: %w", err)
	}

	// Create the "command" subkey.
	commandKey, _, err := registry.CreateKey(vtKey, "command", registry.KEY_WRITE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("failed to create command key: %w", err)
	}
	defer commandKey.Close()

	// Set the default value for the command key.
	command := fmt.Sprintf(`%s "%s" "%%1"`, executablePath, apiKey)
	err = commandKey.SetStringValue("", command)
	if err != nil {
		return fmt.Errorf("failed to set command value: %w", err)
	}

	return nil
}

func checkAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")

	return err == nil
}

func becomeAdmin() {
	verb := "runas"
	exe, _ := os.Executable()
	cwd, _ := os.Getwd()
	args := strings.Join(os.Args[1:], " ")

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1

	err := windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		// Failed to become admin
		return
	}
}

func getExecutablePath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Abs(executable)
}
