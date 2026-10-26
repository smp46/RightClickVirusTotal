package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func (a *App) AddRightClickShortcut(apiKey string) error {
	if !checkAdmin() {
		if err := becomeAdmin(elevationArgs(apiKey, file_path)); err != nil {
			return fmt.Errorf("failed to restart as administrator: %w", err)
		}
		runtime.Quit(a.ctx)
		return nil
	}

	executablePath := getExecutablePath()
	if executablePath == "" {
		return fmt.Errorf("failed to get executable path")
	}
	return addRegKeys(executablePath, apiKey)
}

func (a *App) ShortcutExists() bool {
	key, err := registry.OpenKey(
		registry.CLASSES_ROOT,
		`*\shell\Upload to VirusTotal`,
		registry.READ|registry.WOW64_64KEY,
	)
	if err != nil {
		return false
	}
	key.Close()
	return true
}

func addRegKeys(executablePath, apiKey string) error {
	// Create the main key for the context menu entry.
	vtKey, _, err := registry.CreateKey(
		registry.CLASSES_ROOT,
		`*\shell\Upload to VirusTotal`,
		registry.WRITE|registry.WOW64_64KEY,
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
	commandKey, _, err := registry.CreateKey(vtKey, "command", registry.WRITE|registry.WOW64_64KEY)
	if err != nil {
		return fmt.Errorf("failed to create command key: %w", err)
	}
	defer commandKey.Close()

	// Set the default value for the command key.
	err = commandKey.SetStringValue("", contextMenuCommand(executablePath, apiKey))
	if err != nil {
		return fmt.Errorf("failed to set command value: %w", err)
	}

	return nil
}

func checkAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// becomeAdmin relaunches this executable elevated with the given command line.
func becomeAdmin(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	return windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, windows.SW_NORMAL)
}

func getExecutablePath() string {
	executable, err := os.Executable()
	if err != nil {
		return ""
	}
	absPath, err := filepath.Abs(executable)
	if err != nil {
		return ""
	}
	return absPath
}

func canAddShortcut() bool {
	return true
}
