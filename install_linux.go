package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
)

func (a *App) AddRightClickShortcut(apiKey string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	fms := detectFileManagers(exec.LookPath)
	if len(fms) == 0 {
		return errors.New("no supported file manager found (Nautilus, Caja, Nemo or Dolphin)")
	}
	return installMenus(fms, home, exe, apiKey)
}

func (a *App) ShortcutExists() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	return menusInstalled(detectFileManagers(exec.LookPath), home)
}

func canAddShortcut() bool {
	return len(detectFileManagers(exec.LookPath)) > 0
}
