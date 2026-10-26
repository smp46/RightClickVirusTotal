package main

import (
	"os"

	"golang.org/x/sys/windows"
)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

const attachParentProcess = ^uintptr(0) // ATTACH_PARENT_PROCESS, (DWORD)-1

// hasConsole reports whether CLI output would be visible. Release builds use
// the Windows GUI subsystem and get no console of their own, so when started
// from a terminal we attach to the parent's console and point any standard
// streams that weren't redirected at it.
func hasConsole() bool {
	hasOut := validHandle(windows.STD_OUTPUT_HANDLE)
	hasErr := validHandle(windows.STD_ERROR_HANDLE)
	hasIn := validHandle(windows.STD_INPUT_HANDLE)

	if r, _, _ := procAttachConsole.Call(attachParentProcess); r == 0 {
		// No parent console, but output may still be redirected to a file.
		return hasOut
	}
	if !hasOut {
		if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stdout = f
		}
	}
	if !hasErr {
		if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
			os.Stderr = f
		}
	}
	if !hasIn {
		if f, err := os.OpenFile("CONIN$", os.O_RDWR, 0); err == nil {
			os.Stdin = f
		}
	}
	return true
}

func validHandle(std uint32) bool {
	h, err := windows.GetStdHandle(std)
	return err == nil && h != 0 && h != windows.InvalidHandle
}
