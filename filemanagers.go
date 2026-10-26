package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// fileManager describes how to add a "Scan with VirusTotal" entry to one
// Linux file manager's right click menu.
type fileManager struct {
	Name string
	// Binary is looked up on PATH to decide whether the file manager is
	// installed. The default folder handler isn't used because it is often
	// something else, e.g. a terminal on tiling window managers.
	Binary  string
	Path    func(home string) string
	Content func(exe, apiKey string) string
}

const menuLabel = "Scan with VirusTotal"

var fileManagers = []fileManager{
	{
		// Nautilus scripts get the selection in an environment variable,
		// which the GUI reads itself when started with "shortcut".
		Name:   "Nautilus",
		Binary: "nautilus",
		Path: func(home string) string {
			return filepath.Join(home, ".local", "share", "nautilus", "scripts", menuLabel)
		},
		Content: func(exe, apiKey string) string {
			return fmt.Sprintf("#!/bin/sh\nexec %s gui %s shortcut\n", shellQuote(exe), apiKey)
		},
	},
	{
		Name:   "Caja",
		Binary: "caja",
		Path: func(home string) string {
			return filepath.Join(home, ".config", "caja", "scripts", menuLabel)
		},
		Content: func(exe, apiKey string) string {
			return fmt.Sprintf(`#!/bin/sh
file=$(printf '%%s\n' "$CAJA_SCRIPT_SELECTED_FILE_PATHS" | head -n 1)
exec %s gui %s -- "$file"
`, shellQuote(exe), apiKey)
		},
	},
	{
		Name:   "Nemo",
		Binary: "nemo",
		Path: func(home string) string {
			return filepath.Join(home, ".local", "share", "nemo", "actions", "rcvt-scan.nemo_action")
		},
		Content: func(exe, apiKey string) string {
			// Nemo splits Exec like a shell and quotes %F itself.
			return fmt.Sprintf(`[Nemo Action]
Name=%s
Comment=Upload the selected file to VirusTotal
Exec=%s gui %s %%F
Icon-Name=security-high
Selection=s
Extensions=nodirs;
`, menuLabel, strings.ReplaceAll(shellQuote(exe), "%", "%%"), apiKey)
		},
	},
	{
		Name:   "Dolphin",
		Binary: "dolphin",
		Path: func(home string) string {
			return filepath.Join(home, ".local", "share", "kio", "servicemenus", "rcvt-scan.desktop")
		},
		Content: func(exe, apiKey string) string {
			return fmt.Sprintf(`[Desktop Entry]
Type=Service
MimeType=all/allfiles;
Actions=scanWithVirusTotal;
X-KDE-Priority=TopLevel

[Desktop Action scanWithVirusTotal]
Name=%s
Icon=security-high
Exec=%s gui %s %%f
`, menuLabel, desktopExecQuote(exe), apiKey)
		},
	},
}

func detectFileManagers(lookPath func(string) (string, error)) []fileManager {
	var found []fileManager
	for _, fm := range fileManagers {
		if _, err := lookPath(fm.Binary); err == nil {
			found = append(found, fm)
		}
	}
	return found
}

// installMenus writes the menu entry for each file manager. Files are made
// executable: scripts need it to run, and Dolphin ignores service menus in
// the home directory that aren't.
func installMenus(fms []fileManager, home, exe, apiKey string) error {
	for _, fm := range fms {
		path := fm.Path(home)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("adding %s menu: %w", fm.Name, err)
		}
		if err := os.WriteFile(path, []byte(fm.Content(exe, apiKey)), 0755); err != nil {
			return fmt.Errorf("adding %s menu: %w", fm.Name, err)
		}
		// WriteFile keeps the mode of an existing file.
		if err := os.Chmod(path, 0755); err != nil {
			return fmt.Errorf("adding %s menu: %w", fm.Name, err)
		}
	}
	return nil
}

// menusInstalled reports whether every given file manager has the entry.
func menusInstalled(fms []fileManager, home string) bool {
	if len(fms) == 0 {
		return false
	}
	for _, fm := range fms {
		if _, err := os.Stat(fm.Path(home)); err != nil {
			return false
		}
	}
	return true
}

// desktopExecQuote quotes an argument for the Exec key of a .desktop file:
// the quoting rule escapes " ` $ and \ inside double quotes, then the
// string escape rule doubles every backslash, and % is a field code prefix.
func desktopExecQuote(s string) string {
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune("\"`$\\", c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	quoted := strings.ReplaceAll(b.String(), `\`, `\\`)
	return `"` + strings.ReplaceAll(quoted, "%", "%%") + `"`
}

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
