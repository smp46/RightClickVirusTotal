package cli

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rcvt/internal/cmdline"

	vt "github.com/VirusTotal/vt-go"
	"golang.org/x/term"
)

// ANSI color codes
const (
	Reset     = "\033[0m"
	Green     = "\033[32m"
	Blue      = "\033[34m"
	Red       = "\033[31m"
	Yellow    = "\033[33m"
	White     = "\033[37m"
	Dim       = "\033[2m"
	CursorUp  = "\033[A"
	ClearLine = "\033[K"
)

type Stats struct {
	Harmless   int
	Malicious  int
	Suspicious int
	Undetected int
}

const VERSION string = "v2.0.4"

// pollInterval is how often the analysis spinner ticks.
var pollInterval = time.Second

// out is where all CLI output is written, set by Run.
var out io.Writer = os.Stdout

func Interface(stage string, file_name string, loading_dots int, stats *Stats) {
	switch stage {
	case "title":
		width, height, err := term.GetSize(int(os.Stdout.Fd()))

		required_width := 73
		required_height := 6

		// Check if terminal has enough space
		if err == nil && width >= required_width && height >= required_height {
			// Terminal has enough space, print the title
			fmt.Fprintln(out, "  ___ _      _   _    ___ _ _    _  __   ___             _____    _        _ ")
			fmt.Fprintln(out, " | _ (_)__ _| |_| |_ / __| (_)__| |_\\ \\ / (_)_ _ _  _ __|_   ____| |_ __ _| |")
			fmt.Fprintln(out, " |   | / _` | ' |  _| (__| | / _| / /\\ V /| | '_| || (_-< | |/ _ |  _/ _` | |")
			fmt.Fprintln(out, " |_|_|_\\__, |_||_\\__|\\___|_|_\\__|_\\_\\ \\_/ |_|_|  \\_,_/__/ |_|\\___/\\__\\__,_|_|")
			fmt.Fprintln(out, "       |___/                                                                 ")
			fmt.Fprintln(out, "                                                                      "+VERSION)
		} else {
			// Not enough space, print small title and version
			fmt.Fprintln(out, "\nRightClickVirusTotal")
			fmt.Fprintln(out, VERSION)
		}
	case "uploading":
		fmt.Fprintf(out, "\nChecking File: %s\n", file_name)
		fmt.Fprintf(out, "%s[ ] File Uploading...%s\n", Green, Reset)

	case "uploaded":
		fmt.Fprintf(out, "%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Fprintf(out, "[✓] File Uploaded\n\n")

	case "analysing":
		fmt.Fprintf(out, "%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Fprintf(out, "[ ] File Analysing%s\n", strings.Repeat(".", loading_dots))

	case "analysed":
		fmt.Fprintf(out, "%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Fprintf(out, "[✓] Analysis Complete\n\n")

	case "results":
		fmt.Fprintf(out, "%sFile: %s%s\n", Blue, file_name, Reset)
		fmt.Fprintf(out, "%sHarmless: %d%s\n", Green, stats.Harmless, Reset)
		fmt.Fprintf(out, "%sMalicious: %d%s\n", Red, stats.Malicious, Reset)
		fmt.Fprintf(out, "%sSuspicious: %d%s\n", Yellow, stats.Suspicious, Reset)
		fmt.Fprintf(out, "%s%sUndetected: %d%s\n", White, Dim, stats.Undetected, Reset)
	}
}

func hash_file(file_path string) (string, error) {
	file, err := os.ReadFile(file_path)
	if err != nil {
		return "", err
	}
	md5_hash_byte := md5.Sum(file)
	return hex.EncodeToString(md5_hash_byte[:]), nil
}

func scan_file(client *vt.Client, file_path string) error {
	loading_dots := 0
	api_counter := 0

	file_name := filepath.Base(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		return err
	}
	defer file.Close()

	file_scanner := client.NewFileScanner()
	analysis, err := file_scanner.ScanFile(file, nil)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}

	analysis_url := vt.URL("analyses/%s", analysis.ID())

	for {
		Interface("analysing", file_name, loading_dots, nil)
		loading_dots = (loading_dots + 1) % 4

		time.Sleep(pollInterval)

		if api_counter%15 == 0 {
			analysis, err := client.GetObject(analysis_url)
			if err != nil {
				return fmt.Errorf("checking analysis status: %w", err)
			}
			status, err := analysis.GetString("status")
			if err != nil {
				return fmt.Errorf("checking analysis status: %w", err)
			}
			if status == "completed" {
				break
			}
		}
		api_counter += 1
	}

	Interface("analysed", file_name, 0, nil)
	return nil
}

func displayHelp() {
	Interface("title", "", 0, nil)

	prog := filepath.Base(os.Args[0])
	fmt.Fprintln(out, "\nUsage:")
	fmt.Fprintf(out, "  %s%s [options] <VirusTotalAPIKey> <FilePath>%s\n", Green, prog, Reset)
	fmt.Fprintf(out, "  %s%s install%s\n", Green, prog, Reset)
	fmt.Fprintln(out, "\nArguments:")
	fmt.Fprintf(out, "  %s<VirusTotalAPIKey>%s  VirusTotal API key\n", Blue, Reset)
	fmt.Fprintf(out, "  %s<FilePath>%s          Path to the file you want to scan\n\n", Blue, Reset)
	fmt.Fprintln(out, "Options:")
	fmt.Fprintf(out, "  %sgui, --gui%s          Open the graphical interface\n", Blue, Reset)
	fmt.Fprintf(out, "  %s--cli%s               Use the terminal interface even without a console\n", Blue, Reset)
	fmt.Fprintf(out, "  %sinstall, --install%s  Create a shell alias with your API key for easier usage\n", Blue, Reset)
	fmt.Fprintf(out, "  %s-v, --version%s       Print the version\n", Blue, Reset)
	fmt.Fprintf(out, "  %s-h, --help%s          Show this help\n", Blue, Reset)
	fmt.Fprintf(out, "  %s--%s                  Treat everything after as a file path\n", Blue, Reset)
	fmt.Fprintln(out, "\nExample:")
	fmt.Fprintf(out, "  %s%s YOUR_API_KEY file.exe%s\n", Dim, prog, Reset)
}

// Run executes the CLI for already parsed options and returns the exit code.
func Run(opts cmdline.Options, in io.Reader, w io.Writer) int {
	out = w

	switch opts.Action {
	case cmdline.ActionHelp:
		displayHelp()
		return 0
	case cmdline.ActionVersion:
		fmt.Fprintln(out, VERSION)
		return 0
	case cmdline.ActionInstall:
		return install(opts, in)
	}

	if opts.APIKey == "" && opts.FilePath == "" {
		displayHelp()
		return 0
	}
	if err := validateScan(opts); err != nil {
		fmt.Fprintf(out, "%s[!] Error: %s%s\n", Red, err, Reset)
		fmt.Fprintf(out, "Run '%s --help' for usage.\n", filepath.Base(os.Args[0]))
		return 2
	}

	if err := scan(opts.APIKey, opts.FilePath); err != nil {
		fmt.Fprintf(out, "%s[!] Error: %s%s\n", Red, err, Reset)
		return 1
	}
	return 0
}

func validateScan(opts cmdline.Options) error {
	if opts.APIKey == "" {
		return fmt.Errorf("missing VirusTotal API key")
	}
	if opts.FilePath == "" {
		return fmt.Errorf("missing file path")
	}
	info, err := os.Stat(opts.FilePath)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("%s is a directory, not a file", opts.FilePath)
	}
	return nil
}

func scan(VirusTotalAPIKey, file_path string) error {
	file_name := filepath.Base(file_path)

	Interface("title", "", 0, nil)
	Interface("uploading", file_name, 0, nil)

	client := vt.NewClient(VirusTotalAPIKey)
	md5_hash, err := hash_file(file_path)
	if err != nil {
		return err
	}

	file_url := vt.URL("files/%s", md5_hash)
	file_object, err := client.GetObject(file_url)

	if err == nil {
		Interface("uploaded", file_name, 0, nil)
		Interface("analysed", file_name, 0, nil)
	} else {
		if err := scan_file(client, file_path); err != nil {
			return err
		}

		file_object, err = client.GetObject(file_url)
		if err != nil {
			return fmt.Errorf("fetching results: %w", err)
		}
		Interface("uploaded", file_name, 0, nil)
	}

	stats, err := parseStats(file_object)
	if err != nil {
		return err
	}

	Interface("results", file_name, 0, &stats)
	return nil
}

func parseStats(file_object *vt.Object) (Stats, error) {
	var stats Stats

	stats_data, err := file_object.Get("last_analysis_stats")
	if err != nil {
		return stats, fmt.Errorf("reading results: %w", err)
	}

	stats_map, ok := stats_data.(map[string]any)
	if !ok {
		return stats, fmt.Errorf("reading results: unexpected last_analysis_stats format")
	}

	for keyStr, v := range stats_map {
		num, _ := v.(json.Number)
		intVal, _ := num.Int64()

		switch keyStr {
		case "harmless":
			stats.Harmless = int(intVal)
		case "malicious":
			stats.Malicious = int(intVal)
		case "suspicious":
			stats.Suspicious = int(intVal)
		case "undetected":
			stats.Undetected = int(intVal)
		}
	}

	return stats, nil
}
