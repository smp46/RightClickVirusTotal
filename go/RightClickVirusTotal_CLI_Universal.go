package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	vt "github.com/VirusTotal/vt-go"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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

func Interface(stage string, file_name string, loading_dots int, stats *Stats) {
	switch stage {
	case "title":
		fmt.Println("  ___ _      _   _    ___ _ _    _  __   ___             _____    _        _ ")
		fmt.Println(" | _ (_)__ _| |_| |_ / __| (_)__| |_\\ \\ / (_)_ _ _  _ __|_   ____| |_ __ _| |")
		fmt.Println(" |   | / _` | ' |  _| (__| | / _| / /\\ V /| | '_| || (_-< | |/ _ |  _/ _` | |")
		fmt.Println(" |_|_|_\\__, |_||_\\__|\\___|_|_\\__|_\\_\\ \\_/ |_|_|  \\_,_/__/ |_|\\___/\\__\\__,_|_|")
		fmt.Println("       |___/                                                                 ")

	case "uploading":
		fmt.Printf("\nChecking File: %s\n", file_name)
		fmt.Printf("%s[ ] File Uploading...%s\n", Green, Reset)

	case "uploaded":
		fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Printf("[✓] File Uploaded\n\n")

	case "analysing":
		fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Printf("[ ] File Analysing%s\n", strings.Repeat(".", loading_dots))

	case "analysed":
		fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
		fmt.Printf("[✓] Analysis Complete\n\n")

	case "results":
		fmt.Printf("%sFile: %s%s\n", Blue, file_name, Reset)
		fmt.Printf("%sHarmless: %d%s\n", Green, stats.Harmless, Reset)
		fmt.Printf("%sMalicious: %d%s\n", Red, stats.Malicious, Reset)
		fmt.Printf("%sSuspicious: %d%s\n", Yellow, stats.Suspicious, Reset)
		fmt.Printf("%s%sUndetected: %d%s\n", White, Dim, stats.Undetected, Reset)
	case "error":
		fmt.Printf("%s[!] Error: %s%s\n", Red, file_name, Reset)
		os.Exit(1)
	}
}

func hash_file(file_path string) string {
	file, err := os.ReadFile(file_path)
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}
	md5_hash_byte := md5.Sum(file)
	md5_hash := hex.EncodeToString(md5_hash_byte[:])
	return md5_hash
}

func scan_file(client *vt.Client, file_path string) {
	loading_dots := 0
	api_counter := 0

	file_name := filepath.Base(file_path)

	file, err := os.Open(file_path)
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}
	defer file.Close()

	file_scanner := client.NewFileScanner()
	analysis, err := file_scanner.ScanFile(file, nil)
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}

	analysis_url_str := "https://www.virustotal.com/api/v3/analyses/" + analysis.ID()

	analysis_url, err := url.Parse(analysis_url_str)
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}

	analysis_complete := false

	for !analysis_complete {
		Interface("analysing", file_name, loading_dots, nil)
		loading_dots = (loading_dots + 1) % 4

		time.Sleep(1000 * time.Millisecond)

		if api_counter%15 == 0 {
			analysis, err := client.GetObject(analysis_url)
			analysis_status, err := analysis.Get("status")
			analysis_status_str := ""
			if err != nil {
				Interface("error", err.Error(), 0, nil)
			} else {
				analysis_status_str, _ = analysis_status.(string)
			}

			if analysis_status_str == "completed" {
				analysis_complete = true
			}
		}
		api_counter += 1
	}

	Interface("analysed", file_name, 0, nil)
}

func createAlias() {
	var VirusTotalAPIKey string = " "
	for len(VirusTotalAPIKey) != 64 {
		fmt.Print("Please enter your VirusTotal API Key: ")
		fmt.Scanln(&VirusTotalAPIKey)
	}

	shell := ""
	home := ""
	if runtime.GOOS == "windows" {
		shell = os.Getenv("ComSpec")
		home = os.Getenv("Home")
	} else {
		shell = os.Getenv("SHELL")
		home = os.Getenv("HOME")
	}

	rcvt_path, err := os.Executable()
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}

	rc_path := ""
	alias := ""

	switch {
	case strings.Contains(shell, "bash"):
		rc_path = home + "/.bashrc"
		alias = "alias rcvt=\"" + rcvt_path + " " + VirusTotalAPIKey + "\""
	case strings.Contains(shell, "zsh"):
		rc_path = home + "/.zshrc"
		alias = "alias rcvt=\"" + rcvt_path + " " + VirusTotalAPIKey + "\""
	case strings.Contains(strings.ToLower(shell), "powershell"):
		rc_path = home + "\\Documents\\profile.ps1"
		alias = "New-Alias rcvt \"" + rcvt_path + " " + VirusTotalAPIKey + "\""
	default:
		fmt.Println("Couldn't detect the current shell.\nCannot create an alias. Bye bye.")
		os.Exit(1)
	}

	var confirm string
	fmt.Println("Appending alias to: " + rc_path)
	fmt.Print("Procced? (Yy/Nn): ")
	fmt.Scanln(&confirm)
	if strings.ToLower(confirm) == "y" {
		f, err := os.OpenFile(rc_path,
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			Interface("error", err.Error(), 0, nil)
		}
		defer f.Close()
		if _, err := f.WriteString(alias); err != nil {
			Interface("error", err.Error(), 0, nil)
		}
	} else {
		fmt.Println("You've chosen to not append an alias.\nHere's the alias if you want to add it manually:")
		fmt.Println(alias)
		os.Exit(0)
	}

	fmt.Println("\nAlias added successfully!\nRestart your shell, or run `source " + rc_path + "` to use rcvt")

	return
}

func displayHelp() {
	Interface("title", "", 0, nil)

	fmt.Println("\nUsage:")
	fmt.Printf("  %s <VirusTotalAPIKey> <FilePath>%s\n", Green, Reset)
	fmt.Println("\nArguments:")
	fmt.Printf("  %s<VirusTotalAPIKey>%s  VirusTotal API key\n", Blue, Reset)
	fmt.Printf("  %s<FilePath>%s          Path to the file you want to scan\n\n", Blue, Reset)
	fmt.Println("Options:")
	fmt.Printf("  %s--install%s           Create an alias with your API key for easier usage\n", Blue, Reset)
	fmt.Println("\nExample:")
	fmt.Printf("  %s%s YOUR_API_KEY file.exe%s\n", Dim, os.Args[0], Reset)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--install" {
		fmt.Println("\nWould you like to create an alias with your API key?")
		fmt.Println("This will allow you to just type `rcvt <File>` in the future.")
		fmt.Print("(Yy/Nn): ")
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) == "y" {
			createAlias()
		} else {
			fmt.Println("You've chosen to not create an alias, bye bye.")
			os.Exit(0)
		}
		createAlias()
		os.Exit(0)
	}

	if len(os.Args) != 3 {
		displayHelp()
		return
	}

	VirusTotalAPIKey := os.Args[1]
	file_path := os.Args[2]

	file_name := filepath.Base(file_path)

	Interface("title", "", 0, nil)
	Interface("uploading", file_name, 0, nil)

	client := vt.NewClient(VirusTotalAPIKey)
	md5_hash := hash_file(file_path)

	file_url, err := url.Parse("https://www.virustotal.com/api/v3/files/" + md5_hash)
	file_object, err := client.GetObject(file_url)

	if err == nil {
		Interface("uploaded", file_name, 0, nil)
		Interface("analysed", file_name, 0, nil)
	} else {
		scan_file(client, file_path)

		file_object, err = client.GetObject(file_url)
		if err != nil {
			Interface("error", err.Error(), 0, nil)
		}
		Interface("uploaded", file_name, 0, nil)
	}

	stats_data, err := file_object.Get("last_analysis_stats")
	if err != nil {
		Interface("error", err.Error(), 0, nil)
	}

	stats_map, ok := stats_data.(map[string]interface{})
	if !ok {
		Interface("error", err.Error(), 0, nil)
	}

	var stats Stats

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

	Interface("results", file_name, 0, &stats)
}
