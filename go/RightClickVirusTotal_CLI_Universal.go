package main 

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
    "strings"
    "time"
	"crypto/md5"
	"net/url"
	"encoding/hex"
	vt "github.com/VirusTotal/vt-go"
)

// ANSI color codes
const (
    Reset      = "\033[0m"
    Green      = "\033[32m"
    Blue       = "\033[34m"
    Red        = "\033[31m"
    Yellow     = "\033[33m"
    White      = "\033[37m"
    Dim        = "\033[2m"
    CursorUp   = "\033[A"
    ClearLine  = "\033[K"
)

type Stats struct {
    Harmless   int
    Malicious  int
    Suspicious int
    Undetected int
}

func Interface(printStage string, fileName string, loadingDots int, stats *Stats) {
    switch printStage {
    case "title":
        fmt.Println("  ___ _      _   _    ___ _ _    _  __   ___             _____    _        _ ")
        fmt.Println(" | _ (_)__ _| |_| |_ / __| (_)__| |_\\ \\ / (_)_ _ _  _ __|_   ____| |_ __ _| |")
        fmt.Println(" |   | / _` | ' |  _| (__| | / _| / /\\ V /| | '_| || (_-< | |/ _ |  _/ _` | |")
        fmt.Println(" |_|_|_\\__, |_||_\\__|\\___|_|_\\__|_\\_\\ \\_/ |_|_|  \\_,_/__/ |_|\\___/\\__\\__,_|_|")
        fmt.Println("       |___/                                                                 ")

    case "uploading":
        fmt.Printf("\nChecking File: %s\n", fileName)
        fmt.Printf("%s[ ] File Uploading...%s\n", Green, Reset)

    case "uploaded":
        fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
        fmt.Printf("[✓] File Uploaded\n\n")

    case "analysing":
        fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
        fmt.Printf("[ ] File Analysing%s\n", strings.Repeat(".", loadingDots))

    case "analysed":
        fmt.Printf("%s%s%s\n", CursorUp, strings.Repeat(" ", 30), CursorUp)
        fmt.Printf("[✓] Analysis Complete\n\n")

    case "results":
        fmt.Printf("%sFile: %s%s\n", Blue, fileName, Reset)
        fmt.Printf("%sHarmless: %d%s\n", Green, stats.Harmless, Reset)
        fmt.Printf("%sMalicious: %d%s\n", Red, stats.Malicious, Reset)
        fmt.Printf("%sSuspicious: %d%s\n", Yellow, stats.Suspicious, Reset)
        fmt.Printf("%s%sUndetected: %d%s\n", White, Dim, stats.Undetected, Reset)
    }
}

func hash_file(file_path string) string {
    file, err := os.ReadFile(file_path)
    if err != nil {
        log.Fatal(err)
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
        log.Fatal(err)
    }
    defer file.Close()

    file_scanner := client.NewFileScanner()
    analysis, err := file_scanner.ScanFile(file, nil)
    if err != nil {
        log.Fatal(err)
    }
    analysis_url, err := url.Parse(fmt.Sprintf("/analyses/%s", analysis.ID()))
    if err != nil {
        log.Fatal(err)
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
                log.Printf("Error getting status: %v", err)
                continue
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

func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: <script> <VirusTotalAPIKey> <FilePath>")
        os.Exit(1)
    }

	VIRUSTOTALAPIKEY := os.Args[1]
    file_path := os.Args[2]

    file_name := filepath.Base(file_path)

    Interface("title", "", 0, nil)
    Interface("uploading", file_name, 0, nil)

    client := vt.NewClient(VIRUSTOTALAPIKEY)
    md5_hash := hash_file(file_path)

    file_url, err := url.Parse("/files/" + md5_hash)
    if err != nil {
        log.Fatal(err)
    }

    file_object, err := client.GetObject(file_url)
    if err == nil {
        Interface("uploaded", file_name, 0, nil)
        Interface("analysed", file_name, 0, nil)
    } else {
        scan_file(client, file_path)

        file_object, err = client.GetObject(file_url)
        if err != nil {
            log.Fatal(err)
        }
        Interface("uploaded", file_name, 0, nil)
    }

    statsMap, err := file_object.GetContext("last_analysis_stats")
    if err != nil {
        log.Printf("Error getting stats: %v", err)
        return
    }

    stats := &Stats{}

    if harmless, ok := statsMap.(map[string]interface{})["harmless"].(float64); ok {
        stats.Harmless = int(harmless)
    }
    if malicious, ok := statsMap.(map[string]interface{})["malicious"].(float64); ok {
        stats.Malicious = int(malicious)
    }
    if suspicious, ok := statsMap.(map[string]interface{})["suspicious"].(float64); ok {
        stats.Suspicious = int(suspicious)
    }
    if undetected, ok := statsMap.(map[string]interface{})["undetected"].(float64); ok {
        stats.Undetected = int(undetected)
    }

    Interface("results", file_name, 0, stats)
}
