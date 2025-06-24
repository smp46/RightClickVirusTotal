package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

// -- START TEMPLATE CODE --

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called at application startup
func (a *App) startup(ctx context.Context) {
	// Perform your setup here
	a.ctx = ctx

	a.start()
}

// domReady is called after front-end resources have been loaded
func (a App) domReady(ctx context.Context) {
	// Add your action here
}

// beforeClose is called when the application is about to quit,
// either by clicking the window close button or calling runtime.Quit.
// Returning true will cause the application to continue, false will continue shutdown as normal.
func (a *App) beforeClose(ctx context.Context) (prevent bool) {
	return false
}

// shutdown is called at application termination
func (a *App) shutdown(ctx context.Context) {
	// Perform your teardown here
}

// -- END TEMPLATE CODE --

type Stats struct {
	Harmless   int
	Malicious  int
	Suspicious int
	Undetected int
}

var client *vt.Client
var VT_API_Key string
var file_name string
var file_path string
var file_hash string
var file_object *vt.Object
var file_url *url.URL
var analysis_url *url.URL

func (a *App) start() {
	VT_API_Key = os.Args[1]
	file_path = os.Args[2]
	file_name = filepath.Base(file_path)

	client = vt.NewClient(VT_API_Key)
	file_hash = a.hash_file(file_path)

	file_url, _ = url.Parse("https://www.virustotal.com/api/v3/files/" + file_hash)
	file_object, _ = client.GetObject(file_url)
}

func (a *App) get_file_info() (string, int64) {
	file, err := os.Stat(file_path)
	if err != nil {
		return "", 0
	}

	return file_name, file.Size()
}

func (a *App) hash_file(file_path string) string {
	file, err := os.ReadFile(file_path)
	if err != nil {
		println("Error reading file:", err)
	}
	md5_hash_byte := md5.Sum(file)
	md5_hash := hex.EncodeToString(md5_hash_byte[:])
	return md5_hash
}

func (a *App) start_file_scan() (bool, string) {
	file, err := os.Open(file_path)
	if err != nil {
		return false, err.Error()
	}
	defer file.Close()

	file_scanner := client.NewFileScanner()
	analysis, err := file_scanner.ScanFile(file, nil)
	if err != nil {
		return false, err.Error()
	}

	analysis_url_str := "https://www.virustotal.com/api/v3/analyses/" + analysis.ID()

	analysis_url, err = url.Parse(analysis_url_str)
	if err != nil {
		return false, err.Error()
	}

	return true, ""
}

func (a *App) check_analysis_status() (bool, string) {
	api_counter := 0
	analysis_complete := false

	for !analysis_complete {
		time.Sleep(1000 * time.Millisecond)

		if api_counter%15 == 0 {
			analysis, _ := client.GetObject(analysis_url)
			analysis_status, err := analysis.Get("status")
			analysis_status_str := ""
			if err != nil {
				return false, err.Error()
			} else {
				analysis_status_str, _ = analysis_status.(string)
			}

			if analysis_status_str == "completed" {
				analysis_complete = true
			}
		}
		api_counter += 1
	}

	return true, ""
}

func (a *App) confirm_analysis_success() bool {
	var err error
	file_object, err = client.GetObject(file_url)
	if err != nil {
		return false
	}
	return true
}

func (a *App) get_analysis_results() (bool, Stats) {
	stats_data, err := file_object.Get("last_analysis_stats")
	if err != nil {
		return false, Stats{}
	}

	stats_map, ok := stats_data.(map[string]any)
	if !ok {
		return false, Stats{}
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

	return true, stats
}
