package main

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"rcvt/internal/cmdline"

	vt "github.com/VirusTotal/vt-go"
)

// App struct
type App struct {
	ctx  context.Context
	opts cmdline.Options
}

// NewApp creates a new App application struct
func NewApp(opts cmdline.Options) *App {
	return &App{opts: opts}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	a.start()
}

// Greet returns a greeting for the given name
func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

type Stats struct {
	Harmless   int
	Malicious  int
	Suspicious int
	Undetected int
}

type FileInfo struct {
	Name string
	Size int64
}

type FunctionResult struct {
	Success bool
	Message string
}

type AnalysisResults struct {
	Success bool
	Stats   Stats
}

var (
	startUpError         string
	offerShortcut        bool
	finishAddingShortcut bool
	client               *vt.Client
	VT_API_Key           string
	file_name            string
	file_path            string
	file_hash            string
	file_object          *vt.Object
	file_url             *url.URL
	analysis_url         *url.URL
)

const VERSION string = "v2.0.4"

func (a *App) start() {
	plan := planStartup(a.opts, startupSys{
		GOOS:          runtime.GOOS,
		UsingNautilus: UsingNautilus,
		Getenv:        os.Getenv,
	})
	VT_API_Key = plan.APIKey
	file_path = plan.FilePath
	offerShortcut = plan.OfferShortcut
	finishAddingShortcut = plan.FinishShortcut
	if plan.Error != "" {
		startUpError = plan.Error
		return
	}

	file_name = filepath.Base(file_path)

	client = vt.NewClient(VT_API_Key)
	file_hash = a.hashFile(file_path)

	file_url, _ = url.Parse("https://www.virustotal.com/api/v3/files/" + file_hash)
	file_object, _ = client.GetObject(file_url)
}

func (a *App) GetFileInfo() FileInfo {
	file, err := os.Stat(file_path)
	if err != nil {
		return FileInfo{"", 0}
	}

	return FileInfo{file_name, file.Size()}
}

func (a *App) GetAPIKey() string {
	return VT_API_Key
}

func (a *App) OfferShortcut() bool {
	return offerShortcut
}

func (a *App) GetStartupError() string {
	return startUpError
}

func (a *App) FinishAddingShortcut() bool {
	return finishAddingShortcut
}

func (a *App) GetVersion() string {
	return VERSION
}

func (a *App) hashFile(file_path string) string {
	file, err := os.ReadFile(file_path)
	if err != nil {
		println("Error reading file:", err)
	}
	md5_hash_byte := md5.Sum(file)
	md5_hash := hex.EncodeToString(md5_hash_byte[:])
	return md5_hash
}

func (a *App) StartFileScan() FunctionResult {
	file, err := os.Open(file_path)
	if err != nil {
		return FunctionResult{false, err.Error()}
	}
	defer file.Close()

	file_scanner := client.NewFileScanner()
	analysis, err := file_scanner.ScanFile(file, nil)
	if err != nil {
		return FunctionResult{false, err.Error()}
	}

	analysis_url_str := "https://www.virustotal.com/api/v3/analyses/" + analysis.ID()

	analysis_url, err = url.Parse(analysis_url_str)
	if err != nil {
		return FunctionResult{false, err.Error()}
	}

	return FunctionResult{true, ""}
}

func (a *App) CheckAnalysisStatus() FunctionResult {
	result := FunctionResult{false, ""}
	// See if file has already been scanned
	if a.ConfirmAnalysisSuccess() {
		result.Success = true
		return result
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		waitForAnalysisCompletion(&result)
	}()

	wg.Wait()

	return result
}

func waitForAnalysisCompletion(result *FunctionResult) {
	api_counter := 0
	analysis_complete := false

	for !analysis_complete {
		if api_counter%15 == 0 {
			analysis, _ := client.GetObject(analysis_url)
			analysis_status, err := analysis.Get("status")
			analysis_status_str := ""
			if err != nil {
				result.Success = false
				result.Message = "Error fetching analysis status: " + err.Error()
				break
			} else {
				analysis_status_str, _ = analysis_status.(string)
			}

			if analysis_status_str == "completed" {
				result.Success = true
				break
			}
		}
		api_counter += 1
		time.Sleep(1000 * time.Millisecond)
	}
}

func (a *App) ConfirmAnalysisSuccess() bool {
	var err error
	file_object, err = client.GetObject(file_url)
	if err != nil {
		return false
	}
	return true
}

func (a *App) GetAnalysisResults() AnalysisResults {
	stats_data, err := file_object.Get("last_analysis_stats")
	if err != nil {
		return AnalysisResults{false, Stats{}}
	}

	stats_map, ok := stats_data.(map[string]any)
	if !ok {
		return AnalysisResults{false, Stats{}}
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

	return AnalysisResults{true, stats}
}
