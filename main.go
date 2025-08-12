package main

import (
	"embed"
	"os"
	"rcvt/cli"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	runCli := true
	for i, arg := range os.Args {
		if arg == "gui" {
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			runCli = false
		}
	}
	if runCli {
		cli.Run()
		return

	}

	// Create an instance of the app structure
	app := NewApp()

	// Create application with options
	err := wails.Run(&options.App{
		Title:  "RightClickVirusTotal",
		Width:  512,
		Height: 768,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
		OnStartup:        app.startup,
		Bind: []interface{}{
			app,
		},
	})
	if err != nil {
		println("Error:", err.Error())
	}
}
