package main

import (
	"embed"
	"fmt"
	"os"
	"rcvt/cli"
	"rcvt/internal/cmdline"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Checked first: on Windows this attaches the console that errors print to.
	console := hasConsole()

	opts, err := cmdline.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintf(os.Stderr, "Run '%s --help' for usage.\n", os.Args[0])
		os.Exit(2)
	}

	if !opts.UseGUI(console) {
		os.Exit(cli.Run(opts, os.Stdin, os.Stdout))
	}

	// Create an instance of the app structure
	app := NewApp(opts)

	// Create application with options
	err = wails.Run(&options.App{
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
