package main

import (
	"fmt"
	"os"
	"path/filepath"
	"proxy-inspector/proxy"
	"proxy-inspector/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {

	fmt.Println("STARTING PROXY + UI")

	cfg := proxy.DefaultConfig()

	// Automatically use mkcert Root CA if it exists
	caPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "mkcert")
	caCert := filepath.Join(caPath, "rootCA.pem")
	caKey := filepath.Join(caPath, "rootCA-key.pem")

	if _, err := os.Stat(caCert); err == nil {
		if _, err := os.Stat(caKey); err == nil {
			cfg.TLSCertFile = caCert
			cfg.TLSKeyFile = caKey
		}
	}

	// start proxy
	go proxy.Start(cfg)

	// create UI program
	p := tea.NewProgram(ui.NewModel(), tea.WithAltScreen())

	// bridge: proxy -> bubble tea
	go func() {
		for e := range proxy.EventChannel {
			fmt.Println("EVENT IN MAIN:", e.Method, e.URL)

			// IMPORTANT: Send is correct way
			p.Send(e)
		}
	}()

	// run UI (blocking)
	if _, err := p.Run(); err != nil {
		fmt.Println("ERROR:", err)
	}
}