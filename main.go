package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"proxy-inspector/proxy"
	"proxy-inspector/ui"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v3"
)

func main() {
	// Parse CLI flags
	portFlag := flag.String("port", ":3000", "Port to listen on")
	maxEventsFlag := flag.Int("max-events", 1000, "Maximum number of events to keep in memory")
	blockFlag := flag.String("block", "", "Comma-separated list of domains to block")
	configFlag := flag.String("config", "", "Path to YAML config file")
	flag.Parse()

	cfg := proxy.DefaultConfig()
	cfg.ListenAddr = *portFlag
	cfg.MaxEvents = *maxEventsFlag
	if *blockFlag != "" {
		cfg.BlockedDomains = strings.Split(*blockFlag, ",")
	}

	// Load from YAML if provided
	if *configFlag != "" {
		data, err := os.ReadFile(*configFlag)
		if err != nil {
			fmt.Printf("Error reading config file: %v\n", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Printf("Error parsing config file: %v\n", err)
			os.Exit(1)
		}
	}

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
			p.Send(e)
		}
	}()

	// run UI (blocking)
	if _, err := p.Run(); err != nil {
		fmt.Println("ERROR:", err)
	}
}