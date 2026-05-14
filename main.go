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

	// Attack mode flags
	attackFlag := flag.Bool("attack", false, "Run in attack mode instead of proxy mode")
	targetUrlFlag := flag.String("target-url", "", "Target URL for brute force (e.g., http://localhost:8080/login)")
	userFlag := flag.String("user", "admin", "Username to use for attack")
	wordlistFlag := flag.String("wordlist", "passwords.txt", "Path to password wordlist")
	userFieldFlag := flag.String("user-field", "username", "Form field name for username")
	passFieldFlag := flag.String("pass-field", "password", "Form field name for password")
	regexFlag := flag.String("success-regex", "", "Regex to detect success in response")
	concurrencyFlag := flag.Int("concurrency", 5, "Number of concurrent workers")
	jsonFlag := flag.Bool("json", false, "Send payload as JSON instead of form-urlencoded")
	delayFlag := flag.Int("delay", 0, "Delay in ms between each request")
	batchSizeFlag := flag.Int("batch-size", 0, "Number of requests before a longer batch delay")
	batchDelayFlag := flag.Int("batch-delay", 0, "Longer delay in ms after batch-size requests")
	expStatusFlag := flag.Int("expected-status", 0, "Status code to check (0 to disable)")
	statusSuccessFlag := flag.Bool("status-success", true, "If true, expected-status means success; else failure")
	genCharsetFlag := flag.String("gen-charset", "abcdefghijklmnopqrstuvwxyz0123456789", "Characters for auto-generation")
	genMaxLenFlag := flag.Int("gen-maxlen", 4, "Max length for auto-generation")
	
	flag.Parse()

	if *attackFlag {
		if *targetUrlFlag == "" {
			fmt.Println("Error: -target-url is required in attack mode")
			os.Exit(1)
		}
		proxy.RunBruteForce(proxy.AttackConfig{
			TargetURL:    *targetUrlFlag,
			Username:     *userFlag,
			Wordlist:     *wordlistFlag,
			UserField:    *userFieldFlag,
			PassField:    *passFieldFlag,
			SuccessRegex: *regexFlag,
			Concurrency:  *concurrencyFlag,
			IsJSON:       *jsonFlag,
			DelayMs:      *delayFlag,
			BatchSize:    *batchSizeFlag,
			BatchDelayMs: *batchDelayFlag,
			ExpectedStatus: *expStatusFlag,
			StatusIsSuccess: *statusSuccessFlag,
			GenCharset:     *genCharsetFlag,
			GenMaxLen:      *genMaxLenFlag,
		})
		os.Exit(0)
	}

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