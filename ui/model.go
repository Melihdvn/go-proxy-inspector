package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"net/url"

	"proxy-inspector/proxy"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ── Styles ────────────────────────────────────────────────────────────────────

var (
	styleGET    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599")).Bold(true)
	stylePOST   = lipgloss.NewStyle().Foreground(lipgloss.Color("#4D9EFF")).Bold(true)
	stylePUT    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB800")).Bold(true)
	styleDELETE = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4D4D")).Bold(true)
	stylePATCH  = lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true)
	styleOther  = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA")).Bold(true)

	styleOK    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599"))
	styleRedir = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB800"))
	styleWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF8C00"))
	styleErr   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4D4D"))

	styleTitle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599")).Bold(true)
	styleIntercept = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4D4D")).Bold(true).Reverse(true)
	styleCursor    = lipgloss.NewStyle().Bold(true).Reverse(true)
	styleFilter    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB800"))
	styleDim       = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	styleBlocked   = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000")).Strikethrough(true)
)

func methodStyle(m string) lipgloss.Style {
	switch strings.ToUpper(m) {
	case "GET":
		return styleGET
	case "POST":
		return stylePOST
	case "PUT":
		return stylePUT
	case "DELETE":
		return styleDELETE
	case "PATCH":
		return stylePATCH
	default:
		return styleOther
	}
}

func statusStyle(code int) lipgloss.Style {
	switch {
	case code == 0:
		return styleDim
	case code >= 500:
		return styleErr
	case code >= 400:
		return styleWarn
	case code >= 300:
		return styleRedir
	default:
		return styleOK
	}
}

// ── Model ─────────────────────────────────────────────────────────────────────

type screen int

const (
	listScreen screen = iota
	attackScreen
	detailScreen
	editScreen
	interceptScreen
	replayResultScreen
	blocklistScreen
	statsScreen
	helpScreen
)

type model struct {
	events       []proxy.Event
	cursor       int
	width        int
	height       int
	screen       screen
	detailScroll int

	filterMode bool
	filterBuf  string

	editBuf    []rune
	editCursor int
	replayMsg  string

	exportMsg string

	// intercept state
	pendingIntercept *proxy.InterceptRequest
	interceptScroll  int
	interceptQueue   []proxy.InterceptRequest

	// replay response state
	replayResult *proxy.Event

	// attack state
	attackTargetURL    string
	attackUser         string
	attackWordlist     string
	attackUserField    string
	attackPassField    string
	attackSuccessRegex string
	attackConcurrency  int
	attackIsJSON       bool
	attackDelayMs      int
	attackBatchSize    int
	attackBatchDelayMs int
	attackExpectedStatus int
	attackStatusIsSuccess bool
	attackGenCharset     string
	attackGenMaxLen      int
	attackProxyList      string
	attackRandomUA       bool
	attackRandomIP       bool
	attackStatus       string
	attackActive       bool
	attackResult       string
	attackFocus        int
	attackChan         chan proxy.AttackProgressMsg
	attackCancel       chan bool
	attackFocusMax     int // dynamic max focus based on fields
	attackType         string // "Sniper", "Battering Ram"

	// Interactive field selection
	attackAvailableFields []string
	attackUserFieldIndex  int
	attackPassFieldIndex  int
	attackOriginalBody    string
	attackHeaders         map[string]string

	// selected event for detail/edit screens
	selectedEvent *proxy.Event
}

func NewModel() model {
	return model{
		events:            []proxy.Event{},
		attackUser:        "admin",
		attackWordlist:    "passwords.txt",
		attackUserField:   "username",
		attackPassField:   "password",
		attackConcurrency: 5,
		attackGenCharset: "abcdefghijklmnopqrstuvwxyz0123456789",
		attackGenMaxLen:  4,
		attackRandomUA:   true,
		attackRandomIP:   true,
		attackFocusMax:   19, // URL, User, Wordlist, UserField, PassField, Regex, Concurrency, JSON, Delay, BatchSize, BatchDelay, ExpStatus, StatusIsSuccess, GenCharset, GenMaxLen, ProxyList, RandomUA, RandomIP, AttackType
		attackType:        "Sniper",
	}
}

func waitForAttack(sub chan proxy.AttackProgressMsg) tea.Cmd {
	return func() tea.Msg {
		return <-sub
	}
}

func (m model) Init() tea.Cmd {
	return checkIntercepts
}

// checkIntercepts polls the InterceptChan without blocking
func checkIntercepts() tea.Msg {
	select {
	case ir := <-proxy.InterceptChan:
		return ir
	case <-time.After(100 * time.Millisecond):
		return struct{}{} // tick
	}
}

func (m model) isEventVisible(e proxy.Event) bool {
	if m.filterBuf == "" {
		return true
	}
	
	// Regex check
	var re *regexp.Regexp
	if strings.HasPrefix(m.filterBuf, "regex:") {
		var err error
		re, err = regexp.Compile("(?i)" + strings.TrimPrefix(m.filterBuf, "regex:"))
		if err == nil {
			return re.MatchString(e.FullURL) || re.MatchString(e.Method)
		}
	}

	q := strings.ToLower(m.filterBuf)
	if strings.HasPrefix(q, "method:") {
		return strings.ToLower(e.Method) == strings.TrimPrefix(q, "method:")
	} else if strings.HasPrefix(q, "host:") {
		return strings.Contains(strings.ToLower(e.Host), strings.TrimPrefix(q, "host:"))
	} else if strings.HasPrefix(q, "status:") {
		return fmt.Sprintf("%d", e.Status) == strings.TrimPrefix(q, "status:")
	}
	return strings.Contains(strings.ToLower(e.FullURL), q) || strings.Contains(strings.ToLower(e.Method), q)
}

func (m model) filteredEvents() []proxy.Event {
	if m.filterBuf == "" {
		return m.events
	}
	out := make([]proxy.Event, 0, len(m.events))
	for _, e := range m.events {
		if m.isEventVisible(e) {
			out = append(out, e)
		}
	}
	return out
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case proxy.Event:
		m.events = append([]proxy.Event{msg}, m.events...)
		
		if m.isEventVisible(msg) {
			if m.screen == listScreen && m.cursor == 0 && !m.filterMode {
				// User is at the top of the live feed, stay at 0
				m.cursor = 0
			} else {
				// User is scrolled down or examining details, track the selected item
				m.cursor++
			}
		}

		vis := m.filteredEvents()
		if m.cursor >= len(vis) {
			m.cursor = len(vis) - 1
		}
		if m.cursor < 0 {
			m.cursor = 0
		}
		// cap events to a hard limit to prevent OOM
		if len(m.events) > 1000 {
			m.events = m.events[:1000]
		}

	case proxy.AttackProgressMsg:
		if msg.Status == "Running" {
			m.attackStatus = fmt.Sprintf("Attempt %d: Trying password '%s'...", msg.AttemptCount, msg.Password)
			return m, waitForAttack(m.attackChan)
		} else if msg.Status == "Success" {
			m.attackActive = false
			
			resStr := fmt.Sprintf("[+] SUCCESS! Password found: %s", msg.Password)
			if msg.FinalURL != "" && msg.FinalURL != m.attackTargetURL {
				resStr += fmt.Sprintf("\n[+] Redirected to: %s", msg.FinalURL)
			}
			if msg.ResponseBody != "" {
				resStr += fmt.Sprintf("\n[+] Response: %s", msg.ResponseBody)
			}
			m.attackResult = resStr
			m.attackStatus = ""
		} else if msg.Status == "Failed" {
			m.attackActive = false
			m.attackResult = "[-] Attack finished. Password not found."
			m.attackStatus = ""
		} else if msg.Status == "Error" {
			m.attackActive = false
			m.attackResult = "[!] Error: " + msg.ErrorMsg
			m.attackStatus = ""
		}
		return m, nil

	case proxy.InterceptRequest:
		if m.pendingIntercept == nil {
			ir := msg
			m.pendingIntercept = &ir
			m.screen = interceptScreen
			m.editBuf = []rune(ir.Event.ReqBody)
			m.editCursor = len(m.editBuf)
		} else {
			m.interceptQueue = append(m.interceptQueue, msg)
		}
		return m, checkIntercepts

	case struct{}:
		return m, checkIntercepts

	case tea.KeyMsg:
		switch m.screen {
		// ── List screen ───────────────────────────────────────────────
		case listScreen:
			if m.filterMode {
				switch msg.String() {
				case "esc", "enter":
					m.filterMode = false
				case "backspace":
					if len(m.filterBuf) > 0 {
						m.filterBuf = m.filterBuf[:len(m.filterBuf)-1]
					}
				default:
					if len(msg.Runes) > 0 {
						m.filterBuf += string(msg.Runes)
					}
				}
				m.cursor = 0
				return m, nil
			}
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "?":
				m.screen = helpScreen
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.filteredEvents())-1 {
					m.cursor++
				}
			case "enter":
				vis := m.filteredEvents()
				if len(vis) > 0 && m.cursor < len(vis) {
					e := vis[m.cursor]
					m.selectedEvent = &e
					m.screen = detailScreen
					m.detailScroll = 0
					m.replayMsg = ""
				}
			case "/":
				m.filterMode = true
			case "ctrl+x":
				m.filterBuf = ""
				m.cursor = 0
			case "A":
				vis := m.filteredEvents()
				if m.cursor < len(vis) {
					e := vis[m.cursor]
					m.selectedEvent = &e // Track for attack screen too
					m.attackTargetURL = e.FullURL
					m.attackStatus = ""
					m.attackActive = false
					m.attackResult = ""
					m.attackFocus = 1 // Username focus
					
					// --- Auto-Discovery (Alanları Bulma) ---
					m.attackOriginalBody = e.ReqBody
					m.attackHeaders = e.ReqHeaders
					m.attackAvailableFields = []string{"[MANUEL]"}
					
					// Form parser
					if strings.Contains(e.ReqHeaders["Content-Type"], "application/x-www-form-urlencoded") {
						parsed, _ := url.ParseQuery(e.ReqBody)
						for k := range parsed {
							m.attackAvailableFields = append(m.attackAvailableFields, k)
						}
					} else { // JSON parser dener
						var jsonData map[string]interface{}
						if err := json.Unmarshal([]byte(e.ReqBody), &jsonData); err == nil {
							for k := range jsonData {
								m.attackAvailableFields = append(m.attackAvailableFields, k)
							}
						}
					}
					
					// Default indexler
					m.attackUserFieldIndex = 0
					m.attackPassFieldIndex = 0
					if len(m.attackAvailableFields) > 1 {
						for i, f := range m.attackAvailableFields {
							lf := strings.ToLower(f)
							if strings.Contains(lf, "user") || strings.Contains(lf, "email") || lf == "u" {
								m.attackUserFieldIndex = i
							}
							if strings.Contains(lf, "pass") || strings.Contains(lf, "pwd") || lf == "p" {
								m.attackPassFieldIndex = i
							}
						}
					}
					m.attackUserField = m.attackAvailableFields[m.attackUserFieldIndex]
					m.attackPassField = m.attackAvailableFields[m.attackPassFieldIndex]
					// ---------------------------------------

					m.editBuf = []rune(m.attackUser)
					m.editCursor = len(m.editBuf)
					m.attackChan = make(chan proxy.AttackProgressMsg)
					m.screen = attackScreen
				}
			case "x":
				// JSON Export
				evs := m.events
				go func() { proxy.ExportEvents(evs) }()
				m.exportMsg = fmt.Sprintf("✓ Exported %d events to JSON", len(m.events))
			case "h":
				// HAR Export
				evs := m.events
				go func() { proxy.ExportHAR(evs) }()
				m.exportMsg = fmt.Sprintf("✓ Exported %d events to HAR", len(m.events))
			case "i":
				proxy.SetInterceptMode(!proxy.IsInterceptEnabled())
				if proxy.IsInterceptEnabled() {
					m.exportMsg = "⚠ Intercept mode ON"
				} else {
					m.exportMsg = "✓ Intercept mode OFF"
				}
			case "r":
				// Quick replay
				vis := m.filteredEvents()
				if m.cursor < len(vis) {
					e := vis[m.cursor]
					go func() {
						res, err := proxy.ReplayWithResponse(e, e.ReqBody)
						if err == nil {
							proxy.EventChannel <- res
						}
					}()
					m.exportMsg = "↺ Replaying request..."
				}
			case "b":
				vis := m.filteredEvents()
				if m.cursor < len(vis) {
					e := vis[m.cursor]
					proxy.AddToBlocklist(e.Host)
					m.exportMsg = "⚠ Blocked host: " + e.Host
				}
			case "B":
				m.screen = blocklistScreen
			case "S":
				m.screen = statsScreen
			case "T":
				// General Brute Force Tool
				m.attackTargetURL = "http://"
				m.attackStatus = ""
				m.attackActive = false
				m.attackResult = ""
				m.attackFocus = 0 // Target URL focus
				m.editBuf = []rune(m.attackTargetURL)
				m.editCursor = len(m.editBuf)
				m.attackChan = make(chan proxy.AttackProgressMsg)
				m.screen = attackScreen
			}

		// ── Attack screen ─────────────────────────────────────────────
		case attackScreen:
			if m.attackActive {
				if msg.String() == "ctrl+c" {
					if m.attackCancel != nil {
						close(m.attackCancel)
						m.attackCancel = nil
					}
					m.attackActive = false
					m.attackResult = "[-] Attack cancelled by user."
					m.attackStatus = ""
					return m, nil
				}
				return m, nil
			}

			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.screen = listScreen
			case "up", "shift+tab":
				m.saveAttackField()
				m.attackFocus--
				if m.attackFocus < 0 { m.attackFocus = m.attackFocusMax - 1 }
				m.loadAttackField()
			case "down", "tab":
				m.saveAttackField()
				m.attackFocus++
				if m.attackFocus >= m.attackFocusMax { m.attackFocus = 0 }
				m.loadAttackField()
			case " ":
				if m.attackFocus == 7 { // JSON toggle
					m.attackIsJSON = !m.attackIsJSON
				} else if m.attackFocus == 12 { // StatusIsSuccess toggle
					m.attackStatusIsSuccess = !m.attackStatusIsSuccess
				} else if m.attackFocus == 16 { // RandomUA toggle
					m.attackRandomUA = !m.attackRandomUA
				} else if m.attackFocus == 17 { // RandomIP toggle
					m.attackRandomIP = !m.attackRandomIP
				} else {
					if m.editCursor <= len(m.editBuf) {
						m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append([]rune{' '}, m.editBuf[m.editCursor:]...)...)
						m.editCursor++
					}
				}
			case "enter":
				m.saveAttackField()
				m.attackActive = true
				m.attackResult = ""
				m.attackStatus = "Starting attack..."
				m.attackChan = make(chan proxy.AttackProgressMsg)
				m.attackCancel = make(chan bool)
				config := proxy.AttackConfig{
					TargetURL:    m.attackTargetURL,
					Username:     m.attackUser,
					Wordlist:     m.attackWordlist,
					UserField:    m.attackUserField,
					PassField:    m.attackPassField,
					SuccessRegex: m.attackSuccessRegex,
					Concurrency:  m.attackConcurrency,
					IsJSON:       m.attackIsJSON,
					DelayMs:      m.attackDelayMs,
					BatchSize:    m.attackBatchSize,
					BatchDelayMs: m.attackBatchDelayMs,
					ExpectedStatus: m.attackExpectedStatus,
					StatusIsSuccess: m.attackStatusIsSuccess,
					GenCharset:     m.attackGenCharset,
					GenMaxLen:      m.attackGenMaxLen,
					ProxyList:      m.attackProxyList,
					RandomUA:       m.attackRandomUA,
					RandomIP:       m.attackRandomIP,
					AttackType:     m.attackType,
				}
				go proxy.RunBruteForceUI(config, m.attackChan, m.attackCancel)
				return m, waitForAttack(m.attackChan)
			case "backspace":
				if m.editCursor > 0 {
					m.editBuf = append(m.editBuf[:m.editCursor-1:m.editCursor-1], m.editBuf[m.editCursor:]...)
					m.editCursor--
				}
			case "delete":
				if m.editCursor < len(m.editBuf) {
					m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], m.editBuf[m.editCursor+1:]...)
				}
			case "left":
				if m.attackFocus == 3 && len(m.attackAvailableFields) > 1 {
					m.attackUserFieldIndex--
					if m.attackUserFieldIndex < 0 { m.attackUserFieldIndex = len(m.attackAvailableFields) - 1 }
					m.attackUserField = m.attackAvailableFields[m.attackUserFieldIndex]
					m.editBuf = []rune(m.attackUserField)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 4 && len(m.attackAvailableFields) > 1 {
					m.attackPassFieldIndex--
					if m.attackPassFieldIndex < 0 { m.attackPassFieldIndex = len(m.attackAvailableFields) - 1 }
					m.attackPassField = m.attackAvailableFields[m.attackPassFieldIndex]
					m.editBuf = []rune(m.attackPassField)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 18 {
					if m.attackType == "Sniper" {
						m.attackType = "Battering Ram"
					} else {
						m.attackType = "Sniper"
					}
					m.editBuf = []rune(m.attackType)
					m.editCursor = len(m.editBuf)
				} else if m.editCursor > 0 {
					m.editCursor--
				}
			case "right":
				if m.attackFocus == 3 && len(m.attackAvailableFields) > 1 {
					m.attackUserFieldIndex++
					if m.attackUserFieldIndex >= len(m.attackAvailableFields) { m.attackUserFieldIndex = 0 }
					m.attackUserField = m.attackAvailableFields[m.attackUserFieldIndex]
					m.editBuf = []rune(m.attackUserField)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 4 && len(m.attackAvailableFields) > 1 {
					m.attackPassFieldIndex++
					if m.attackPassFieldIndex >= len(m.attackAvailableFields) { m.attackPassFieldIndex = 0 }
					m.attackPassField = m.attackAvailableFields[m.attackPassFieldIndex]
					m.editBuf = []rune(m.attackPassField)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 18 {
					if m.attackType == "Sniper" {
						m.attackType = "Battering Ram"
					} else {
						m.attackType = "Sniper"
					}
					m.editBuf = []rune(m.attackType)
					m.editCursor = len(m.editBuf)
				} else if m.editCursor < len(m.editBuf) {
					m.editCursor++
				}
			default:
				if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
					// Eğer "[MANUEL]" seçili değilse klavyeden yazı yazılmasını engelle
					if m.attackFocus == 3 && m.attackUserField != "[MANUEL]" { return m, nil }
					if m.attackFocus == 4 && m.attackPassField != "[MANUEL]" { return m, nil }
					if m.attackFocus == 18 { return m, nil }

					if len(msg.Runes) > 0 {
						m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append(msg.Runes, m.editBuf[m.editCursor:]...)...)
						m.editCursor += len(msg.Runes)
					}
				}
			}
		// ── Detail screen ─────────────────────────────────────────────
		case detailScreen:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "backspace":
				m.screen = listScreen
			case "up", "k":
				if m.detailScroll > 0 {
					m.detailScroll--
				}
			case "down", "j":
				m.detailScroll++
			case "e":
				if m.selectedEvent != nil {
					m.editBuf = []rune(m.selectedEvent.ReqBody)
					m.editCursor = len(m.editBuf)
					m.screen = editScreen
					m.replayMsg = ""
				}
			case "A":
				if m.selectedEvent != nil {
					e := *m.selectedEvent
					m.attackTargetURL = e.FullURL
					m.attackStatus = ""
					m.attackActive = false
					m.attackResult = ""
					m.attackFocus = 1 // Username focus
					
					// --- Auto-Discovery (Alanları Bulma) ---
					m.attackOriginalBody = e.ReqBody
					m.attackHeaders = e.ReqHeaders
					m.attackAvailableFields = []string{"[MANUEL]"}
					
					if strings.Contains(e.ReqHeaders["Content-Type"], "application/x-www-form-urlencoded") {
						parsed, _ := url.ParseQuery(e.ReqBody)
						for k := range parsed {
							m.attackAvailableFields = append(m.attackAvailableFields, k)
						}
					} else {
						var jsonData map[string]interface{}
						if err := json.Unmarshal([]byte(e.ReqBody), &jsonData); err == nil {
							for k := range jsonData {
								m.attackAvailableFields = append(m.attackAvailableFields, k)
							}
						}
					}
					
					m.attackUserFieldIndex = 0
					m.attackPassFieldIndex = 0
					if len(m.attackAvailableFields) > 1 {
						for i, f := range m.attackAvailableFields {
							lf := strings.ToLower(f)
							if strings.Contains(lf, "user") || strings.Contains(lf, "email") || lf == "u" {
								m.attackUserFieldIndex = i
							}
							if strings.Contains(lf, "pass") || strings.Contains(lf, "pwd") || lf == "p" {
								m.attackPassFieldIndex = i
							}
						}
					}
					m.attackUserField = m.attackAvailableFields[m.attackUserFieldIndex]
					m.attackPassField = m.attackAvailableFields[m.attackPassFieldIndex]
					// ---------------------------------------

					m.editBuf = []rune(m.attackUser)
					m.editCursor = len(m.editBuf)
					m.attackChan = make(chan proxy.AttackProgressMsg)
					m.screen = attackScreen
				}
			case "T":
				m.attackTargetURL = "http://"
				m.attackStatus = ""
				m.attackActive = false
				m.attackResult = ""
				m.attackFocus = 0
				m.editBuf = []rune(m.attackTargetURL)
				m.editCursor = len(m.editBuf)
				m.attackChan = make(chan proxy.AttackProgressMsg)
				m.screen = attackScreen
			}

		// ── Edit screen ───────────────────────────────────────────────
		case editScreen:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.screen = detailScreen
			case "ctrl+s":
				body := string(m.editBuf)
				if m.selectedEvent != nil {
					e := *m.selectedEvent
					m.exportMsg = "↺ Sending replay..."
					res, err := proxy.ReplayWithResponse(e, body)
					if err == nil {
						m.replayResult = &res
						m.screen = replayResultScreen
						m.detailScroll = 0
						proxy.EventChannel <- res // add to list too
					} else {
						m.screen = detailScreen
						m.replayMsg = "⚠ Replay error: " + err.Error()
					}
				}
			case "backspace":
				if m.editCursor > 0 {
					m.editBuf = append(m.editBuf[:m.editCursor-1:m.editCursor-1], m.editBuf[m.editCursor:]...)
					m.editCursor--
				}
			case "delete":
				if m.editCursor < len(m.editBuf) {
					m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], m.editBuf[m.editCursor+1:]...)
				}
			case "left":
				if m.editCursor > 0 {
					m.editCursor--
				}
			case "right":
				if m.editCursor < len(m.editBuf) {
					m.editCursor++
				}
			case "enter":
				m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append([]rune{'\n'}, m.editBuf[m.editCursor:]...)...)
				m.editCursor++
			default:
				if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
					if len(msg.Runes) > 0 {
						m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append(msg.Runes, m.editBuf[m.editCursor:]...)...)
						m.editCursor += len(msg.Runes)
					}
				}
			}

		// ── Intercept screen ──────────────────────────────────────────
		case interceptScreen:
			switch msg.String() {
			case "ctrl+c":
				if m.pendingIntercept != nil {
					m.pendingIntercept.Decision <- proxy.InterceptDecision{Action: "drop"}
				}
				return m, tea.Quit
			case "ctrl+f":
				if m.pendingIntercept != nil {
					m.pendingIntercept.Decision <- proxy.InterceptDecision{Action: "forward", NewBody: string(m.editBuf)}
					m.pendingIntercept = nil
				}
				if len(m.interceptQueue) > 0 {
					ir := m.interceptQueue[0]
					m.interceptQueue = m.interceptQueue[1:]
					m.pendingIntercept = &ir
					m.editBuf = []rune(ir.Event.ReqBody)
					m.editCursor = len(m.editBuf)
				} else {
					m.screen = listScreen
				}
			case "ctrl+d":
				if m.pendingIntercept != nil {
					m.pendingIntercept.Decision <- proxy.InterceptDecision{Action: "drop"}
					m.pendingIntercept = nil
				}
				if len(m.interceptQueue) > 0 {
					ir := m.interceptQueue[0]
					m.interceptQueue = m.interceptQueue[1:]
					m.pendingIntercept = &ir
					m.editBuf = []rune(ir.Event.ReqBody)
					m.editCursor = len(m.editBuf)
				} else {
					m.screen = listScreen
				}
			case "backspace":
				if m.editCursor > 0 {
					m.editBuf = append(m.editBuf[:m.editCursor-1:m.editCursor-1], m.editBuf[m.editCursor:]...)
					m.editCursor--
				}
			case "delete":
				if m.editCursor < len(m.editBuf) {
					m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], m.editBuf[m.editCursor+1:]...)
				}
			case "left":
				if m.editCursor > 0 {
					m.editCursor--
				}
			case "right":
				if m.editCursor < len(m.editBuf) {
					m.editCursor++
				}
			case "enter":
				m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append([]rune{'\n'}, m.editBuf[m.editCursor:]...)...)
				m.editCursor++
			default:
				if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
					if len(msg.Runes) > 0 {
						m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append(msg.Runes, m.editBuf[m.editCursor:]...)...)
						m.editCursor += len(msg.Runes)
					}
				}
			}

		// ── Replay Result screen ──────────────────────────────────────
		case replayResultScreen:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "backspace":
				m.screen = listScreen
			case "up", "k":
				if m.detailScroll > 0 {
					m.detailScroll--
				}
			case "down", "j":
				m.detailScroll++
			}

		// ── Blocklist / Stats / Help screens ──────────────────────────
		case blocklistScreen, statsScreen, helpScreen:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "esc", "backspace":
				m.screen = listScreen
			}
		}
	}

	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case detailScreen:
		return m.detailView()
	case attackScreen:
		return m.attackView()
	case editScreen:
		return m.editView()
	case interceptScreen:
		return m.interceptView()
	case replayResultScreen:
		return m.replayResultView()
	case blocklistScreen:
		return m.blocklistView()
	case statsScreen:
		return RenderStats(ComputeStats(m.events))
	case helpScreen:
		return m.helpView()
	default:
		return m.listView()
	}
}

// ── Views ─────────────────────────────────────────────────────────────────────

func (m model) listView() string {
	var sb strings.Builder

	title := "HTTP Proxy Inspector"
	if proxy.IsInterceptEnabled() {
		title += " " + styleIntercept.Render("[INTERCEPT ON]")
	}
	title += fmt.Sprintf(" (%d requests)", len(m.events))

	sb.WriteString(styleTitle.Render(title) + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	if m.exportMsg != "" {
		sb.WriteString(styleOK.Render(m.exportMsg) + "\n")
	}

	if m.filterMode {
		sb.WriteString(styleFilter.Render("/ Filter: "+m.filterBuf+"█") + "\n")
	} else if m.filterBuf != "" {
		sb.WriteString(styleFilter.Render("/ "+m.filterBuf) + styleDim.Render("  ctrl+x:clear") + "\n")
	}

	vis := m.filteredEvents()

	if len(vis) == 0 {
		sb.WriteString(styleDim.Render("  No requests match or no requests yet...\n"))
		sb.WriteString(strings.Repeat("─", 62) + "\n")
		sb.WriteString(styleDim.Render("?:help  q:quit  i:intercept") + "\n")
		return sb.String()
	}

	extraLines := 0
	if m.filterBuf != "" { extraLines++ }
	if m.exportMsg != "" { extraLines++ }
	const fixedLines = 4
	listHeight := m.height - fixedLines - extraLines
	if listHeight < 2 { listHeight = 2 }

	start := 0
	if m.cursor >= listHeight { start = m.cursor - listHeight + 1 }
	end := start + listHeight
	if end > len(vis) { end = len(vis) }

	for i := start; i < end; i++ {
		e := vis[i]
		mst := methodStyle(e.Method)
		sst := statusStyle(e.Status)

		methodStr := fmt.Sprintf("%-6s", e.Method)
		hostPath := e.Host + e.URL
		if len(hostPath) > 38 {
			hostPath = hostPath[:35] + "..."
		}
		urlStr := fmt.Sprintf("%-38s", hostPath)
		statusStr := fmt.Sprintf("%3d", e.Status)
		latStr := fmt.Sprintf("%4dms", e.LatencyMs)

		if e.Blocked {
			sst = styleBlocked
			statusStr = "BLK"
			latStr = "   -"
		} else if e.Status == 0 {
			statusStr = "---"
		}

		var line string
		if i == m.cursor {
			raw := fmt.Sprintf("> [%-6s] %-38s  %s  %s", e.Method, hostPath, statusStr, latStr)
			line = styleCursor.Render(raw)
		} else {
			line = fmt.Sprintf("  [%s] %s  %s  %s", mst.Render(methodStr), urlStr, sst.Render(statusStr), styleDim.Render(latStr))
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("?:help  q:quit  ↑/↓:nav  enter:detail  /:filter  i:intercept  T:attack tool") + "\n")
	return sb.String()
}

func (m model) detailView() string {
	if m.selectedEvent == nil { return "No event selected.\n" }
	e := *m.selectedEvent
	
	var sb strings.Builder
	header := fmt.Sprintf("[ %s %s — %s — %dms ] %s",
		methodStyle(e.Method).Render(e.Method), e.FullURL,
		statusStyle(e.Status).Render(fmt.Sprintf("%d", e.Status)),
		e.LatencyMs, styleDim.Render(e.Timestamp.Format("15:04:05.000")),
	)
	sb.WriteString(header + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	if m.replayMsg != "" {
		sb.WriteString(styleFilter.Render(m.replayMsg) + "\n")
	}

	lines := buildDetailLines(e)
	viewHeight := m.height - 4
	if m.replayMsg != "" { viewHeight-- }
	if viewHeight < 2 { viewHeight = 2 }

	maxScroll := len(lines) - viewHeight
	if maxScroll < 0 { maxScroll = 0 }
	scroll := m.detailScroll
	if scroll > maxScroll { scroll = maxScroll }
	end := scroll + viewHeight
	if end > len(lines) { end = len(lines) }

	for _, l := range lines[scroll:end] {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("esc:back  e:edit  r:replay  b:block host  A:attack  T:tool  ↑/↓:scroll") + "\n")
	return sb.String()
}

func (m model) editView() string {
	if m.selectedEvent == nil { return "No event selected.\n" }
	e := *m.selectedEvent
	var sb strings.Builder

	sb.WriteString(stylePUT.Render(fmt.Sprintf("EDIT  [ %s %s ]", e.Method, e.FullURL)) + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	before := string(m.editBuf[:m.editCursor])
	after := string(m.editBuf[m.editCursor:])
	bufferText := before + "█" + after

	for _, l := range strings.Split(bufferText, "\n") {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("ctrl+s:replay  esc:cancel  ←→:cursor") + "\n")
	return sb.String()
}

func (m model) attackView() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("BRUTE FORCE ATTACK TOOL") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	userFieldDisplay := m.attackUserField
	if m.attackFocus == 3 && len(m.attackAvailableFields) > 1 {
		if m.attackUserField == "[MANUEL]" {
			userFieldDisplay = "< [MANUEL] > (Type below)"
		} else {
			userFieldDisplay = fmt.Sprintf("< %s >", m.attackUserField)
		}
	} else if m.attackUserField == "[MANUEL]" {
		userFieldDisplay = "[MANUEL]"
	}

	passFieldDisplay := m.attackPassField
	if m.attackFocus == 4 && len(m.attackAvailableFields) > 1 {
		if m.attackPassField == "[MANUEL]" {
			passFieldDisplay = "< [MANUEL] > (Type below)"
		} else {
			passFieldDisplay = fmt.Sprintf("< %s >", m.attackPassField)
		}
	} else if m.attackPassField == "[MANUEL]" {
		passFieldDisplay = "[MANUEL]"
	}

	fields := []struct {
		Label string
		Value string
		Focus int
	}{
		{"Target URL ", m.attackTargetURL, 0},
		{"Username   ", m.attackUser, 1},
		{"Wordlist   ", m.attackWordlist, 2},
		{"User Field ", userFieldDisplay, 3},
		{"Pass Field ", passFieldDisplay, 4},
		{"Success RE ", m.attackSuccessRegex, 5},
		{"Concurrent ", fmt.Sprintf("%d", m.attackConcurrency), 6},
		{"JSON Mode  ", fmt.Sprintf("%v", m.attackIsJSON), 7},
		{"Delay (ms) ", fmt.Sprintf("%d", m.attackDelayMs), 8},
		{"Batch Size ", fmt.Sprintf("%d", m.attackBatchSize), 9},
		{"Batch Delay", fmt.Sprintf("%d", m.attackBatchDelayMs), 10},
		{"Exp Status  ", fmt.Sprintf("%d", m.attackExpectedStatus), 11},
		{"Success ifSt", fmt.Sprintf("%v", m.attackStatusIsSuccess), 12},
		{"Gen Charset ", m.attackGenCharset, 13},
		{"Gen Max Len ", fmt.Sprintf("%d", m.attackGenMaxLen), 14},
		{"Proxy List  ", m.attackProxyList, 15},
		{"Random UA   ", fmt.Sprintf("%v", m.attackRandomUA), 16},
		{"Random IP   ", fmt.Sprintf("%v", m.attackRandomIP), 17},
		{"Attack Type ", m.attackType, 18},
	}

	for _, f := range fields {
		line := f.Label + ": "
		if m.attackFocus == f.Focus && !m.attackActive {
			line += string(m.editBuf[:m.editCursor]) + "█" + string(m.editBuf[m.editCursor:])
		} else {
			line += f.Value
		}
		sb.WriteString(line + "\n")
	}
	sb.WriteString(strings.Repeat("─", 62) + "\n")
	
	// Payload Preview
	sb.WriteString(styleDim.Render("Payload Preview:") + "\n")
	preview := m.attackOriginalBody
	if preview == "" {
		preview = "(Auto-generated based on fields)"
	} else if len(preview) > 150 {
		preview = preview[:147] + "..."
	}
	sb.WriteString("  " + preview + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	if m.attackActive {
		sb.WriteString(styleWarn.Render("Status: ") + m.attackStatus + "\n")
	} else if m.attackResult != "" {
		if strings.Contains(m.attackResult, "SUCCESS") {
			sb.WriteString(styleOK.Render(m.attackResult) + "\n")
		} else {
			sb.WriteString(styleErr.Render(m.attackResult) + "\n")
		}
	} else {
		sb.WriteString(styleDim.Render("Status: Waiting to start...") + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	if m.attackActive {
		sb.WriteString(styleDim.Render("ctrl+c:cancel attack") + "\n")
	} else {
		sb.WriteString(styleDim.Render("enter:start attack  tab:change field  esc:back  ←→:edit") + "\n")
	}
	return sb.String()
}

func (m model) interceptView() string {
	if m.pendingIntercept == nil {
		return "No pending intercept.\n"
	}
	e := m.pendingIntercept.Event
	var sb strings.Builder

	title := fmt.Sprintf(" INTERCEPTED: %s %s ", e.Method, e.FullURL)
	if len(m.interceptQueue) > 0 {
		title += fmt.Sprintf(" (+%d in queue) ", len(m.interceptQueue))
	}
	sb.WriteString(styleIntercept.Render(title) + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	before := string(m.editBuf[:m.editCursor])
	after := string(m.editBuf[m.editCursor:])
	bufferText := before + "█" + after

	for _, l := range strings.Split(bufferText, "\n") {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("ctrl+f:forward  ctrl+d:drop  ←→:edit body") + "\n")
	return sb.String()
}

func (m model) replayResultView() string {
	if m.replayResult == nil { return "" }
	e := *m.replayResult
	
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("REPLAY RESULT") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	lines := buildDetailLines(e)
	viewHeight := m.height - 4
	if viewHeight < 2 { viewHeight = 2 }

	maxScroll := len(lines) - viewHeight
	if maxScroll < 0 { maxScroll = 0 }
	scroll := m.detailScroll
	if scroll > maxScroll { scroll = maxScroll }
	end := scroll + viewHeight
	if end > len(lines) { end = len(lines) }

	for _, l := range lines[scroll:end] {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("esc:back  ↑/↓:scroll") + "\n")
	return sb.String()
}

func (m model) blocklistView() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("Blocked Domains") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	blocked := proxy.GetBlocklist().List()
	if len(blocked) == 0 {
		sb.WriteString(styleDim.Render("  No domains blocked.\n"))
	} else {
		for i, d := range blocked {
			sb.WriteString(fmt.Sprintf("  %d. %s\n", i+1, styleErr.Render(d)))
		}
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("esc:back") + "\n")
	return sb.String()
}

func (m model) helpView() string {
	var sb strings.Builder
	sb.WriteString(styleTitle.Render("Keyboard Shortcuts") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")
	
	help := `
Global:
  q, ctrl+c   Quit
  ?           Show this help screen
  esc         Back to previous screen

List Screen:
  ↑/k, ↓/j    Navigate requests
  enter       View request details
  /           Filter (e.g., host:api, method:POST, regex:^https)
  ctrl+x      Clear filter
  i           Toggle Intercept mode (Pause & Modify)
  x           Export all events to JSON
  h           Export all events to HAR (DevTools compatible)
  r           Quick replay selected request
  b           Block selected request's host
  A           Open Brute Force Attack Tool for request
  T           Open General Brute Force Tool
  B           View Blocklist
  S           View Statistics (Latency histogram, etc)

Detail Screen:
  ↑/k, ↓/j    Scroll headers and body
  e           Edit request body
  r           Quick replay
  A           Open Brute Force Attack Tool

Intercept Screen:
  ctrl+f      Forward request (with modified body)
  ctrl+d      Drop request
`
	sb.WriteString(help)
	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("esc:back") + "\n")
	return sb.String()
}

func buildDetailLines(e proxy.Event) []string {
	var lines []string

	lines = append(lines, styleGET.Render("── Request Headers ───────────────────────────────────"))
	for _, k := range sortedKeys(e.ReqHeaders) {
		lines = append(lines, fmt.Sprintf("  %s %s", styleDim.Render(fmt.Sprintf("%-25s", k+":")), e.ReqHeaders[k]))
	}

	lines = append(lines, "", styleGET.Render("── Request Body ──────────────────────────────────────"))
	if e.ReqBody == "" {
		lines = append(lines, styleDim.Render("  (empty)"))
	} else {
		for _, l := range strings.Split(prettyJSON(e.ReqBody), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	if e.Blocked {
		lines = append(lines, "", styleErr.Render("── BLOCKED BY BLOCKLIST ──────────────────────────────"))
		return lines
	}

	lines = append(lines, "", styleOK.Render("── Response Headers ──────────────────────────────────"))
	for _, k := range sortedKeys(e.RespHeaders) {
		lines = append(lines, fmt.Sprintf("  %s %s", styleDim.Render(fmt.Sprintf("%-25s", k+":")), e.RespHeaders[k]))
	}

	lines = append(lines, "", styleOK.Render("── Response Body ─────────────────────────────────────"))
	if e.RespBody == "" {
		lines = append(lines, styleDim.Render("  (empty)"))
	} else {
		for _, l := range strings.Split(prettyJSON(e.RespBody), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	return lines
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m { keys = append(keys, k) }
	sort.Strings(keys)
	return keys
}

func prettyJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

func (m *model) saveAttackField() {
	switch m.attackFocus {
	case 0: m.attackTargetURL = string(m.editBuf)
	case 1: m.attackUser = string(m.editBuf)
	case 2: m.attackWordlist = string(m.editBuf)
	case 3: m.attackUserField = string(m.editBuf)
	case 4: m.attackPassField = string(m.editBuf)
	case 5: m.attackSuccessRegex = string(m.editBuf)
	case 6:
		var c int
		fmt.Sscanf(string(m.editBuf), "%d", &c)
		if c > 0 { m.attackConcurrency = c }
	case 8:
		var d int
		fmt.Sscanf(string(m.editBuf), "%d", &d)
		m.attackDelayMs = d
	case 9:
		var b int
		fmt.Sscanf(string(m.editBuf), "%d", &b)
		m.attackBatchSize = b
	case 10:
		var bd int
		fmt.Sscanf(string(m.editBuf), "%d", &bd)
		m.attackBatchDelayMs = bd
	case 11:
		var es int
		fmt.Sscanf(string(m.editBuf), "%d", &es)
		m.attackExpectedStatus = es
	case 13:
		m.attackGenCharset = string(m.editBuf)
	case 14:
		var ml int
		fmt.Sscanf(string(m.editBuf), "%d", &ml)
		if ml > 0 { m.attackGenMaxLen = ml }
	case 15: m.attackProxyList = string(m.editBuf)
	case 18: m.attackType = string(m.editBuf)
	}
}

func (m *model) loadAttackField() {
	var s string
	switch m.attackFocus {
	case 0: s = m.attackTargetURL
	case 1: s = m.attackUser
	case 2: s = m.attackWordlist
	case 3: s = m.attackUserField
	case 4: s = m.attackPassField
	case 5: s = m.attackSuccessRegex
	case 6: s = fmt.Sprintf("%d", m.attackConcurrency)
	case 7: s = fmt.Sprintf("%v", m.attackIsJSON)
	case 8: s = fmt.Sprintf("%d", m.attackDelayMs)
	case 9: s = fmt.Sprintf("%d", m.attackBatchSize)
	case 10: s = fmt.Sprintf("%d", m.attackBatchDelayMs)
	case 11: s = fmt.Sprintf("%d", m.attackExpectedStatus)
	case 12: s = fmt.Sprintf("%v", m.attackStatusIsSuccess)
	case 13: s = m.attackGenCharset
	case 14: s = fmt.Sprintf("%d", m.attackGenMaxLen)
	case 15: s = m.attackProxyList
	case 16: s = fmt.Sprintf("%v", m.attackRandomUA)
	case 17: s = fmt.Sprintf("%v", m.attackRandomIP)
	case 18: s = m.attackType
	}
	m.editBuf = []rune(s)
	m.editCursor = len(m.editBuf)
}
