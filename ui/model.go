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
	"strconv"

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
	
	styleStatus2xx = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599"))
	styleStatus4xx = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4D4D"))
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
	attackEditBodyScreen
)

type model struct {
	events       []proxy.Event
	cursor       int
	width        int
	height       int
	screen       screen
	detailScroll int
	attackScroll int

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
	attackBatchSize       int
	attackBatchDelayMs    int
	attackExpectedStatus  int
	attackStatusIsSuccess bool
	attackGenCharset      string
	attackGenMaxLen       int
	attackProxyList       string
	attackRandomUA        bool
	attackRandomIP        bool
	attackResetCount      int
	attackResetUser       string
	attackResetPass       string
	attackStatus          string
	attackActive          bool
	attackResult          string
	attackFocus           int
	attackChan            chan proxy.AttackProgressMsg
	attackCancel          chan bool
	attackFocusMax        int // dynamic max focus based on fields

	// Burp Suite Intruder additions
	attackType         string // "Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"
	attackWordlist2    string
	attackGenCharset2  string
	attackGenMaxLen2   int
	attackStopOnSuccess bool

	// Interactive field selection
	attackAvailableFields []string
	attackUserFieldIndex  int
	attackPassFieldIndex  int
	attackOriginalBody    string
	attackHeaders         map[string]string
	attackMethod          string
	attackHistory         []proxy.AttackProgressMsg

	// selected event for detail/edit screens
	selectedEvent *proxy.Event
}

func NewModel() model {
	return model{
		events:              []proxy.Event{},
		attackUser:          "admin",
		attackWordlist:      "passwords.txt",
		attackUserField:     "username",
		attackPassField:     "password",
		attackConcurrency:   5,
		attackGenCharset:    "abcdefghijklmnopqrstuvwxyz0123456789",
		attackGenMaxLen:     4,
		attackRandomUA:      true,
		attackRandomIP:      true,
		attackType:          "Sniper",
		attackGenCharset2:   "abcdefghijklmnopqrstuvwxyz0123456789",
		attackGenMaxLen2:    4,
		attackStopOnSuccess: true,
		attackFocusMax:      27,
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
	prevScreen := m.screen
	var cmd tea.Cmd
	m, cmd = m.updateInternal(msg)

	if m.screen == attackScreen && prevScreen != attackScreen {
		m.attackScroll = 0
	}

	if m.screen == attackScreen {
		m.adjustAttackScroll()
	}
	return m, cmd
}

func (m model) updateInternal(msg tea.Msg) (model, tea.Cmd) {
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
			
			// Geçmişe ekle (Table için)
			m.attackHistory = append([]proxy.AttackProgressMsg{msg}, m.attackHistory...)
			if len(m.attackHistory) > 10 {
				m.attackHistory = m.attackHistory[:10]
			}

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
					m.attackMethod = e.Method
					m.attackStatus = ""
					m.attackActive = false
					m.attackResult = ""
					m.attackFocus = 1 // Username focus
					
					// Initialize Burp intruder defaults
					m.attackType = "Sniper"
					m.attackWordlist2 = ""
					m.attackGenCharset2 = "abcdefghijklmnopqrstuvwxyz0123456789"
					m.attackGenMaxLen2 = 4

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
			case "ctrl+e":
				m.saveAttackField()
				m.editBuf = []rune(m.attackOriginalBody)
				m.editCursor = len(m.editBuf)
				m.screen = attackEditBodyScreen
				return m, nil
			case " ":
				if m.attackFocus == 5 { // JSON toggle
					m.attackIsJSON = !m.attackIsJSON
					m.editBuf = []rune(fmt.Sprintf("%v", m.attackIsJSON))
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 10 { // StatusIsSuccess toggle
					m.attackStatusIsSuccess = !m.attackStatusIsSuccess
					m.editBuf = []rune(fmt.Sprintf("%v", m.attackStatusIsSuccess))
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 11 { // Stop On Success toggle
					m.attackStopOnSuccess = !m.attackStopOnSuccess
					m.editBuf = []rune(fmt.Sprintf("%v", m.attackStopOnSuccess))
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 21 { // RandomUA toggle
					m.attackRandomUA = !m.attackRandomUA
					m.editBuf = []rune(fmt.Sprintf("%v", m.attackRandomUA))
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 22 { // RandomIP toggle
					m.attackRandomIP = !m.attackRandomIP
					m.editBuf = []rune(fmt.Sprintf("%v", m.attackRandomIP))
					m.editCursor = len(m.editBuf)
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
					Method:          m.attackMethod,
					TargetURL:       m.attackTargetURL,
					Username:        m.attackUser,
					Wordlist:        m.attackWordlist,
					UserField:       m.attackUserField,
					PassField:       m.attackPassField,
					SuccessRegex:    m.attackSuccessRegex,
					Concurrency:     m.attackConcurrency,
					IsJSON:          m.attackIsJSON,
					DelayMs:         m.attackDelayMs,
					BatchSize:       m.attackBatchSize,
					BatchDelayMs:    m.attackBatchDelayMs,
					ExpectedStatus:  m.attackExpectedStatus,
					StatusIsSuccess: m.attackStatusIsSuccess,
					GenCharset:      m.attackGenCharset,
					GenMaxLen:       m.attackGenMaxLen,
					ProxyList:       m.attackProxyList,
					RandomUA:        m.attackRandomUA,
					RandomIP:        m.attackRandomIP,
					ResetCount:      m.attackResetCount,
					ResetUser:       m.attackResetUser,
					ResetPass:       m.attackResetPass,
					OriginalBody:    m.attackOriginalBody,
					Headers:         m.attackHeaders,
					AttackType:      m.attackType,
					Wordlist2:       m.attackWordlist2,
					GenCharset2:     m.attackGenCharset2,
					GenMaxLen2:      m.attackGenMaxLen2,
					StopOnSuccess:   m.attackStopOnSuccess,
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
				if m.attackFocus == 1 { // Method toggle
					switch m.attackMethod {
					case "GET": m.attackMethod = "PATCH"
					case "POST": m.attackMethod = "GET"
					case "PUT": m.attackMethod = "POST"
					case "DELETE": m.attackMethod = "PUT"
					case "PATCH": m.attackMethod = "DELETE"
					default: m.attackMethod = "POST"
					}
					m.editBuf = []rune(m.attackMethod)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 3 && len(m.attackAvailableFields) > 1 {
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
				} else if m.attackFocus == 7 { // Attack Type toggling
					switch m.attackType {
					case "Sniper": m.attackType = "Cluster Bomb"
					case "Battering Ram": m.attackType = "Sniper"
					case "Pitchfork": m.attackType = "Battering Ram"
					case "Cluster Bomb": m.attackType = "Pitchfork"
					}
					m.editBuf = []rune(m.attackType)
					m.editCursor = len(m.editBuf)
				} else if m.editCursor > 0 {
					m.editCursor--
				}
			case "right":
				if m.attackFocus == 1 { // Method toggle
					switch m.attackMethod {
					case "GET": m.attackMethod = "POST"
					case "POST": m.attackMethod = "PUT"
					case "PUT": m.attackMethod = "DELETE"
					case "DELETE": m.attackMethod = "PATCH"
					case "PATCH": m.attackMethod = "GET"
					default: m.attackMethod = "POST"
					}
					m.editBuf = []rune(m.attackMethod)
					m.editCursor = len(m.editBuf)
				} else if m.attackFocus == 3 && len(m.attackAvailableFields) > 1 {
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
				} else if m.attackFocus == 7 { // Attack Type toggling
					switch m.attackType {
					case "Sniper": m.attackType = "Battering Ram"
					case "Battering Ram": m.attackType = "Pitchfork"
					case "Pitchfork": m.attackType = "Cluster Bomb"
					case "Cluster Bomb": m.attackType = "Sniper"
					}
					m.editBuf = []rune(m.attackType)
					m.editCursor = len(m.editBuf)
				} else if m.editCursor < len(m.editBuf) {
					m.editCursor++
				}
			default:
				if msg.Type == tea.KeyRunes || msg.Type == tea.KeySpace {
					// Eğer toggle-only veya selector ise klavyeden yazı yazılmasını engelle
					if m.attackFocus == 1 || m.attackFocus == 3 || m.attackFocus == 4 || m.attackFocus == 5 || m.attackFocus == 7 || m.attackFocus == 10 || m.attackFocus == 11 || m.attackFocus == 21 || m.attackFocus == 22 {
						return m, nil
					}

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
					m.attackMethod = e.Method
					m.attackStatus = ""
					m.attackActive = false
					m.attackResult = ""
					m.attackFocus = 1 // Username focus

					// Initialize Burp intruder defaults
					m.attackType = "Sniper"
					m.attackWordlist2 = ""
					m.attackGenCharset2 = "abcdefghijklmnopqrstuvwxyz0123456789"
					m.attackGenMaxLen2 = 4
					
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

		// ── Attack Edit Body screen ───────────────────────────────────
		case attackEditBodyScreen:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.screen = attackScreen
				m.loadAttackField()
			case "ctrl+s":
				m.attackOriginalBody = string(m.editBuf)
				m.screen = attackScreen
				m.loadAttackField()
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
	case attackEditBodyScreen:
		return m.attackEditBodyView()
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

func getAttackFieldHelp(focus int) string {
	switch focus {
	case 0:
		return "Target URL\n\nThe target HTTP/HTTPS URL. You can use manual § markers here (e.g., http://example.com/api?user=§admin§)."
	case 1:
		return "Method\n\nThe HTTP method used (GET, POST, etc.) for the attack requests."
	case 2:
		return "Static Username\n\nStatic username value used if you are not brute-forcing the username field."
	case 3:
		return "User Field\n\nForm parameter or JSON key name representing the Username. Use [MANUEL] to rely only on manual § markers."
	case 4:
		return "Pass Field\n\nForm parameter or JSON key name representing the Password. Use [MANUEL] to rely only on manual § markers."
	case 5:
		return "JSON Mode\n\nWhen enabled, requests will be sent with 'Content-Type: application/json' and parameter injection will respect JSON format."
	case 6:
		return "Concurrency\n\nThe number of concurrent worker threads. High values speed up the attack but might rate-limit or crash the server."
	case 7:
		return "Attack Type\n\nChoose the brute-force strategy:\n- Sniper: One payload list. Replaces one marker at a time.\n- Battering Ram: One payload list. Replaces all markers with the same value.\n- Pitchfork: Two payload sets. Replaces markers in pair lockstep.\n- Cluster Bomb: Two payload sets. Tries all combinations (Cartesian product)."
	case 8:
		return "Success Regex (Success RE)\n\nAn optional regular expression check. If this regex matches the response body, the attempt is marked as SUCCESS."
	case 9:
		return "Expected Status\n\nIf non-zero, checks the response status code against this value. Together with 'Success ifSt', determines success/failure."
	case 10:
		return "Success if Status Matches\n\n- true: status == Expected Status is SUCCESS\n- false: status != Expected Status is SUCCESS (useful to detect when code changes from 401/403 to 200/302)"
	case 11:
		return "Stop on Success\n\nIf enabled, the attack will cancel all remaining workers immediately when a successful payload is found."
	case 12:
		return "Wordlist 1 / NUM:\n\nWordlist path for Payload Set 1. Or use NUM:min-max (e.g., NUM:001-100) to generate a numeric sequence on the fly."
	case 13:
		return "Gen Charset 1\n\nFallback charset to generate random passwords for Set 1 if Wordlist 1 is left empty."
	case 14:
		return "Gen Max Length 1\n\nMaximum length of generated passwords for Set 1 if Wordlist 1 is empty."
	case 15:
		return "Wordlist 2 / NUM:\n\nWordlist path for Payload Set 2. Or use NUM:min-max (e.g. NUM:1-500) to generate numeric sequences."
	case 16:
		return "Gen Charset 2\n\nFallback charset for Set 2 payload generation."
	case 17:
		return "Gen Max Length 2\n\nMaximum length of generated passwords for Set 2."
	case 18:
		return "Delay (ms)\n\nTime in milliseconds to wait between sending requests. Useful to bypass rate limiting or prevent server overload."
	case 19:
		return "Batch Size\n\nNumber of requests to send before performing a longer pause (Batch Delay)."
	case 20:
		return "Batch Delay (ms)\n\nDuration of the delay in milliseconds after sending a full batch of requests."
	case 21:
		return "Random User-Agent\n\nRotate requests using a list of common browser User-Agent headers to bypass simple WAF rules."
	case 22:
		return "Random IP Header\n\nInject randomized X-Forwarded-For, X-Real-IP, and Client-IP headers to bypass IP-based rate limiting."
	case 23:
		return "Proxy List File\n\nPath to a file containing proxy servers (one per line, e.g. http://127.0.0.1:8080) to rotate requests."
	case 24:
		return "Reset Count\n\nIf non-zero, triggers a credential reset or warmup request after every N attempts."
	case 25:
		return "Reset Username\n\nThe username to send in the reset/warmup request."
	case 26:
		return "Reset Password\n\nThe password to send in the reset/warmup request."
	default:
		return ""
	}
}

func (m model) attackView() string {
	var topSection strings.Builder
	topSection.WriteString(styleTitle.Render("BRUTE FORCE ATTACK TOOL") + "\n")
	topSection.WriteString(strings.Repeat("─", 50) + "\n")

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

	attackTypeDisplay := m.attackType
	if m.attackFocus == 7 && !m.attackActive {
		attackTypeDisplay = fmt.Sprintf("< %s > (Use Left/Right keys)", m.attackType)
	}

	renderField := func(label string, val string, focus int) string {
		line := "  " + label + ": "
		if m.attackFocus == focus && !m.attackActive {
			if focus == 7 {
				line = "> " + label + ": " + val
			} else {
				line = "> " + label + ": " + string(m.editBuf[:m.editCursor]) + "█" + string(m.editBuf[m.editCursor:])
			}
			return lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599")).Bold(true).Render(line)
		} else {
			line += val
			return line
		}
	}

	var formLines []string
	// 1. TARGET CONFIG
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("┌── TARGET CONFIG ────────────────────────────────"))
	formLines = append(formLines, renderField("Target URL  ", m.attackTargetURL, 0))
	formLines = append(formLines, renderField("Method      ", m.attackMethod, 1))
	formLines = append(formLines, renderField("User Default", m.attackUser, 2))
	formLines = append(formLines, renderField("User Field  ", userFieldDisplay, 3))
	formLines = append(formLines, renderField("Pass Field  ", passFieldDisplay, 4))
	formLines = append(formLines, renderField("JSON Mode   ", fmt.Sprintf("%v", m.attackIsJSON), 5))
	formLines = append(formLines, renderField("Concurrent  ", fmt.Sprintf("%d", m.attackConcurrency), 6))

	// 2. ATTACK STRATEGY
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("├── ATTACK STRATEGY ──────────────────────────────"))
	formLines = append(formLines, renderField("Attack Type ", attackTypeDisplay, 7))
	formLines = append(formLines, renderField("Success RE  ", m.attackSuccessRegex, 8))
	formLines = append(formLines, renderField("Expected St ", fmt.Sprintf("%d", m.attackExpectedStatus), 9))
	formLines = append(formLines, renderField("Success ifSt", fmt.Sprintf("%v", m.attackStatusIsSuccess), 10))
	formLines = append(formLines, renderField("Stop Success", fmt.Sprintf("%v", m.attackStopOnSuccess), 11))

	// 3. PAYLOAD SET 1 (USER)
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("├── PAYLOAD SET 1 (USER) ──────────────────────────"))
	formLines = append(formLines, renderField("Wordlist 1  ", m.attackWordlist, 12))
	formLines = append(formLines, renderField("Gen Charset1", m.attackGenCharset, 13))
	formLines = append(formLines, renderField("Gen MaxLen 1", fmt.Sprintf("%d", m.attackGenMaxLen), 14))

	// 4. PAYLOAD SET 2 (PASS)
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("├── PAYLOAD SET 2 (PASS) ──────────────────────────"))
	formLines = append(formLines, renderField("Wordlist 2  ", m.attackWordlist2, 15))
	formLines = append(formLines, renderField("Gen Charset2", m.attackGenCharset2, 16))
	formLines = append(formLines, renderField("Gen MaxLen 2", fmt.Sprintf("%d", m.attackGenMaxLen2), 17))

	// 5. RATE LIMITS & TUNING
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("├── RATE LIMITS & TUNING ──────────────────────────"))
	formLines = append(formLines, renderField("Delay (ms)  ", fmt.Sprintf("%d", m.attackDelayMs), 18))
	formLines = append(formLines, renderField("Batch Size  ", fmt.Sprintf("%d", m.attackBatchSize), 19))
	formLines = append(formLines, renderField("Batch Delay ", fmt.Sprintf("%d", m.attackBatchDelayMs), 20))
	formLines = append(formLines, renderField("Random UA   ", fmt.Sprintf("%v", m.attackRandomUA), 21))
	formLines = append(formLines, renderField("Random IP   ", fmt.Sprintf("%v", m.attackRandomIP), 22))
	formLines = append(formLines, renderField("Proxy List  ", m.attackProxyList, 23))

	// 6. BYPASS & RESET
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("├── BYPASS & RESET ───────────────────────────────"))
	formLines = append(formLines, renderField("Reset Count ", fmt.Sprintf("%d", m.attackResetCount), 24))
	formLines = append(formLines, renderField("Reset User  ", m.attackResetUser, 25))
	formLines = append(formLines, renderField("Reset Pass  ", m.attackResetPass, 26))
	formLines = append(formLines, lipgloss.NewStyle().Foreground(lipgloss.Color("#CC66FF")).Bold(true).Render("└─────────────────────────────────────────────────"))

	formLines = append(formLines, styleDim.Render("Payload Preview:"))
	preview := m.attackOriginalBody
	if preview == "" {
		preview = "(Auto-generated based on fields)"
	} else if len(preview) > 150 {
		preview = preview[:147] + "..."
	}
	formLines = append(formLines, "  "+preview)

	formHeight := m.getFormHeight()

	// Adjust m.attackScroll bound check to be double-safe during View
	if m.attackScroll < 0 {
		m.attackScroll = 0
	}
	maxScroll := len(formLines) - formHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.attackScroll > maxScroll {
		m.attackScroll = maxScroll
	}

	end := m.attackScroll + formHeight
	if end > len(formLines) {
		end = len(formLines)
	}

	var formSB strings.Builder
	for _, l := range formLines[m.attackScroll:end] {
		formSB.WriteString(l + "\n")
	}

	// Help panel on the right
	rightSideHelp := getAttackFieldHelp(m.attackFocus)
	helpStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#4D9EFF")).
		Padding(1, 2).
		Width(38)

	helpBox := helpStyle.Render(rightSideHelp)

	// Combine form and right side help box horizontally
	var mainLayout string
	if m.width >= 95 {
		scrolledFormAndHelp := lipgloss.JoinHorizontal(lipgloss.Top, formSB.String(), "\n"+helpBox)
		mainLayout = topSection.String() + scrolledFormAndHelp
	} else {
		mainLayout = topSection.String() + formSB.String() + "\n" + helpBox
	}

	var finalSB strings.Builder
	finalSB.WriteString(mainLayout + "\n")
	finalSB.WriteString(strings.Repeat("─", 62) + "\n")

	// Atak Geçmişi Tablosu (Live Feed)
	if m.attackActive || len(m.attackHistory) > 0 {
		finalSB.WriteString(styleDim.Render(fmt.Sprintf("%-5s | %-20s | %-6s | %-6s", "ID", "Password", "Status", "Size")) + "\n")
		finalSB.WriteString(styleDim.Render(strings.Repeat("─", 62)) + "\n")
		
		maxHistoryRows := 5
		if m.height < 35 {
			maxHistoryRows = 3
		}
		if m.height < 25 {
			maxHistoryRows = 1
		}
		
		shownHistoryCount := len(m.attackHistory)
		if shownHistoryCount > maxHistoryRows {
			shownHistoryCount = maxHistoryRows
		}

		for i := 0; i < shownHistoryCount; i++ {
			h := m.attackHistory[i]
			pass := h.Password
			if len(pass) > 20 { pass = pass[:17] + "..." }
			
			statusColor := styleDim
			if h.StatusCode >= 200 && h.StatusCode < 300 {
				statusColor = styleStatus2xx
			} else if h.StatusCode >= 400 {
				statusColor = styleStatus4xx
			}
			
			resetTag := ""
			if h.IsReset {
				resetTag = styleWarn.Render(" (R)")
			}

			line := fmt.Sprintf("%-5d | %-20s | %-6s | %-6d", 
				h.AttemptCount, 
				pass, 
				statusColor.Render(fmt.Sprintf("%d", h.StatusCode)), 
				h.ContentLength)
			finalSB.WriteString(line + resetTag + "\n")
		}
		finalSB.WriteString(strings.Repeat("─", 62) + "\n")
	}

	if m.attackActive {
		finalSB.WriteString(styleWarn.Render("Status: ") + m.attackStatus + "\n")
	} else if m.attackResult != "" {
		if strings.Contains(m.attackResult, "SUCCESS") {
			finalSB.WriteString(styleOK.Render(m.attackResult) + "\n")
		} else {
			finalSB.WriteString(styleErr.Render(m.attackResult) + "\n")
		}
	} else {
		finalSB.WriteString(styleDim.Render("Status: Waiting to start...") + "\n")
	}

	finalSB.WriteString(strings.Repeat("─", 62) + "\n")
	if m.attackActive {
		finalSB.WriteString(styleDim.Render("ctrl+c:cancel attack") + "\n")
	} else {
		finalSB.WriteString(styleDim.Render("enter:start attack  tab:change field  esc:back  ctrl+e:edit body template") + "\n")
	}
	return finalSB.String()
}

func (m model) attackEditBodyView() string {
	var sb strings.Builder
	sb.WriteString(stylePUT.Render("EDIT REQUEST BODY TEMPLATE (Use § to define markers)") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	before := string(m.editBuf[:m.editCursor])
	after := string(m.editBuf[m.editCursor:])
	bufferText := before + "█" + after

	for _, l := range strings.Split(bufferText, "\n") {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("ctrl+s:save template  esc:cancel  ←→:cursor") + "\n")
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
	case 2: m.attackUser = string(m.editBuf)
	case 6:
		var c int
		fmt.Sscanf(string(m.editBuf), "%d", &c)
		if c > 0 { m.attackConcurrency = c }
	case 8: m.attackSuccessRegex = string(m.editBuf)
	case 9:
		var es int
		fmt.Sscanf(string(m.editBuf), "%d", &es)
		m.attackExpectedStatus = es
	case 12: m.attackWordlist = string(m.editBuf)
	case 13: m.attackGenCharset = string(m.editBuf)
	case 14:
		m.attackGenMaxLen, _ = strconv.Atoi(string(m.editBuf))
	case 15: m.attackWordlist2 = string(m.editBuf)
	case 16: m.attackGenCharset2 = string(m.editBuf)
	case 17:
		m.attackGenMaxLen2, _ = strconv.Atoi(string(m.editBuf))
	case 18:
		var d int
		fmt.Sscanf(string(m.editBuf), "%d", &d)
		m.attackDelayMs = d
	case 19:
		var b int
		fmt.Sscanf(string(m.editBuf), "%d", &b)
		m.attackBatchSize = b
	case 20:
		var bd int
		fmt.Sscanf(string(m.editBuf), "%d", &bd)
		m.attackBatchDelayMs = bd
	case 23: m.attackProxyList = string(m.editBuf)
	case 24:
		m.attackResetCount, _ = strconv.Atoi(string(m.editBuf))
	case 25: m.attackResetUser = string(m.editBuf)
	case 26: m.attackResetPass = string(m.editBuf)
	}
}

func (m *model) loadAttackField() {
	var s string
	switch m.attackFocus {
	case 0: s = m.attackTargetURL
	case 1: s = m.attackMethod
	case 2: s = m.attackUser
	case 3: s = m.attackUserField
	case 4: s = m.attackPassField
	case 5: s = fmt.Sprintf("%v", m.attackIsJSON)
	case 6: s = fmt.Sprintf("%d", m.attackConcurrency)
	case 7: s = m.attackType
	case 8: s = m.attackSuccessRegex
	case 9: s = fmt.Sprintf("%d", m.attackExpectedStatus)
	case 10: s = fmt.Sprintf("%v", m.attackStatusIsSuccess)
	case 11: s = fmt.Sprintf("%v", m.attackStopOnSuccess)
	case 12: s = m.attackWordlist
	case 13: s = m.attackGenCharset
	case 14: s = fmt.Sprintf("%d", m.attackGenMaxLen)
	case 15: s = m.attackWordlist2
	case 16: s = m.attackGenCharset2
	case 17: s = fmt.Sprintf("%d", m.attackGenMaxLen2)
	case 18: s = fmt.Sprintf("%d", m.attackDelayMs)
	case 19: s = fmt.Sprintf("%d", m.attackBatchSize)
	case 20: s = fmt.Sprintf("%d", m.attackBatchDelayMs)
	case 21: s = fmt.Sprintf("%v", m.attackRandomUA)
	case 22: s = fmt.Sprintf("%v", m.attackRandomIP)
	case 23: s = m.attackProxyList
	case 24: s = fmt.Sprintf("%d", m.attackResetCount)
	case 25: s = m.attackResetUser
	case 26: s = m.attackResetPass
	}
	m.editBuf = []rune(s)
	m.editCursor = len(m.editBuf)
}

func getFocusLine(focus int) int {
	switch {
	case focus >= 0 && focus <= 6:
		return 1 + focus
	case focus >= 7 && focus <= 11:
		return 2 + focus
	case focus >= 12 && focus <= 14:
		return 3 + focus
	case focus >= 15 && focus <= 17:
		return 4 + focus
	case focus >= 18 && focus <= 23:
		return 5 + focus
	case focus >= 24 && focus <= 26:
		return 6 + focus
	default:
		return 0
	}
}

func (m model) getAttackResultLines() int {
	if m.attackActive {
		return 1
	}
	if m.attackResult == "" {
		return 1 // "Status: Waiting to start..."
	}
	return len(strings.Split(m.attackResult, "\n"))
}

func (m model) getFormHeight() int {
	nonFormHeight := 2 // title + separator

	// History/Live Feed
	if m.attackActive || len(m.attackHistory) > 0 {
		maxHistoryRows := 5
		if m.height < 35 {
			maxHistoryRows = 3
		}
		if m.height < 25 {
			maxHistoryRows = 1
		}
		shownHistoryCount := len(m.attackHistory)
		if shownHistoryCount > maxHistoryRows {
			shownHistoryCount = maxHistoryRows
		}
		// 3 extra lines: header (1) + separator (1) + bottom border (1)
		nonFormHeight += 3 + shownHistoryCount
	}

	// Status/Result lines
	nonFormHeight += m.getAttackResultLines()

	// Keys and separators
	nonFormHeight += 4 // separator before history/status (1) + separator after status (1) + keys hint (1) + final newline (1)

	// Help box if stacked vertically
	if m.width < 95 {
		rightSideHelp := getAttackFieldHelp(m.attackFocus)
		helpBoxHeight := len(strings.Split(rightSideHelp, "\n")) + 2
		nonFormHeight += helpBoxHeight
	}
	
	formHeight := m.height - nonFormHeight
	if formHeight < 5 {
		formHeight = 5
	}
	return formHeight
}

func (m *model) adjustAttackScroll() {
	formHeight := m.getFormHeight()
	focusLine := getFocusLine(m.attackFocus)
	
	// Ensure focusLine is visible
	if focusLine < m.attackScroll {
		m.attackScroll = focusLine
	} else if focusLine >= m.attackScroll + formHeight {
		m.attackScroll = focusLine - formHeight + 1
	}
	
	// Bound checks
	if m.attackScroll < 0 {
		m.attackScroll = 0
	}
}