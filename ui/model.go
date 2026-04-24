package ui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"proxy-inspector/proxy"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"
)

// ── Lipgloss styles ───────────────────────────────────────────────────────────

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

	styleTitle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00E599")).Bold(true)
	styleCursor = lipgloss.NewStyle().Bold(true).Reverse(true)
	styleFilter = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB800"))
	styleDim    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
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
	listScreen   screen = iota
	detailScreen
	editScreen
)

type model struct {
	events       []proxy.Event
	cursor       int
	width        int
	height       int
	screen       screen
	detailScroll int

	// filter
	filterMode bool
	filterBuf  string

	// edit mode
	editBuf    []rune
	editCursor int
	replayMsg  string

	// export feedback
	exportMsg string
}

func NewModel() model {
	return model{events: []proxy.Event{}}
}

func (m model) Init() tea.Cmd { return nil }

// filteredEvents returns events matching the current filter query.
func (m model) filteredEvents() []proxy.Event {
	if m.filterBuf == "" {
		return m.events
	}
	q := strings.ToLower(m.filterBuf)
	out := make([]proxy.Event, 0, len(m.events))
	for _, e := range m.events {
		if strings.Contains(strings.ToLower(e.URL), q) ||
			strings.Contains(strings.ToLower(e.Method), q) {
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
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.filteredEvents())-1 {
					m.cursor++
				}
			case "enter":
				if len(m.filteredEvents()) > 0 {
					m.screen = detailScreen
					m.detailScroll = 0
					m.replayMsg = ""
				}
			case "/":
				m.filterMode = true
			case "ctrl+x":
				m.filterBuf = ""
				m.cursor = 0
			case "x":
				// Export all events to a JSON file
				evs := m.events
				go func() {
					_, _ = proxy.ExportEvents(evs)
				}()
				if len(m.events) == 0 {
					m.exportMsg = "⚠ No events to export"
				} else {
					m.exportMsg = fmt.Sprintf("✓ Exporting %d events…", len(m.events))
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
				vis := m.filteredEvents()
				if m.cursor < len(vis) {
					m.editBuf = []rune(vis[m.cursor].ReqBody)
					m.editCursor = len(m.editBuf)
					m.screen = editScreen
					m.replayMsg = ""
				}
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
				vis := m.filteredEvents()
				e := vis[m.cursor]
				go func() {
					if err := proxy.Replay(e, body); err != nil {
						_ = err
					}
				}()
				m.screen = detailScreen
				m.replayMsg = "↺ Replayed! (check list for new event)"
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
			case "home", "ctrl+a":
				m.editCursor = 0
			case "end", "ctrl+e":
				m.editCursor = len(m.editBuf)
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

	case proxy.Event:
		m.events = append([]proxy.Event{msg}, m.events...)
		if m.screen == listScreen && !m.filterMode {
			m.cursor++
			vis := m.filteredEvents()
			if m.cursor >= len(vis) {
				m.cursor = len(vis) - 1
			}
			if m.cursor < 0 {
				m.cursor = 0
			}
		}
		if len(m.events) > 100 {
			m.events = m.events[:100]
		}
	}

	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case detailScreen:
		return m.detailView()
	case editScreen:
		return m.editView()
	default:
		return m.listView()
	}
}

// ── List screen ───────────────────────────────────────────────────────────────

func (m model) listView() string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("HTTP Proxy Inspector") + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	// Export feedback
	if m.exportMsg != "" {
		sb.WriteString(styleOK.Render(m.exportMsg) + "\n")
	}

	// Filter bar
	if m.filterMode {
		sb.WriteString(styleFilter.Render("/ Filter: "+m.filterBuf+"█") + "\n")
	} else if m.filterBuf != "" {
		sb.WriteString(styleFilter.Render("/ "+m.filterBuf) + styleDim.Render("  ctrl+x:clear") + "\n")
	}

	vis := m.filteredEvents()

	if len(vis) == 0 {
		if m.filterBuf != "" {
			sb.WriteString(styleDim.Render("  No requests match the filter.\n"))
		} else {
			sb.WriteString(styleDim.Render("  No requests yet… Send a request to :3000\n"))
		}
		sb.WriteString(strings.Repeat("─", 62) + "\n")
		sb.WriteString(styleDim.Render("q:quit  ↑/k ↓/j:navigate  enter:detail  /:filter") + "\n")
		return sb.String()
	}

	extraLines := 0
	if m.filterBuf != "" {
		extraLines = 1
	}
	const fixedLines = 4
	listHeight := m.height - fixedLines - extraLines
	if listHeight < 2 {
		listHeight = 2
	}

	start := 0
	if m.cursor >= listHeight {
		start = m.cursor - listHeight + 1
	}
	end := start + listHeight
	if end > len(vis) {
		end = len(vis)
	}

	for i := start; i < end; i++ {
		e := vis[i]
		mst := methodStyle(e.Method)
		sst := statusStyle(e.Status)

		methodStr := fmt.Sprintf("%-6s", e.Method)
		urlStr := fmt.Sprintf("%-32s", e.URL)
		statusStr := fmt.Sprintf("%d", e.Status)
		latStr := fmt.Sprintf("%dms", e.LatencyMs)

		var line string
		if i == m.cursor {
			// Reversed highlight — plain text inside Reverse style
			raw := fmt.Sprintf("> [%-6s] %-32s  %s  %s",
				e.Method, e.URL, statusStr, latStr)
			line = styleCursor.Render(raw)
		} else {
			line = fmt.Sprintf("  [%s] %s  %s  %s",
				mst.Render(methodStr),
				urlStr,
				sst.Render(statusStr),
				styleDim.Render(latStr),
			)
		}
		sb.WriteString(line + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("q:quit  ↑/k ↓/j:navigate  enter:detail  /:filter  ctrl+x:clear  x:export") + "\n")
	return sb.String()
}

// ── Detail screen ─────────────────────────────────────────────────────────────

func (m model) detailView() string {
	vis := m.filteredEvents()
	if m.cursor >= len(vis) {
		return "No event selected.\n"
	}
	e := vis[m.cursor]
	var sb strings.Builder

	mst := methodStyle(e.Method)
	sst := statusStyle(e.Status)
	header := fmt.Sprintf("[ %s %s — %s — %dms ]",
		mst.Render(e.Method),
		e.URL,
		sst.Render(fmt.Sprintf("%d", e.Status)),
		e.LatencyMs,
	)
	sb.WriteString(header + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	if m.replayMsg != "" {
		sb.WriteString(styleFilter.Render(m.replayMsg) + "\n")
	}

	lines := buildDetailLines(e)

	const fixedLines = 4
	viewHeight := m.height - fixedLines
	if m.replayMsg != "" {
		viewHeight--
	}
	if viewHeight < 2 {
		viewHeight = 2
	}

	maxScroll := len(lines) - viewHeight
	if maxScroll < 0 {
		maxScroll = 0
	}
	scroll := m.detailScroll
	if scroll > maxScroll {
		scroll = maxScroll
	}
	end := scroll + viewHeight
	if end > len(lines) {
		end = len(lines)
	}

	for _, l := range lines[scroll:end] {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("esc:back  e:edit&replay  ↑/k ↓/j:scroll") + "\n")
	return sb.String()
}

func buildDetailLines(e proxy.Event) []string {
	var lines []string

	lines = append(lines, styleGET.Render("── Request Headers ───────────────────────────────────"))
	if len(e.ReqHeaders) == 0 {
		lines = append(lines, styleDim.Render("  (none)"))
	} else {
		keys := make([]string, 0, len(e.ReqHeaders))
		for k := range e.ReqHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("  %s %s",
				styleDim.Render(fmt.Sprintf("%-30s", k+":")),
				e.ReqHeaders[k],
			))
		}
	}

	lines = append(lines, "")
	lines = append(lines, styleGET.Render("── Request Body ──────────────────────────────────────"))
	body := strings.TrimSpace(e.ReqBody)
	if body == "" {
		lines = append(lines, styleDim.Render("  (empty)"))
	} else {
		for _, l := range strings.Split(prettyJSON(body), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	lines = append(lines, "")
	lines = append(lines, styleOK.Render("── Response Headers ──────────────────────────────────"))
	if len(e.RespHeaders) == 0 {
		lines = append(lines, styleDim.Render("  (none)"))
	} else {
		keys := make([]string, 0, len(e.RespHeaders))
		for k := range e.RespHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("  %s %s",
				styleDim.Render(fmt.Sprintf("%-30s", k+":")),
				e.RespHeaders[k],
			))
		}
	}

	lines = append(lines, "")
	lines = append(lines, styleOK.Render("── Response Body ─────────────────────────────────────"))
	respBody := strings.TrimSpace(e.RespBody)
	if respBody == "" {
		lines = append(lines, styleDim.Render("  (empty)"))
	} else {
		for _, l := range strings.Split(prettyJSON(respBody), "\n") {
			lines = append(lines, "  "+l)
		}
	}

	return lines
}

// prettyJSON attempts to pretty-print a JSON string; returns the original on failure.
func prettyJSON(s string) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(s), "", "  "); err != nil {
		return s
	}
	return buf.String()
}

// ── Edit screen ───────────────────────────────────────────────────────────────

func (m model) editView() string {
	vis := m.filteredEvents()
	if m.cursor >= len(vis) {
		return "No event selected.\n"
	}
	e := vis[m.cursor]
	var sb strings.Builder

	sb.WriteString(stylePUT.Render(fmt.Sprintf("EDIT  [ %s %s ]", e.Method, e.URL)) + "\n")
	sb.WriteString(strings.Repeat("─", 62) + "\n")

	before := string(m.editBuf[:m.editCursor])
	after := string(m.editBuf[m.editCursor:])
	bufferText := before + "█" + after

	for _, l := range strings.Split(bufferText, "\n") {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 62) + "\n")
	sb.WriteString(styleDim.Render("ctrl+s:replay  esc:cancel  ←→:cursor  home/end") + "\n")
	return sb.String()
}