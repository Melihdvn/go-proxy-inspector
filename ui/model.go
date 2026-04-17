package ui

import (
	"fmt"
	"sort"
	"strings"

	"proxy-inspector/proxy"

	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	listScreen   screen = iota
	detailScreen
	editScreen
)

type model struct {
	events      []proxy.Event
	cursor      int
	width       int
	height      int
	screen      screen
	detailScroll int

	// edit mode
	editBuf    []rune
	editCursor int
	replayMsg  string
}

func NewModel() model {
	return model{events: []proxy.Event{}}
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch m.screen {

		// ── List screen ───────────────────────────────────────────────
		case listScreen:
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.events)-1 {
					m.cursor++
				}
			case "enter":
				if len(m.events) > 0 {
					m.screen = detailScreen
					m.detailScroll = 0
					m.replayMsg = ""
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
				if m.cursor < len(m.events) {
					m.editBuf = []rune(m.events[m.cursor].ReqBody)
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
				// Replay in background; UI stays on detail screen
				body := string(m.editBuf)
				e := m.events[m.cursor]
				go func() {
					if err := proxy.Replay(e, body); err != nil {
						// Error will be silently ignored for now
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
				if len(msg.Runes) > 0 {
					m.editBuf = append(m.editBuf[:m.editCursor:m.editCursor], append(msg.Runes, m.editBuf[m.editCursor:]...)...)
					m.editCursor += len(msg.Runes)
				}
			}
		}

	case proxy.Event:
		m.events = append([]proxy.Event{msg}, m.events...)
		if m.screen == listScreen {
			m.cursor++
			if m.cursor >= len(m.events) {
				m.cursor = len(m.events) - 1
			}
		}
		if len(m.events) > 100 {
			m.events = m.events[:100]
			if m.cursor >= len(m.events) {
				m.cursor = len(m.events) - 1
			}
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

// ── List screen ───────────────────────────────────────────────────────────

func (m model) listView() string {
	var sb strings.Builder

	sb.WriteString("HTTP Proxy Inspector\n")
	sb.WriteString(strings.Repeat("─", 50) + "\n")

	if len(m.events) == 0 {
		sb.WriteString("  No requests yet... Send a request to :3000\n")
		sb.WriteString(strings.Repeat("─", 50) + "\n")
		sb.WriteString("q: quit  ↑/k ↓/j: navigate  enter: detail\n")
		return sb.String()
	}

	const fixedLines = 4
	listHeight := m.height - fixedLines
	if listHeight < 2 {
		listHeight = 2
	}

	start := 0
	if m.cursor >= listHeight {
		start = m.cursor - listHeight + 1
	}
	end := start + listHeight
	if end > len(m.events) {
		end = len(m.events)
	}

	for i := start; i < end; i++ {
		e := m.events[i]
		cur := "  "
		if i == m.cursor {
			cur = "> "
		}
		line := fmt.Sprintf("%s[%-6s] %-30s %d  %dms\n",
			cur, e.Method, e.URL, e.Status, e.LatencyMs)
		sb.WriteString(line)
	}

	sb.WriteString(strings.Repeat("─", 50) + "\n")
	sb.WriteString("q: quit  ↑/k ↓/j: navigate  enter: detail\n")
	return sb.String()
}

// ── Detail screen ─────────────────────────────────────────────────────────

func (m model) detailView() string {
	if m.cursor >= len(m.events) {
		return "No event selected.\n"
	}

	e := m.events[m.cursor]
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[ %s %s — %d — %dms ]\n", e.Method, e.URL, e.Status, e.LatencyMs))
	sb.WriteString(strings.Repeat("─", 50) + "\n")

	if m.replayMsg != "" {
		sb.WriteString(m.replayMsg + "\n")
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

	sb.WriteString(strings.Repeat("─", 50) + "\n")
	sb.WriteString("esc: back  e: edit & replay  ↑/k ↓/j: scroll\n")
	return sb.String()
}

func buildDetailLines(e proxy.Event) []string {
	var lines []string

	// ── Request ───────────────────────────────────────────────────────
	lines = append(lines, "── Request Headers ──────────────────────────────")
	if len(e.ReqHeaders) == 0 {
		lines = append(lines, "  (none)")
	} else {
		keys := make([]string, 0, len(e.ReqHeaders))
		for k := range e.ReqHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("  %-30s %s", k+":", e.ReqHeaders[k]))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "── Request Body ─────────────────────────────────")
	body := strings.TrimSpace(e.ReqBody)
	if body == "" {
		lines = append(lines, "  (empty)")
	} else {
		for _, l := range strings.Split(body, "\n") {
			lines = append(lines, "  "+l)
		}
	}

	// ── Response ──────────────────────────────────────────────────────
	lines = append(lines, "")
	lines = append(lines, "── Response Headers ─────────────────────────────")
	if len(e.RespHeaders) == 0 {
		lines = append(lines, "  (none)")
	} else {
		keys := make([]string, 0, len(e.RespHeaders))
		for k := range e.RespHeaders {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("  %-30s %s", k+":", e.RespHeaders[k]))
		}
	}

	lines = append(lines, "")
	lines = append(lines, "── Response Body ────────────────────────────────")
	respBody := strings.TrimSpace(e.RespBody)
	if respBody == "" {
		lines = append(lines, "  (empty)")
	} else {
		for _, l := range strings.Split(respBody, "\n") {
			lines = append(lines, "  "+l)
		}
	}

	return lines
}

// ── Edit screen ───────────────────────────────────────────────────────────

func (m model) editView() string {
	if m.cursor >= len(m.events) {
		return "No event selected.\n"
	}

	e := m.events[m.cursor]
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("EDIT  [ %s %s ]\n", e.Method, e.URL))
	sb.WriteString(strings.Repeat("─", 50) + "\n")

	// Render buffer with cursor marker
	before := string(m.editBuf[:m.editCursor])
	after := string(m.editBuf[m.editCursor:])
	bufferText := before + "█" + after

	// Show each line of the buffer
	for _, l := range strings.Split(bufferText, "\n") {
		sb.WriteString(l + "\n")
	}

	sb.WriteString(strings.Repeat("─", 50) + "\n")
	sb.WriteString("ctrl+s: replay  esc: cancel  ←→: cursor  home/end\n")
	return sb.String()
}