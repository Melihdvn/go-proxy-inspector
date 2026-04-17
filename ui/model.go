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
)

type model struct {
	events      []proxy.Event
	cursor      int
	width       int
	height      int
	screen      screen
	detailScroll int
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
				}
			}

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

	// Build all scrollable lines
	lines := buildDetailLines(e)

	const fixedLines = 4
	viewHeight := m.height - fixedLines
	if viewHeight < 2 {
		viewHeight = 2
	}

	// Clamp scroll
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
	sb.WriteString("esc: back  q: quit  ↑/k ↓/j: scroll\n")
	return sb.String()
}

func buildDetailLines(e proxy.Event) []string {
	var lines []string

	lines = append(lines, "── Request Headers ──────────────────────────────")
	if len(e.ReqHeaders) == 0 {
		lines = append(lines, "  (none)")
	} else {
		// Sort for consistent display
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

	return lines
}