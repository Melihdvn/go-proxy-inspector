package main

import (
	"fmt"
	"proxy-inspector/proxy"
	"proxy-inspector/ui"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {

	fmt.Println("STARTING PROXY + UI")

	// start proxy
	go proxy.Start("http://localhost:4001")

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