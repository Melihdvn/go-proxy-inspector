package main

import (
	"fmt"
	"proxy-inspector/proxy"
)

func main() {
	fmt.Println("Proxy running on :3000")

	go proxy.Start("http://localhost:4001")

	go func() {
	for event := range proxy.EventChannel {
		fmt.Printf("[%s] %s %s -> %d (%dms)\n",
			event.Method,
			event.URL,
			event.URL,
			event.Status,
			event.LatencyMs,
		)
	}
}()

	select {}
}