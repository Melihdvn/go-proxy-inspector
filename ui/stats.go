package ui

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"proxy-inspector/proxy"
)

// Stats holds computed aggregate statistics for all captured events.
type Stats struct {
	Total       int
	Methods     map[string]int
	StatusBands map[string]int // "2xx", "3xx", "4xx", "5xx", "other"
	TopHosts    []HostCount
	AvgLatency  float64
	MinLatency  int64
	MaxLatency  int64
	Buckets     []LatencyBucket
}

// HostCount pairs a host with its request count.
type HostCount struct {
	Host  string
	Count int
}

// LatencyBucket is one bar in the latency histogram.
type LatencyBucket struct {
	Label string
	Count int
}

// ComputeStats calculates statistics from a slice of events.
func ComputeStats(events []proxy.Event) Stats {
	if len(events) == 0 {
		return Stats{
			Methods:     map[string]int{},
			StatusBands: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0},
		}
	}

	s := Stats{
		Total:       len(events),
		Methods:     map[string]int{},
		StatusBands: map[string]int{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0},
		MinLatency:  events[0].LatencyMs,
		MaxLatency:  events[0].LatencyMs,
	}

	hostCounts := map[string]int{}
	var totalLat int64

	for _, e := range events {
		if e.Blocked {
			continue
		}
		s.Methods[e.Method]++
		switch {
		case e.Status >= 500:
			s.StatusBands["5xx"]++
		case e.Status >= 400:
			s.StatusBands["4xx"]++
		case e.Status >= 300:
			s.StatusBands["3xx"]++
		case e.Status >= 200:
			s.StatusBands["2xx"]++
		default:
			s.StatusBands["other"]++
		}
		hostCounts[e.Host]++
		totalLat += e.LatencyMs
		if e.LatencyMs < s.MinLatency {
			s.MinLatency = e.LatencyMs
		}
		if e.LatencyMs > s.MaxLatency {
			s.MaxLatency = e.LatencyMs
		}
	}

	if s.Total > 0 {
		s.AvgLatency = float64(totalLat) / float64(s.Total)
	}

	// Top 5 hosts
	type kv struct{ k string; v int }
	var sorted []kv
	for k, v := range hostCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	limit := 5
	if len(sorted) < limit {
		limit = len(sorted)
	}
	for _, item := range sorted[:limit] {
		s.TopHosts = append(s.TopHosts, HostCount{Host: item.k, Count: item.v})
	}

	s.Buckets = buildLatencyBuckets(events)
	return s
}

func buildLatencyBuckets(events []proxy.Event) []LatencyBucket {
	defs := []struct {
		label string
		max   int64
	}{
		{"<10ms", 10},
		{"10-50ms", 50},
		{"50-100ms", 100},
		{"100-500ms", 500},
		{"500ms-1s", 1000},
		{">1s", math.MaxInt64},
	}
	counts := make([]int, len(defs))
	for _, e := range events {
		for i, b := range defs {
			if e.LatencyMs < b.max {
				counts[i]++
				break
			}
		}
	}
	out := make([]LatencyBucket, len(defs))
	for i, b := range defs {
		out[i] = LatencyBucket{Label: b.label, Count: counts[i]}
	}
	return out
}

// RenderStats renders the stats screen content as a string.
func RenderStats(s Stats) string {
	var sb strings.Builder

	sb.WriteString(styleTitle.Render("  go-proxy-inspector — Statistics") + "\n")
	sb.WriteString(strings.Repeat("─", 60) + "\n")
	sb.WriteString(fmt.Sprintf("  Total Requests : %s\n", stylePOST.Render(fmt.Sprintf("%d", s.Total))))
	sb.WriteString("\n")

	// Methods
	sb.WriteString(styleGET.Render("── Methods ─────────────────────────────────────────") + "\n")
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		if c, ok := s.Methods[m]; ok && c > 0 {
			bar := pct(c, s.Total, 20)
			sb.WriteString(fmt.Sprintf("  %s  %s %d\n", methodStyle(m).Render(fmt.Sprintf("%-7s", m)), bar, c))
		}
	}
	sb.WriteString("\n")

	// Status bands
	sb.WriteString(styleOK.Render("── Status Codes ────────────────────────────────────") + "\n")
	for _, si := range []struct{ label, band string }{
		{"2xx  OK    ", "2xx"}, {"3xx  Redir ", "3xx"},
		{"4xx  Client", "4xx"}, {"5xx  Server", "5xx"},
	} {
		c := s.StatusBands[si.band]
		bar := pct(c, s.Total, 20)
		sb.WriteString(fmt.Sprintf("  %s  %s %d\n", si.label, bar, c))
	}
	sb.WriteString("\n")

	// Latency
	sb.WriteString(styleRedir.Render("── Latency ─────────────────────────────────────────") + "\n")
	sb.WriteString(fmt.Sprintf("  Avg: %dms   Min: %dms   Max: %dms\n",
		int(s.AvgLatency), s.MinLatency, s.MaxLatency))
	sb.WriteString("\n")

	// Histogram
	sb.WriteString(styleRedir.Render("── Latency Distribution ────────────────────────────") + "\n")
	maxBucket := 0
	for _, b := range s.Buckets {
		if b.Count > maxBucket {
			maxBucket = b.Count
		}
	}
	for _, b := range s.Buckets {
		barLen := 0
		if maxBucket > 0 {
			barLen = int(float64(b.Count) / float64(maxBucket) * 24)
		}
		bar := styleOK.Render(strings.Repeat("█", barLen))
		sb.WriteString(fmt.Sprintf("  %-10s │%s %d\n", b.Label, bar, b.Count))
	}
	sb.WriteString("\n")

	// Top hosts
	if len(s.TopHosts) > 0 {
		sb.WriteString(stylePOST.Render("── Top Hosts ───────────────────────────────────────") + "\n")
		for i, hc := range s.TopHosts {
			bar := pct(hc.Count, s.Total, 16)
			host := hc.Host
			if len(host) > 36 {
				host = host[:33] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %d. %-36s %s %d\n", i+1, host, bar, hc.Count))
		}
	}

	return sb.String()
}

func pct(count, total, maxWidth int) string {
	if total == 0 || count == 0 {
		return strings.Repeat(" ", maxWidth)
	}
	barLen := int(float64(count) / float64(total) * float64(maxWidth))
	if barLen < 1 {
		barLen = 1
	}
	return styleOK.Render(strings.Repeat("▪", barLen))
}
