package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// ── HAR 1.2 structs ───────────────────────────────────────────────────────────

type HAR struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Version string     `json:"version"`
	Creator HARCreator `json:"creator"`
	Entries []HAREntry `json:"entries"`
}

type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type HAREntry struct {
	StartedDateTime string      `json:"startedDateTime"`
	Time            int64       `json:"time"`
	Request         HARRequest  `json:"request"`
	Response        HARResponse `json:"response"`
	Timings         HARTimings  `json:"timings"`
}

type HARRequest struct {
	Method      string       `json:"method"`
	URL         string       `json:"url"`
	HTTPVersion string       `json:"httpVersion"`
	Headers     []HARHeader  `json:"headers"`
	QueryString []HARParam   `json:"queryString"`
	PostData    *HARPostData `json:"postData,omitempty"`
	HeadersSize int          `json:"headersSize"`
	BodySize    int          `json:"bodySize"`
}

type HARResponse struct {
	Status      int        `json:"status"`
	StatusText  string     `json:"statusText"`
	HTTPVersion string     `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent `json:"content"`
	RedirectURL string     `json:"redirectURL"`
	HeadersSize int        `json:"headersSize"`
	BodySize    int        `json:"bodySize"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
}

type HARTimings struct {
	Send    int64 `json:"send"`
	Wait    int64 `json:"wait"`
	Receive int64 `json:"receive"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func headersToHAR(h map[string]string) []HARHeader {
	out := make([]HARHeader, 0, len(h))
	for k, v := range h {
		out = append(out, HARHeader{Name: k, Value: v})
	}
	return out
}

var statusTexts = map[int]string{
	200: "OK", 201: "Created", 204: "No Content",
	301: "Moved Permanently", 302: "Found", 304: "Not Modified",
	400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
	404: "Not Found", 429: "Too Many Requests",
	500: "Internal Server Error", 502: "Bad Gateway", 503: "Service Unavailable",
}

func harStatusText(code int) string {
	if t, ok := statusTexts[code]; ok {
		return t
	}
	return "Unknown"
}

// ExportHAR writes captured events to a HAR 1.2 file and returns the filename.
func ExportHAR(events []Event) (string, error) {
	if len(events) == 0 {
		return "", fmt.Errorf("no events to export")
	}

	entries := make([]HAREntry, 0, len(events))
	for _, e := range events {
		var postData *HARPostData
		if e.ReqBody != "" {
			ct := e.ReqHeaders["Content-Type"]
			postData = &HARPostData{MimeType: ct, Text: e.ReqBody}
		}

		contentType := e.RespHeaders["Content-Type"]

		startedAt := e.Timestamp
		if startedAt.IsZero() {
			startedAt = time.Now()
		}

		entries = append(entries, HAREntry{
			StartedDateTime: startedAt.UTC().Format(time.RFC3339Nano),
			Time:            e.LatencyMs,
			Request: HARRequest{
				Method:      e.Method,
				URL:         e.FullURL,
				HTTPVersion: "HTTP/1.1",
				Headers:     headersToHAR(e.ReqHeaders),
				QueryString: []HARParam{},
				PostData:    postData,
				HeadersSize: -1,
				BodySize:    len(e.ReqBody),
			},
			Response: HARResponse{
				Status:      e.Status,
				StatusText:  harStatusText(e.Status),
				HTTPVersion: "HTTP/1.1",
				Headers:     headersToHAR(e.RespHeaders),
				Content:     HARContent{Size: len(e.RespBody), MimeType: contentType, Text: e.RespBody},
				RedirectURL: "",
				HeadersSize: -1,
				BodySize:    len(e.RespBody),
			},
			Timings: HARTimings{Send: 0, Wait: e.LatencyMs, Receive: 0},
		})
	}

	har := HAR{Log: HARLog{
		Version: "1.2",
		Creator: HARCreator{Name: "go-proxy-inspector", Version: "1.0"},
		Entries: entries,
	}}

	filename := fmt.Sprintf("traffic_%s.har", time.Now().Format("20060102_150405"))
	data, err := json.MarshalIndent(har, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(filename, data, 0o644); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	return filename, nil
}
