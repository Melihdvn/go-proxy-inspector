package proxy

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"
)

// ReplayWithResponse sends the event's request (with optionally modified body)
// and returns a new Event containing the full response, so the UI can display it.
func ReplayWithResponse(e Event, body string) (Event, error) {
	req, err := http.NewRequest(e.Method, e.FullURL, strings.NewReader(body))
	if err != nil {
		return Event{}, err
	}

	skip := map[string]bool{
		"content-length":    true,
		"transfer-encoding": true,
	}
	for k, v := range e.ReqHeaders {
		if !skip[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return Event{}, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}
	reqHeaders := map[string]string{}
	for k, v := range req.Header {
		if len(v) > 0 {
			reqHeaders[k] = v[0]
		}
	}

	return Event{
		Timestamp:   time.Now(),
		Method:      e.Method,
		Host:        e.Host,
		URL:         e.URL,
		FullURL:     e.FullURL,
		Status:      resp.StatusCode,
		LatencyMs:   time.Since(start).Milliseconds(),
		ReqBody:     body,
		ReqHeaders:  reqHeaders,
		RespBody:    string(respBody),
		RespHeaders: respHeaders,
	}, nil
}
