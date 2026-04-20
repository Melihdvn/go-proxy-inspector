package proxy

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// loggingTransport intercepts each request/response pair
type loggingTransport struct {
	wrapped http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	// Read and restore request body
	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Collect headers
	headers := map[string]string{}
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	// Read and restore response body
	var respBodyBytes []byte
	if resp.Body != nil {
		respBodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
	}

	// Collect response headers
	respHeaders := map[string]string{}
	for k, v := range resp.Header {
		if len(v) > 0 {
			respHeaders[k] = v[0]
		}
	}

	EventChannel <- Event{
		Method:      req.Method,
		URL:         req.URL.Path,
		FullURL:     req.URL.RequestURI(),
		Status:      resp.StatusCode,
		LatencyMs:   time.Since(start).Milliseconds(),
		ReqBody:     string(bodyBytes),
		ReqHeaders:  headers,
		RespBody:    string(respBodyBytes),
		RespHeaders: respHeaders,
	}

	return resp, nil
}

// Start starts the proxy using a Config struct. It supports optional TLS when
// TLSCertFile and TLSKeyFile are provided.
func Start(cfg Config) {
	remote, err := url.Parse(cfg.Target)
	if err != nil {
		log.Fatalf("proxy: invalid target URL %q: %v", cfg.Target, err)
	}

	p := httputil.NewSingleHostReverseProxy(remote)
	p.Transport = &loggingTransport{wrapped: http.DefaultTransport}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.Host = remote.Host
		p.ServeHTTP(w, r)
	})

	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		log.Printf("proxy: listening (TLS) on %s → %s", cfg.ListenAddr, cfg.Target)
		if err := http.ListenAndServeTLS(cfg.ListenAddr, cfg.TLSCertFile, cfg.TLSKeyFile, mux); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	} else {
		log.Printf("proxy: listening on %s → %s", cfg.ListenAddr, cfg.Target)
		if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
			log.Fatalf("proxy: %v", err)
		}
	}
}

// Replay sends a modified request back through the proxy (so it gets logged as a new event)
func Replay(e Event, newBody string) error {
	target := "http://localhost:3000" + e.FullURL
	req, err := http.NewRequest(e.Method, target, strings.NewReader(newBody))
	if err != nil {
		return err
	}

	// Copy original headers — skip headers that Go computes automatically
	skip := map[string]bool{
		"content-length":    true,
		"transfer-encoding": true,
		"host":              true,
	}
	for k, v := range e.ReqHeaders {
		if !skip[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}