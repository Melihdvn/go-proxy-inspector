package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
)

// Start starts the proxy using a Config struct.
func Start(cfg Config) {
	p := goproxy.NewProxyHttpServer()
	p.Verbose = false // We'll do our own logging

	// Set up MITM certificates if provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("proxy: failed to load CA cert/key: %v", err)
		}
		
		// Configure goproxy's MITM CA
		goproxy.GoproxyCa = cert
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&cert)}

		// Tell goproxy to always MITM HTTPS connections
		p.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		log.Printf("proxy: MITM enabled with CA %s", cfg.TLSCertFile)
	}

	// We use this struct to pass data between OnRequest and OnResponse
	type requestData struct {
		start     time.Time
		bodyBytes []byte
	}

	// Intercept requests
	p.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			// Read request body to log it, then restore it
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// Store req body and start time in UserData
			ctx.UserData = requestData{
				start:     time.Now(),
				bodyBytes: bodyBytes,
			}

			return req, nil
		})

	// Intercept responses
	p.OnResponse().DoFunc(
		func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil || ctx.Req == nil {
				return resp
			}

			req := ctx.Req
			var start time.Time
			var reqBodyBytes []byte

			if rd, ok := ctx.UserData.(requestData); ok {
				start = rd.start
				reqBodyBytes = rd.bodyBytes
			} else {
				start = time.Now()
			}

			// Read response body to log it, then restore it
			var respBodyBytes []byte
			if resp.Body != nil {
				respBodyBytes, _ = io.ReadAll(resp.Body)
				resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
			}

			// Collect request headers
			reqHeaders := map[string]string{}
			for k, v := range req.Header {
				if len(v) > 0 {
					reqHeaders[k] = v[0]
				}
			}

			// Collect response headers
			respHeaders := map[string]string{}
			for k, v := range resp.Header {
				if len(v) > 0 {
					respHeaders[k] = v[0]
				}
			}

			scheme := "http"
			if req.URL.Scheme != "" {
				scheme = req.URL.Scheme
			} else if req.TLS != nil || req.URL.Port() == "443" {
				scheme = "https"
			}
			fullURL := scheme + "://" + req.Host + req.URL.RequestURI()

			EventChannel <- Event{
				Method:      req.Method,
				URL:         req.URL.Path,
				FullURL:     fullURL,
				Status:      resp.StatusCode,
				LatencyMs:   time.Since(start).Milliseconds(),
				ReqBody:     string(reqBodyBytes),
				ReqHeaders:  reqHeaders,
				RespBody:    string(respBodyBytes),
				RespHeaders: respHeaders,
			}

			return resp
		})

	log.Printf("proxy: listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

// Replay sends a modified request back out
func Replay(e Event, newBody string) error {
	req, err := http.NewRequest(e.Method, e.FullURL, strings.NewReader(newBody))
	if err != nil {
		return err
	}

	// Copy original headers — skip headers that Go computes automatically
	skip := map[string]bool{
		"content-length":    true,
		"transfer-encoding": true,
	}
	for k, v := range e.ReqHeaders {
		if !skip[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}

	// We use default client for replays
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Allow self-signed for replay
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}