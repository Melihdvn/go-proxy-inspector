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
	// Seed blocklist from config
	for _, d := range cfg.BlockedDomains {
		AddToBlocklist(d)
	}

	p := goproxy.NewProxyHttpServer()
	p.Verbose = false

	// Set up MITM certificates if provided
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("proxy: failed to load CA cert/key: %v", err)
		}
		goproxy.GoproxyCa = cert
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		p.OnRequest().HandleConnect(goproxy.AlwaysMitm)
		log.Printf("proxy: MITM enabled with CA %s", cfg.TLSCertFile)
	}

	type requestData struct {
		start     time.Time
		bodyBytes []byte
	}

	// Intercept requests
	p.OnRequest().DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			var bodyBytes []byte
			if req.Body != nil {
				bodyBytes, _ = io.ReadAll(req.Body)
				req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			}

			// Force server to send uncompressed plain text data
			req.Header.Del("Accept-Encoding")

			// ── Blocklist check ───────────────────────────────────────
			if IsBlocked(req.Host) {
				blocked := Event{
					Timestamp:  time.Now(),
					Method:     req.Method,
					Host:       req.Host,
					URL:        req.URL.Path,
					FullURL:    buildFullURL(req),
					Status:     0,
					LatencyMs:  0,
					ReqBody:    string(bodyBytes),
					ReqHeaders: collectHeaders(req.Header),
					Blocked:    true,
				}
				EventChannel <- blocked
				return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
					http.StatusForbidden, "Blocked by go-proxy-inspector")
			}

			// ── Intercept mode ────────────────────────────────────────
			if IsInterceptEnabled() {
				reqHeaders := collectHeaders(req.Header)
				decChan := make(chan InterceptDecision, 1)
				ir := InterceptRequest{
					Event: Event{
						Timestamp:  time.Now(),
						Method:     req.Method,
						Host:       req.Host,
						URL:        req.URL.Path,
						FullURL:    buildFullURL(req),
						ReqBody:    string(bodyBytes),
						ReqHeaders: reqHeaders,
					},
					Decision: decChan,
				}
				// Non-blocking send; if UI isn't ready, skip intercept
				select {
				case InterceptChan <- ir:
					dec := <-decChan
					if dec.Action == "drop" {
						return req, goproxy.NewResponse(req, goproxy.ContentTypeText,
							http.StatusBadGateway, "Dropped by intercept")
					}
					if dec.NewBody != "" {
						bodyBytes = []byte(dec.NewBody)
						req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
						req.ContentLength = int64(len(bodyBytes))
					}
				default:
					// channel full, let request pass through
				}
			}

			ctx.UserData = requestData{start: time.Now(), bodyBytes: bodyBytes}
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

			var respBodyBytes []byte
			if resp.Body != nil {
				respBodyBytes, _ = io.ReadAll(resp.Body)
				resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes))
			}

			EventChannel <- Event{
				Timestamp:   start,
				Method:      req.Method,
				Host:        req.Host,
				URL:         req.URL.Path,
				FullURL:     buildFullURL(req),
				Status:      resp.StatusCode,
				LatencyMs:   time.Since(start).Milliseconds(),
				ReqBody:     string(reqBodyBytes),
				ReqHeaders:  collectHeaders(req.Header),
				RespBody:    string(respBodyBytes),
				RespHeaders: collectHeaders(resp.Header),
			}

			return resp
		})

	log.Printf("proxy: listening on %s", cfg.ListenAddr)
	if err := http.ListenAndServe(cfg.ListenAddr, p); err != nil {
		log.Fatalf("proxy: %v", err)
	}
}

// buildFullURL constructs the full URL from a request.
func buildFullURL(req *http.Request) string {
	scheme := "http"
	if req.URL.Scheme != "" {
		scheme = req.URL.Scheme
	} else if req.TLS != nil || req.URL.Port() == "443" {
		scheme = "https"
	}
	return scheme + "://" + req.Host + req.URL.RequestURI()
}

// collectHeaders copies headers into a flat map (first value only).
func collectHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// Replay sends a modified request back out (fire-and-forget).
func Replay(e Event, newBody string) error {
	req, err := http.NewRequest(e.Method, e.FullURL, strings.NewReader(newBody))
	if err != nil {
		return err
	}
	skip := map[string]bool{"content-length": true, "transfer-encoding": true}
	for k, v := range e.ReqHeaders {
		if !skip[strings.ToLower(k)] {
			req.Header.Set(k, v)
		}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}