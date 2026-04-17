package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

type loggingTransport struct {
	wrapped http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()

	var bodyBytes []byte
	if req.Body != nil {
		bodyBytes, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

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

	EventChannel <- Event{
		Method:     req.Method,
		URL:        req.URL.Path,
		Status:     resp.StatusCode,
		LatencyMs:  time.Since(start).Milliseconds(),
		ReqBody:    string(bodyBytes),
		ReqHeaders: headers,
	}

	return resp, nil
}

func Start(target string) {
	remote, _ := url.Parse(target)

	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = &loggingTransport{wrapped: http.DefaultTransport}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		r.Host = remote.Host
		proxy.ServeHTTP(w, r)
	})

	http.ListenAndServe(":3000", nil)
}