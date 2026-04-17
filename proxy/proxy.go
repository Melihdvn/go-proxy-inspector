package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

func Start(target string) {
	remote, _ := url.Parse(target)

	proxy := httputil.NewSingleHostReverseProxy(remote)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		proxy.ModifyResponse = func(resp *http.Response) error {

			EventChannel <- Event{
				Method:    r.Method,
				URL:       r.URL.Path,
				Status:    resp.StatusCode,
				LatencyMs: time.Since(start).Milliseconds(),
			}

			return nil
		}

		r.Host = remote.Host
		proxy.ServeHTTP(w, r)
	})

	go http.ListenAndServe(":3000", nil)
}