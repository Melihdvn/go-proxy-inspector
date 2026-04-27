package proxy

import "time"

type Event struct {
	Timestamp   time.Time         // when the request was made
	Method      string
	Host        string            // request host (e.g. api.github.com)
	URL         string            // path only
	FullURL     string            // scheme + host + path + query
	Status      int
	LatencyMs   int64
	ReqBody     string
	ReqHeaders  map[string]string
	RespBody    string
	RespHeaders map[string]string
	Blocked     bool              // true if dropped by blocklist
}

var EventChannel = make(chan Event, 100)