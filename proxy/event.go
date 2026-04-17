package proxy

type Event struct {
	Method      string
	URL         string            // path only
	FullURL     string            // path + query string
	Status      int
	LatencyMs   int64
	ReqBody     string
	ReqHeaders  map[string]string
	RespBody    string
	RespHeaders map[string]string
}

var EventChannel = make(chan Event, 100)