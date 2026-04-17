package proxy

type Event struct {
	Method     string
	URL        string
	Status     int
	LatencyMs  int64
	ReqBody    string
	ReqHeaders map[string]string
}

var EventChannel = make(chan Event, 100)