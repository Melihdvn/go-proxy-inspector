package proxy

type Event struct {
	Method    string
	URL       string
	Status    int
	LatencyMs int64
}

var EventChannel = make(chan Event, 100)