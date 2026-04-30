package proxy

import "sync/atomic"

// InterceptDecision is sent from UI back to the blocked proxy goroutine.
type InterceptDecision struct {
	Action  string // "forward" or "drop"
	NewBody string
}

// InterceptRequest is sent from the proxy to the UI when a request is intercepted.
type InterceptRequest struct {
	Event    Event
	Decision chan InterceptDecision
}

var (
	interceptEnabled int32 // atomic: 0=off, 1=on
	// InterceptChan receives paused requests waiting for UI decision.
	InterceptChan = make(chan InterceptRequest, 1)
)

// SetInterceptMode enables or disables intercept mode.
func SetInterceptMode(on bool) {
	if on {
		atomic.StoreInt32(&interceptEnabled, 1)
	} else {
		atomic.StoreInt32(&interceptEnabled, 0)
	}
}

// IsInterceptEnabled returns true if intercept mode is active.
func IsInterceptEnabled() bool {
	return atomic.LoadInt32(&interceptEnabled) == 1
}
