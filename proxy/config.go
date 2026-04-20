package proxy

// Config holds the proxy runtime configuration.
type Config struct {
	// ListenAddr is the address the proxy listens on (e.g. ":3000").
	ListenAddr string

	// Target is the upstream server URL (e.g. "http://localhost:4001").
	Target string

	// TLSCertFile and TLSKeyFile enable HTTPS on the proxy listener when both
	// are non-empty.
	TLSCertFile string
	TLSKeyFile  string
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr: ":3000",
		Target:     "http://localhost:4001",
	}
}
