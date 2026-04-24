package proxy

// Config holds the proxy runtime configuration.
type Config struct {
	// ListenAddr is the address the proxy listens on (e.g. ":3000").
	ListenAddr string

	// TLSCertFile and TLSKeyFile enable HTTPS MITM interception when both
	// are non-empty. These should be the CA certificate and key.
	TLSCertFile string
	TLSKeyFile  string
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		ListenAddr: ":3000",
	}
}
