package proxy

import (
	"strings"
	"sync"
)

// Blocklist holds a thread-safe list of blocked host patterns.
type Blocklist struct {
	mu      sync.RWMutex
	domains []string
}

var globalBlocklist = &Blocklist{}

// Add adds a domain to the blocklist (no-op if already present).
func (b *Blocklist) Add(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, d := range b.domains {
		if d == domain {
			return
		}
	}
	b.domains = append(b.domains, domain)
}

// Remove removes a domain from the blocklist.
func (b *Blocklist) Remove(domain string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	filtered := b.domains[:0]
	for _, d := range b.domains {
		if d != domain {
			filtered = append(filtered, d)
		}
	}
	b.domains = filtered
}

// List returns a copy of all blocked domains.
func (b *Blocklist) List() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]string, len(b.domains))
	copy(out, b.domains)
	return out
}

// ShouldBlock returns true if the host matches any blocked domain.
func (b *Blocklist) ShouldBlock(host string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	h := host
	if idx := strings.LastIndex(h, ":"); idx >= 0 {
		h = h[:idx]
	}
	for _, d := range b.domains {
		if d == h || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

func GetBlocklist() *Blocklist          { return globalBlocklist }
func AddToBlocklist(domain string)      { globalBlocklist.Add(domain) }
func RemoveFromBlocklist(domain string) { globalBlocklist.Remove(domain) }
func IsBlocked(host string) bool        { return globalBlocklist.ShouldBlock(host) }
