package correlation

import (
	"testing"
	"time"
)

func TestStoreDNSReplyAndTCPConnectCorrelation(t *testing.T) {
	store := NewStore()
	ts := int64(1)

	store.UpsertProcess(1234, 1, "node", "node app.js", ts)
	store.AddDNSReply(1234, "node", "api.example.com", "A", []string{"1.2.3.4"}, 60, ts)

	sig := store.AddTCPConnect(1234, "node", "10.0.0.2", 53000, "1.2.3.4", 443, true, ts)
	if sig == nil {
		t.Fatal("expected signal")
	}

	if sig.Domain != "api.example.com" {
		t.Fatalf("expected domain api.example.com, got %q", sig.Domain)
	}

	if sig.IP != "1.2.3.4" {
		t.Fatalf("expected IP 1.2.3.4, got %q", sig.IP)
	}

	if sig.Port != 443 {
		t.Fatalf("expected port 443, got %d", sig.Port)
	}
}

func TestStoreDNSQueryCreatesProcessContext(t *testing.T) {
	store := NewStore()
	ts := int64(1)

	sig := store.AddDNSQuery(5678, "curl", "example.org", "A", ts)
	if sig == nil {
		t.Fatal("expected signal")
	}

	if sig.Domain != "example.org" {
		t.Fatalf("expected domain example.org, got %q", sig.Domain)
	}

	if sig.QueryType != "A" {
		t.Fatalf("expected query type A, got %q", sig.QueryType)
	}
}

func TestGlobalDNSFallbackUsesTTL(t *testing.T) {
	store := NewStore()
	ts := int64(1_000_000_000)

	store.AddDNSReply(100, "resolver", "example.com", "A", []string{"1.1.1.1"}, 30, ts)

	sig := store.AddTCPConnect(200, "curl", "10.0.0.2", 50000, "1.1.1.1", 80, true, ts+int64(5*time.Second))
	if sig == nil {
		t.Fatal("expected signal")
	}
	if sig.Domain != "example.com" {
		t.Fatalf("expected domain example.com, got %q", sig.Domain)
	}
}

func TestGlobalDNSExpiry(t *testing.T) {
	store := NewStore()
	ts := int64(1_000_000_000)

	store.AddDNSReply(100, "resolver", "expired.com", "A", []string{"9.9.9.9"}, 1, ts)

	sig := store.AddTCPConnect(200, "curl", "10.0.0.2", 50000, "9.9.9.9", 80, true, ts+int64(2*time.Second))
	if sig == nil {
		t.Fatal("expected signal")
	}
	if sig.Domain != "" {
		t.Fatalf("expected empty domain, got %q", sig.Domain)
	}
}
