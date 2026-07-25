package geoip

import (
	"context"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/bus"
	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
)

// Compile-time assertion that the plugin satisfies the CorePlugin contract.
var _ plugins.CorePlugin = (*Plugin)(nil)

func TestExtractIPAddresses(t *testing.T) {
	raw := `{"src_endpoint":{"ip":"8.8.8.8"},"dst_endpoint":{"ip":"1.1.1.1"},"device":{"ip":"8.8.8.8"}}`
	ips := extractIPAddresses(raw)

	if len(ips) != 2 {
		t.Fatalf("expected 2 deduplicated IPs, got %d: %v", len(ips), ips)
	}
	want := map[string]bool{"8.8.8.8": true, "1.1.1.1": true}
	for _, ip := range ips {
		if !want[ip] {
			t.Errorf("unexpected IP %q", ip)
		}
	}
}

func TestExtractIPAddressesIgnoresInvalid(t *testing.T) {
	raw := `{"src_endpoint":{"ip":"not-an-ip"},"dst_endpoint":{"ip":"1.1.1.1"}}`
	ips := extractIPAddresses(raw)
	if len(ips) != 1 || ips[0] != "1.1.1.1" {
		t.Fatalf("expected only 1.1.1.1, got %v", ips)
	}
}

func TestIsPrivateIP(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":     true,
		"172.16.5.4":   true,
		"192.168.1.1":  true,
		"127.0.0.1":    true,
		"169.254.0.1":  true,
		"8.8.8.8":      false,
		"1.1.1.1":      false,
		"203.0.113.10": false,
	}
	for ip, want := range cases {
		if got := isPrivateIP(ip); got != want {
			t.Errorf("isPrivateIP(%q) = %v, want %v", ip, got, want)
		}
	}
}

// TestProcessPrivateIP exercises Process end-to-end for a private IP, which is
// resolved locally without any network call.
func TestProcessPrivateIP(t *testing.T) {
	p := New(nil)
	defer p.Stop()

	enrichments, err := p.Process(context.Background(), bus.EventMessage{
		EventID: "evt1",
		RawJSON: `{"src_endpoint":{"ip":"10.1.2.3"}}`,
	})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(enrichments) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(enrichments))
	}
	e := enrichments[0]
	if e.Source != "geoip" {
		t.Errorf("source = %q, want geoip", e.Source)
	}
	if got := e.Data["geoip_10_1_2_3_country"]; got != "Private Network" {
		t.Errorf("country = %q, want Private Network", got)
	}
}
