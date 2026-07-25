package whois

import (
	"strings"
	"testing"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/plugins"
)

// Compile-time assertion that the plugin satisfies the CorePlugin contract.
var _ plugins.CorePlugin = (*Plugin)(nil)

func TestExtractDomains(t *testing.T) {
	raw := `{"url":"http://example.com/path","host":"sub.example.com","description":"visit example.com for info"}`
	domains := extractDomains(raw)
	if len(domains) == 0 {
		t.Fatalf("expected at least one domain, got none")
	}
	found := false
	for _, d := range domains {
		if d == "example.com" || d == "sub.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected example.com or sub.example.com in domains, got: %v", domains)
	}
}

// TestNormalizeWhois exercises the regex-based parser against a representative
// raw WHOIS response, covering registrar, dates, nameservers and emails.
func TestNormalizeWhois(t *testing.T) {
	raw := `Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2030-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Registrant Email: abuse@example-registrar.com`

	data := normalizeWhois("example.com", raw)
	prefix := "whois_example_com_"

	cases := map[string]string{
		prefix + "registrar":       "Example Registrar, Inc.",
		prefix + "created_date":    "1995-08-14T04:00:00Z",
		prefix + "expiration_date": "2030-08-13T04:00:00Z",
	}
	for key, want := range cases {
		if got := data[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}

	if ns := data[prefix+"nameservers"]; !strings.Contains(ns, "A.IANA-SERVERS.NET") || !strings.Contains(ns, "B.IANA-SERVERS.NET") {
		t.Errorf("nameservers = %q, want both IANA servers", ns)
	}
	if emails := data[prefix+"emails"]; !strings.Contains(emails, "abuse@example-registrar.com") {
		t.Errorf("emails = %q, want registrant email", emails)
	}
	if _, ok := data[prefix+"raw_snippet"]; !ok {
		t.Errorf("expected raw_snippet to be populated")
	}
}
