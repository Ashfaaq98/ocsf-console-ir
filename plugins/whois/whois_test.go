package main

import (
	"testing"

	whoisparser "github.com/likexian/whois-parser"
)

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

func TestNormalizeWhois(t *testing.T) {
	info := &whoisparser.WhoisInfo{
		Registrar: whoisparser.Registrar{
			Name:      "Example Registrar",
			Registrar: "ExampleRegistrarInc",
		},
		Domain: whoisparser.Domain{
			Domain:         "example.com",
			CreatedDate:    "2000-01-01",
			UpdatedDate:    "2020-01-01",
			ExpirationDate: "2030-01-01",
			NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		},
		Registrant: whoisparser.Registrant{
			Name:         "Alice",
			Email:        "alice@example.com",
			Organization: "Example Org",
		},
		Contacts: map[string]whoisparser.Contact{
			"admin": {
				Email: "admin@example.com",
			},
			"tech": {
				Email: "tech@example.com",
			},
		},
		Raw: "Raw WHOIS data here",
	}

	out := normalizeWhois("example.com", info)
	if out["whois_example_com_registrar"] == "" {
		t.Fatalf("expected registrar field, got none: %v", out)
	}
	if out["whois_example_com_created_date"] != "2000-01-01" {
		t.Fatalf("created_date mismatch: %s", out["whois_example_com_created_date"])
	}
	if out["whois_example_com_nameservers"] == "" {
		t.Fatalf("expected nameservers field, got none")
	}
	if out["whois_example_com_registrant_email"] != "alice@example.com" {
		t.Fatalf("registrant_email mismatch: %s", out["whois_example_com_registrant_email"])
	}
	if out["whois_example_com_emails"] == "" {
		t.Fatalf("expected aggregated emails, got none")
	}
	if out["whois_example_com_raw_snippet"] == "" {
		t.Fatalf("expected raw_snippet, got none")
	}
}