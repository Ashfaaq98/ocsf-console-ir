package whois

import (
	"strings"
	"testing"
)

func has(domains []string, want string) bool {
	for _, d := range domains {
		if d == want {
			return true
		}
	}
	return false
}

// The bug: the fallback scan read the raw JSON text, so OCSF *field names* were
// treated as domains. Because .name is a real TLD those lookups succeeded, and
// the .name registry's registrar and abuse contact were stored as if they
// described the event.
func TestExtractDomainsIgnoresOCSFFieldNames(t *testing.T) {
	raw := `{
	  "class_uid": 1007,
	  "process": {"name": "powershell.exe", "cmd_line": "-enc SQBFAFgA"},
	  "actor": {"user": {"name": "m.chen"}},
	  "file": {"name": "invoice.pdf", "hashes": [{"value": "abc123"}]},
	  "message": "Suspicious process execution"
	}`

	domains := extractDomains(raw)

	for _, fieldName := range []string{"process.name", "user.name", "file.name", "file.hashes"} {
		if has(domains, fieldName) {
			t.Errorf("field name %q was treated as a domain: %v", fieldName, domains)
		}
	}
	// Nothing in this event is a domain, so nothing should be looked up.
	if len(domains) != 0 {
		t.Errorf("found %v; this event contains no domains", domains)
	}
}

// The keys are the whole problem, so prove a key spelled exactly like a domain
// is still not followed while a value in the same document is.
func TestExtractDomainsReadsValuesNotKeys(t *testing.T) {
	raw := `{"evil.example.com": "this is a key", "message": "beacon to good.example.org"}`

	domains := extractDomains(raw)

	if has(domains, "evil.example.com") {
		t.Errorf("a JSON key was scanned as a domain: %v", domains)
	}
	if !has(domains, "good.example.org") {
		t.Errorf("value domain missed: %v", domains)
	}
}

// Regression guard for what the scan is *for*: domains mentioned in free text.
func TestExtractDomainsStillFindsDomainsInNestedValues(t *testing.T) {
	raw := `{
	  "http_request": {"url": "http://tracker.example.com/beacon"},
	  "dst_endpoint": {"host": "c2.example.net"},
	  "observables": [{"type": "hostname", "value": "deep.example.io"}],
	  "message": "contacted mentioned.example.co.uk repeatedly"
	}`

	domains := extractDomains(raw)

	for _, want := range []string{
		"tracker.example.com",
		"c2.example.net",
		"deep.example.io",
		"mentioned.example.co.uk",
	} {
		if !has(domains, want) {
			t.Errorf("missed %q; got %v", want, domains)
		}
	}
}

// Several file extensions are real TLDs, so a filename caught by the pattern
// would resolve and store an unrelated registry's details.
func TestExtractDomainsIgnoresFilenames(t *testing.T) {
	raw := `{
	  "file": {"name": "payload.zip", "path": "C:\\Users\\m\\report.docx"},
	  "process": {"name": "invoke.ps1", "cmd_line": "python collect.py && bash run.sh"},
	  "message": "wrote notes.md and dump.sqlite"
	}`

	domains := extractDomains(raw)

	for _, filename := range []string{
		"payload.zip", "report.docx", "invoke.ps1",
		"collect.py", "run.sh", "notes.md", "dump.sqlite",
	} {
		if has(domains, filename) {
			t.Errorf("filename %q was treated as a domain: %v", filename, domains)
		}
	}
	if len(domains) != 0 {
		t.Errorf("found %v; this event contains only filenames", domains)
	}
}

// The filename filter must not override a producer that explicitly said "domain".
// A genuine .sh or .zip domain has to survive when the event names it as a host.
func TestExtractDomainsTrustsExplicitHostFields(t *testing.T) {
	for _, field := range []string{"domain", "host", "url"} {
		raw := `{"` + field + `": "example.zip"}`
		if domains := extractDomains(raw); !has(domains, "example.zip") {
			t.Errorf("%s field: a declared host under a filename-like TLD was dropped: %v", field, domains)
		}
	}

	raw := `{"dst_endpoint": {"host": "backup.sh"}}`
	if domains := extractDomains(raw); !has(domains, "backup.sh") {
		t.Errorf("dst_endpoint.host was dropped: %v", domains)
	}
}

// Non-JSON payloads have no keys to be confused by, so the raw scan must remain.
func TestExtractDomainsHandlesNonJSONPayloads(t *testing.T) {
	raw := "Feb 3 12:00:01 host dnsmasq: query[A] beacon.example.com from 10.0.0.5"
	if domains := extractDomains(raw); !has(domains, "beacon.example.com") {
		t.Errorf("plain-text payload domain missed: %v", domains)
	}
}

// IP addresses are not domains and must never reach a WHOIS server.
func TestExtractDomainsIgnoresIPAddresses(t *testing.T) {
	raw := `{"src_endpoint": {"ip": "8.8.8.8"}, "dst_endpoint": {"ip": "192.168.1.100"}}`
	if domains := extractDomains(raw); len(domains) != 0 {
		t.Errorf("found %v; IPs are not domains", domains)
	}
}

// The same event must produce the same lookups every run, or the enrichment keys
// churn between ingests.
func TestExtractDomainsIsDeterministic(t *testing.T) {
	raw := `{
	  "a": {"message": "one.example.com"},
	  "b": {"message": "two.example.com"},
	  "c": {"message": "three.example.com"},
	  "d": {"message": "four.example.com"}
	}`

	first := strings.Join(extractDomains(raw), ",")
	for i := 0; i < 20; i++ {
		if got := strings.Join(extractDomains(raw), ","); got != first {
			t.Fatalf("order changed between runs: %q then %q", first, got)
		}
	}
}

func TestExtractDomainsDeduplicates(t *testing.T) {
	raw := `{"host": "example.com", "message": "example.com and example.com again"}`
	domains := extractDomains(raw)

	seen := 0
	for _, d := range domains {
		if d == "example.com" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("example.com appears %d times, want 1: %v", seen, domains)
	}
}

// Observables are typed, so a username or file name can be skipped outright
// rather than guessed at from its shape.
func TestExtractDomainsHonoursObservableTypes(t *testing.T) {
	raw := `{
	  "observables": [
	    {"name": "actor.user.name",  "type": "User Name",   "type_id": 4, "value": "j.doe"},
	    {"name": "file.name",        "type": "File Name",   "type_id": 7, "value": "invoice.exe"},
	    {"name": "process.name",     "type": "Process Name","type_id": 9, "value": "powershell.exe"},
	    {"name": "dst_endpoint.ip",  "type": "IP Address",  "type_id": 2, "value": "8.8.8.8"},
	    {"name": "dst.hostname",     "type": "Hostname",    "type_id": 1, "value": "c2.example.net"},
	    {"name": "http_request.url", "type": "URL String",  "type_id": 6, "value": "http://drop.example.org/x"}
	  ]
	}`

	domains := extractDomains(raw)

	for _, unwanted := range []string{"j.doe", "invoice.exe", "powershell.exe", "8.8.8.8"} {
		if has(domains, unwanted) {
			t.Errorf("looked up %q despite its observable type saying otherwise: %v", unwanted, domains)
		}
	}
	for _, want := range []string{"c2.example.net", "drop.example.org"} {
		if !has(domains, want) {
			t.Errorf("missed %q; got %v", want, domains)
		}
	}
}

// A producer that sends only the caption still gets the right treatment.
func TestExtractDomainsFallsBackToObservableTypeCaption(t *testing.T) {
	raw := `{"observables": [
	  {"type": "Hostname", "value": "kept.example.com"},
	  {"type": "User Name", "value": "a.smith"}
	]}`

	domains := extractDomains(raw)
	if !has(domains, "kept.example.com") {
		t.Errorf("hostname caption ignored: %v", domains)
	}
	if has(domains, "a.smith") {
		t.Errorf("username looked up: %v", domains)
	}
}

// Internal hostnames are common in security events and can never be registered,
// so each one would otherwise cost a rate-limited lookup and its retries.
func TestExtractDomainsSkipsReservedTLDs(t *testing.T) {
	raw := `{"domain": "corp.local", "dst_endpoint": {"host": "dc01.internal"},
	         "message": "reached printer.lan and mail.example.com"}`

	domains := extractDomains(raw)

	for _, reserved := range []string{"corp.local", "dc01.internal", "printer.lan"} {
		if has(domains, reserved) {
			t.Errorf("queued a lookup for the unregistrable %q: %v", reserved, domains)
		}
	}
	if !has(domains, "mail.example.com") {
		t.Errorf("a real domain was dropped alongside the reserved ones: %v", domains)
	}
}

// The pattern stops at the first non-letter, so "invoke.ps1" matched "invoke.ps"
// — and .ps is Palestine's TLD, so the truncated form resolved.
func TestExtractDomainsRejectsTruncatedMatches(t *testing.T) {
	raw := `{"message": "ran invoke.ps1 then cleanup.sh2 and archive.tar7"}`

	domains := extractDomains(raw)
	for _, fragment := range []string{"invoke.ps", "cleanup.sh", "archive.tar"} {
		if has(domains, fragment) {
			t.Errorf("truncated %q into a lookup: %v", fragment, domains)
		}
	}
	if len(domains) != 0 {
		t.Errorf("found %v; every match here is a truncated filename", domains)
	}
}

func TestLooksLikeFilename(t *testing.T) {
	cases := map[string]bool{
		"powershell.exe":  true,
		"payload.ZIP":     true, // extension matching is case-insensitive
		"script.py":       true,
		"example.com":     false,
		"sub.example.org": false,
		"example.co":      false, // a real TLD that is not a common extension
		"noextension":     false,
		"trailing.":       false,
	}
	for in, want := range cases {
		if got := looksLikeFilename(in); got != want {
			t.Errorf("looksLikeFilename(%q) = %v, want %v", in, got, want)
		}
	}
}
