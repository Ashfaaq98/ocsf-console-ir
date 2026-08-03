package ingest

import (
	"errors"
	"strings"
	"testing"
)

// A record with no class_uid is not an OCSF event. Accepting it produced a row
// with no host, no message and no severity that ingest reported as a success —
// the most likely first-run failure there is.
func TestRecordsWithoutClassUIDAreRejected(t *testing.T) {
	p := NewParser()

	for _, tc := range []struct{ name, json string }{
		{"sysmon", `{"EventID":1,"Image":"C:\\Windows\\cmd.exe","Computer":"WS-01"}`},
		{"nonsense", `{"foo":"bar","baz":123}`},
		{"empty object", `{}`},
		{"null class_uid", `{"class_uid":null,"time":1700000000}`},
		{"empty string class_uid", `{"class_uid":"","time":1700000000}`},
		{"zero class_uid", `{"class_uid":0,"time":1700000000}`},
		{"unparseable class_uid", `{"class_uid":"not-a-number"}`},
		{"class_uid on a nested object only", `{"data":{"class_uid":4001}}`},
	} {
		_, err := p.ParseEvent([]byte(tc.json))
		if err == nil {
			t.Errorf("%s: accepted as an OCSF event", tc.name)
			continue
		}
		if !errors.Is(err, ErrNotOCSF) {
			t.Errorf("%s: rejected with %v, which callers cannot tell from a malformed line", tc.name, err)
		}
	}
}

// Rejecting valid OCSF would be far worse than accepting junk, so every shape a
// producer legitimately emits has to survive the gate.
func TestValidOCSFStillParses(t *testing.T) {
	p := NewParser()

	for _, tc := range []struct{ name, json string }{
		{"integer class_uid", `{"class_uid":4001,"time":1700000000,"message":"conn"}`},
		{"string class_uid", `{"class_uid":"4001","time":1700000000}`},
		{"float class_uid", `{"class_uid":4001.0,"time":1700000000}`},
		{"finding class", `{"class_uid":2004,"category_uid":2,"time":1700000000}`},
		{"class_uid only", `{"class_uid":1001}`},
	} {
		event, err := p.ParseEvent([]byte(tc.json))
		if err != nil {
			t.Errorf("%s: valid OCSF was rejected: %v", tc.name, err)
			continue
		}
		if event.ClassUID == 0 {
			t.Errorf("%s: parsed but carries no class_uid", tc.name)
		}
	}
}

// Malformed JSON is a different failure from valid JSON that is not OCSF, and
// the remedy differs — so they must not be reported as the same thing.
func TestMalformedJSONIsNotReportedAsNotOCSF(t *testing.T) {
	_, err := NewParser().ParseEvent([]byte(`{"class_uid": 4001`))
	if err == nil {
		t.Fatal("truncated JSON was accepted")
	}
	if errors.Is(err, ErrNotOCSF) {
		t.Error("a truncated line was reported as 'not OCSF', which sends the user to convert a file that is actually corrupt")
	}
}

// The error names the field and quotes the record, so the summary can tell the
// user which of their files it was without making them read the log.
func TestNotOCSFErrorCarriesTheCause(t *testing.T) {
	_, err := NewParser().ParseEvent([]byte(`{"EventID":1,"Computer":"WS-01"}`))

	var notOCSF *NotOCSFError
	if !errors.As(err, &notOCSF) {
		t.Fatalf("error is %T, want a *NotOCSFError callers can inspect", err)
	}
	if notOCSF.Missing != "class_uid" {
		t.Errorf("Missing = %q, want class_uid", notOCSF.Missing)
	}
	if !strings.Contains(notOCSF.Sample, "EventID") {
		t.Errorf("Sample = %q, which does not identify the record", notOCSF.Sample)
	}
	if !strings.Contains(err.Error(), "class_uid") {
		t.Errorf("the message does not name the missing field: %q", err.Error())
	}
}

// A long record is quoted at a length that fits a terminal.
func TestSampleIsBounded(t *testing.T) {
	long := `{"EventID":1,"CommandLine":"` + strings.Repeat("a", 500) + `"}`
	_, err := NewParser().ParseEvent([]byte(long))

	var notOCSF *NotOCSFError
	if !errors.As(err, &notOCSF) {
		t.Fatal("not rejected")
	}
	if len([]rune(notOCSF.Sample)) > sampleLen+1 {
		t.Errorf("sample is %d runes, over the %d bound", len([]rune(notOCSF.Sample)), sampleLen)
	}
}

// Parse routes through the same gate, so the finding path rejects too.
func TestFindingPathRejectsNonOCSF(t *testing.T) {
	_, err := NewParser().Parse([]byte(`{"EventID":1,"is_alert":true}`))
	if !errors.Is(err, ErrNotOCSF) {
		t.Errorf("the finding route accepted a non-OCSF record: %v", err)
	}
}
