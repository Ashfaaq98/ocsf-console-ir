package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Helpers for tests ---

func testLogger() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func sampleEventJSON() string {
	return `{
		"src_endpoint": {"ip": "1.2.3.4", "hostname": "evil.example.com"},
		"dst_endpoint": {"ip": "10.0.0.5"},
		"file": {"hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}},
		"http_request": {"url": "https://malicious.example.org/dropper"},
		"user": {"email_addr": "victim@example.com"}
	}`
}

// --- Unit tests ---

func TestObservableExtraction(t *testing.T) {
	p := &IntelOwlPlugin{}
	obs := p.extractObservables(sampleEventJSON())

	// Count by type
	counts := map[string]int{}
	for _, o := range obs {
		counts[o.Type]++
	}

	if counts["ip"] != 2 {
		t.Fatalf("expected 2 ip observables, got %d", counts["ip"])
	}
	if counts["domain"] != 2 { // evil.example.com + malicious.example.org
		t.Fatalf("expected 2 domain observables, got %d", counts["domain"])
	}
	if counts["hash"] != 2 {
		t.Fatalf("expected 2 hash observables, got %d", counts["hash"])
	}
	if counts["url"] != 1 {
		t.Fatalf("expected 1 url observable, got %d", counts["url"])
	}
	if counts["email"] != 1 {
		t.Fatalf("expected 1 email observable, got %d", counts["email"])
	}
}

func TestConvertToEnrichmentFields(t *testing.T) {
	p := &IntelOwlPlugin{}
	obs := Observable{Type: "ip", Value: "1.2.3.4"}
	intel := &IntelOwlResult{
		Observable:    obs,
		Verdict:       "benign",
		Confidence:    "low",
		Tags:          []string{"mock", "intelowl"},
		Analyzers:     []string{"example_analyzer"},
		Jobs:          []string{"job-1"},
		EvidenceCount: 1,
		Summary:       "Test summary",
		PerAnalyzer: map[string]any{
			"example_analyzer": map[string]any{"score": 10},
		},
	}

	fields := p.convertToEnrichmentFields(obs, intel)

	expectKeys := []string{
		"intelowl_ip_1_2_3_4_artifact",
		"intelowl_ip_1_2_3_4_verdict",
		"intelowl_ip_1_2_3_4_confidence",
		"intelowl_ip_1_2_3_4_tags",
		"intelowl_ip_1_2_3_4_analyzers",
		"intelowl_ip_1_2_3_4_jobs",
		"intelowl_ip_1_2_3_4_evidence_count",
		"intelowl_ip_1_2_3_4_summary",
		"intelowl_ip_1_2_3_4_per_analyzer_json",
	}
	for _, k := range expectKeys {
		if _, ok := fields[k]; !ok {
			t.Fatalf("expected field %s", k)
		}
	}
	if fields["intelowl_ip_1_2_3_4_verdict"] != "benign" {
		t.Fatalf("unexpected verdict: %s", fields["intelowl_ip_1_2_3_4_verdict"])
	}
	if fields["intelowl_ip_1_2_3_4_confidence"] != "low" {
		t.Fatalf("unexpected confidence: %s", fields["intelowl_ip_1_2_3_4_confidence"])
	}
}

func TestMockClient_QueryAndSubmit(t *testing.T) {
	mock := NewMockIntelOwlClient(testLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	obs := Observable{Type: "url", Value: "https://example.com/malware"}
	analyzers := []string{"example"}

	// QueryObservable path
	r1, err := mock.QueryObservable(ctx, obs, analyzers)
	if err != nil || r1 == nil {
		t.Fatalf("mock QueryObservable failed: %v", err)
	}

	// SubmitAndPoll path
	r2, err := mock.SubmitAndPoll(ctx, obs, analyzers, 50*time.Millisecond, 1*time.Second)
	if err != nil || r2 == nil {
		t.Fatalf("mock SubmitAndPoll failed: %v", err)
	}
}

func TestRealClient_HealthPlaceholder(t *testing.T) {
	// Minimal mock server with /api/health returning 200 OK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	client := NewRealIntelOwlClient(realClientOpts{
		BaseURL:   srv.URL,
		Token:     "test-token",
		VerifyTLS: true,
		Timeout:   2 * time.Second,
		RPS:       5,
		Burst:     10,
		Logger:    testLogger(),
	})
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Query should hit /api/health then return placeholder error (no existing results).
	_, err := client.QueryObservable(ctx, Observable{Type: "ip", Value: "1.2.3.4"}, []string{"a"})
	if err == nil {
		t.Fatalf("expected placeholder error for no existing results")
	}
}