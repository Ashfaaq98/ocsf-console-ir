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

// MockOpenCTIServer creates a mock OpenCTI server for testing
func NewMockOpenCTIServer() *httptest.Server {
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/api/settings/about", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"version": "5.12.0",
			"status":  "ok",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// Token validation endpoint
	mux.HandleFunc("/api/me", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		response := map[string]interface{}{
			"id":   "user-123",
			"name": "Test User",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// GraphQL endpoint for cyber observables
	mux.HandleFunc("/api/graphql", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		// Mock response for cyber observable search
		response := map[string]interface{}{
			"data": map[string]interface{}{
				"stixCyberObservables": map[string]interface{}{
					"edges": []map[string]interface{}{
						{
							"node": map[string]interface{}{
								"id":               "observable-123",
								"standard_id":      "ipv4-addr--123",
								"entity_type":      "IPv4-Addr",
								"observable_value": "192.168.1.100",
								"x_opencti_score":  75,
								"confidence":       80,
								"created_at":       time.Now().Format(time.RFC3339),
								"updated_at":       time.Now().Format(time.RFC3339),
								"labels": map[string]interface{}{
									"edges": []map[string]interface{}{
										{
											"node": map[string]interface{}{
												"value": "malicious-activity",
											},
										},
									},
								},
								"indicators": map[string]interface{}{
									"edges": []map[string]interface{}{
										{
											"node": map[string]interface{}{
												"id":         "indicator-123",
												"name":       "Malicious IP",
												"pattern":    "[ipv4-addr:value = '192.168.1.100']",
												"confidence": 75,
												"valid_from": time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
												"valid_until": time.Now().AddDate(0, 1, 0).Format(time.RFC3339),
												"labels": map[string]interface{}{
													"edges": []map[string]interface{}{
														{
															"node": map[string]interface{}{
																"value": "malicious-activity",
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// REST API endpoint for indicators
	mux.HandleFunc("/api/indicators", func(w http.ResponseWriter, r *http.Request) {
		response := []map[string]interface{}{
			{
				"id":         "indicator-456",
				"name":       "Test Indicator",
				"pattern":    "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']",
				"confidence": 85,
				"valid_from": time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
				"valid_until": time.Now().AddDate(0, 1, 0).Format(time.RFC3339),
				"labels":     []string{"malicious-activity"},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	return httptest.NewServer(mux)
}

func TestOpenCTIClient_NewClient(t *testing.T) {
	config := OpenCTIConfig{
		BaseURL:      "https://example.com",
		Token:        "test-token",
		Timeout:      10 * time.Second,
		RateLimitRPS: 5,
		BurstLimit:   10,
	}
	
	client, err := NewOpenCTIClient(config, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	if client.baseURL != "https://example.com" {
		t.Errorf("Expected baseURL 'https://example.com', got '%s'", client.baseURL)
	}
	
	if client.token != "test-token" {
		t.Errorf("Expected token 'test-token', got '%s'", client.token)
	}
}

func TestOpenCTIClient_HealthCheck(t *testing.T) {
	server := NewMockOpenCTIServer()
	defer server.Close()
	
	config := OpenCTIConfig{
		BaseURL:      server.URL,
		Token:        "test-token",
		Timeout:      5 * time.Second,
		RateLimitRPS: 10,
	}
	
	client, err := NewOpenCTIClient(config, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := client.HealthCheck(ctx); err != nil {
		t.Errorf("Health check failed: %v", err)
	}
}

func TestOpenCTIClient_ValidateToken(t *testing.T) {
	server := NewMockOpenCTIServer()
	defer server.Close()
	
	tests := []struct {
		name        string
		token       string
		expectError bool
	}{
		{
			name:        "Valid token",
			token:       "test-token",
			expectError: false,
		},
		{
			name:        "Invalid token",
			token:       "invalid-token",
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := OpenCTIConfig{
				BaseURL:      server.URL,
				Token:        tt.token,
				Timeout:      5 * time.Second,
				RateLimitRPS: 10,
			}
			
			client, err := NewOpenCTIClient(config, log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer client.Close()
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			err = client.ValidateToken(ctx)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}


func TestOpenCTIClient_SearchObservables(t *testing.T) {
	server := NewMockOpenCTIServer()
	defer server.Close()
	
	config := OpenCTIConfig{
		BaseURL:      server.URL,
		Token:        "test-token",
		Timeout:      5 * time.Second,
		RateLimitRPS: 10,
	}
	
	client, err := NewOpenCTIClient(config, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	observables, err := client.SearchObservables(ctx, "ip", "192.168.1.100")
	if err != nil {
		t.Errorf("SearchObservables failed: %v", err)
	}
	
	if len(observables) != 1 {
		t.Errorf("Expected 1 observable, got %d", len(observables))
	}
	
	if len(observables) > 0 {
		obs := observables[0]
		if obs.ObservableValue != "192.168.1.100" {
			t.Errorf("Expected observable value '192.168.1.100', got '%s'", obs.ObservableValue)
		}
		if obs.Confidence != 80 {
			t.Errorf("Expected confidence 80, got %d", obs.Confidence)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(2, 3) // 2 RPS with burst of 3
	defer rl.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	// Should be able to get 3 tokens immediately (burst)
	for i := 0; i < 3; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Errorf("Failed to get token %d: %v", i+1, err)
		}
	}
	
	// 4th token should be rate limited
	start := time.Now()
	if err := rl.Wait(ctx); err == nil {
		duration := time.Since(start)
		if duration < 400*time.Millisecond { // Should wait ~500ms for 2 RPS
			t.Errorf("Rate limiter didn't wait long enough: %v", duration)
		}
	}
}

func TestObservableExtraction(t *testing.T) {
	plugin := &OpenCTIPlugin{
		config: OpenCTIConfig{
			ProcessIPs:     true,
			ProcessDomains: true,
			ProcessHashes:  true,
			ProcessURLs:    true,
		},
	}
	
	eventJSON := `{
		"src_endpoint": {
			"ip": "192.168.1.100",
			"hostname": "malicious.example.com"
		},
		"dst_endpoint": {
			"ip": "10.0.0.1"
		},
		"file": {
			"hashes": {
				"md5": "d41d8cd98f00b204e9800998ecf8427e",
				"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
			}
		},
		"url": "https://evil.example.com/malware.exe"
	}`
	
	observables := plugin.extractObservables(eventJSON)
	
	expectedTypes := map[string]int{
		"ip":     0, // Private IPs are filtered out
		"domain": 2, // malicious.example.com, evil.example.com
		"hash":   2, // MD5 and SHA256
		"url":    1, // https://evil.example.com/malware.exe
	}
	
	typeCounts := make(map[string]int)
	for _, obs := range observables {
		typeCounts[obs.Type]++
	}
	
	for expectedType, expectedCount := range expectedTypes {
		if typeCounts[expectedType] != expectedCount {
			t.Errorf("Expected %d %s observables, got %d", expectedCount, expectedType, typeCounts[expectedType])
		}
	}
}

func TestGenerateMockThreatIntelligence(t *testing.T) {
	plugin := &OpenCTIPlugin{
		logger: log.New(io.Discard, "", 0),
	}
	
	obs := Observable{
		Type:  "ip",
		Value: "1.2.3.4",
	}
	
	intel := plugin.generateMockThreatIntelligence(obs)
	
	if intel.Observable.Type != obs.Type {
		t.Errorf("Expected observable type %s, got %s", obs.Type, intel.Observable.Type)
	}
	
	if intel.Observable.Value != obs.Value {
		t.Errorf("Expected observable value %s, got %s", obs.Value, intel.Observable.Value)
	}
	
	if intel.Confidence == 0 {
		t.Error("Expected non-zero confidence")
	}
	
	if intel.ThreatLevel == "" {
		t.Error("Expected non-empty threat level")
	}
	
	if len(intel.ThreatActors) == 0 {
		t.Error("Expected at least one threat actor in mock data")
	}
	
	if len(intel.Indicators) == 0 {
		t.Error("Expected at least one indicator in mock data")
	}
}

func TestConvertToEnrichmentFields(t *testing.T) {
	plugin := &OpenCTIPlugin{}
	
	obs := Observable{
		Type:  "ip",
		Value: "1.2.3.4",
	}
	
	intel := &ThreatIntelligence{
		Observable:  obs,
		Confidence:  85,
		ThreatLevel: "HIGH",
		ThreatActors: []STIXThreatActor{
			{
				Name:    "APT28",
				Aliases: []string{"Fancy Bear", "Sofacy"},
				Country: "RU",
			},
		},
		Indicators: []STIXIndicator{
			{
				Name:   "Malicious IP",
				Labels: []string{"malicious-activity"},
			},
		},
		AttackPatterns: []STIXAttackPattern{
			{
				Name:    "Spearphishing Link",
				MitreID: "T1566.002",
			},
		},
		QueryTime: time.Now(),
	}
	
	fields := plugin.convertToEnrichmentFields(obs, intel)
	
	expectedFields := []string{
		"opencti_ip_1_2_3_4_confidence",
		"opencti_ip_1_2_3_4_threat_level",
		"opencti_ip_1_2_3_4_threat_actors",
		"opencti_ip_1_2_3_4_indicators",
		"opencti_ip_1_2_3_4_mitre_techniques",
	}
	
	for _, expectedField := range expectedFields {
		if _, exists := fields[expectedField]; !exists {
			t.Errorf("Expected field %s not found in enrichment", expectedField)
		}
	}
	
	if fields["opencti_ip_1_2_3_4_confidence"] != "85" {
		t.Errorf("Expected confidence 85, got %s", fields["opencti_ip_1_2_3_4_confidence"])
	}
	
	if fields["opencti_ip_1_2_3_4_threat_level"] != "HIGH" {
		t.Errorf("Expected threat level HIGH, got %s", fields["opencti_ip_1_2_3_4_threat_level"])
	}
	
	if fields["opencti_ip_1_2_3_4_threat_actors"] != "APT28" {
		t.Errorf("Expected threat actor APT28, got %s", fields["opencti_ip_1_2_3_4_threat_actors"])
	}
}

func TestIsValidIP(t *testing.T) {
	plugin := &OpenCTIPlugin{}
	
	tests := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", true},           // Public IP
		{"1.2.3.4", true},           // Public IP
		{"192.168.1.1", false},     // Private IP
		{"10.0.0.1", false},        // Private IP
		{"127.0.0.1", false},       // Loopback
		{"::1", false},             // IPv6 loopback
		{"invalid", false},         // Invalid IP
		{"", false},                // Empty
	}
	
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			result := plugin.isValidIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isValidIP(%s) = %v, expected %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsValidHash(t *testing.T) {
	plugin := &OpenCTIPlugin{}
	
	tests := []struct {
		hash     string
		expected bool
	}{
		{"d41d8cd98f00b204e9800998ecf8427e", true},                                                         // MD5
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", true},                                                 // SHA1
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},                         // SHA256
		{"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", true}, // SHA512
		{"invalid", false},                                                                                 // Invalid
		{"", false},                                                                                        // Empty
		{"123", false},                                                                                     // Too short
	}
	
	for _, tt := range tests {
		t.Run(tt.hash, func(t *testing.T) {
			result := plugin.isValidHash(tt.hash)
			if result != tt.expected {
				t.Errorf("isValidHash(%s) = %v, expected %v", tt.hash, result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkObservableExtraction(b *testing.B) {
	plugin := &OpenCTIPlugin{
		config: OpenCTIConfig{
			ProcessIPs:     true,
			ProcessDomains: true,
			ProcessHashes:  true,
			ProcessURLs:    true,
		},
	}
	
	eventJSON := `{
		"src_endpoint": {"ip": "1.2.3.4", "hostname": "test.com"},
		"dst_endpoint": {"ip": "5.6.7.8"},
		"file": {"hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}}
	}`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plugin.extractObservables(eventJSON)
	}
}

func BenchmarkEnrichmentFieldConversion(b *testing.B) {
	plugin := &OpenCTIPlugin{}
	
	obs := Observable{Type: "ip", Value: "1.2.3.4"}
	intel := &ThreatIntelligence{
		Observable:  obs,
		Confidence:  85,
		ThreatLevel: "HIGH",
		ThreatActors: []STIXThreatActor{
			{Name: "APT28", Aliases: []string{"Fancy Bear"}},
		},
		Indicators: []STIXIndicator{
			{Name: "Test Indicator", Labels: []string{"malicious"}},
		},
		QueryTime: time.Now(),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plugin.convertToEnrichmentFields(obs, intel)
	}
}