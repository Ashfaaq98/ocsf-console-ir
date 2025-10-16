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

// MockMISPServer creates a mock MISP server for testing
func NewMockMISPServer() *httptest.Server {
	mux := http.NewServeMux()
	
	// Health check endpoint
	mux.HandleFunc("/servers/getVersion", func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"version": "2.4.180",
			"pymisp_version": "2.4.180",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// User validation endpoint
	mux.HandleFunc("/users/view/me", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "test-api-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		
		response := map[string]interface{}{
			"User": map[string]interface{}{
				"id":    "1",
				"email": "test@example.com",
				"Organisation": map[string]interface{}{
					"name": "Test Org",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// Attribute search endpoint
	mux.HandleFunc("/attributes/restSearch", func(w http.ResponseWriter, r *http.Request) {
		var request AttributeSearchRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		
		// Mock response based on search value
		response := MISPAttributeResponse{
			Response: struct {
				Attribute []MISPAttribute `json:"Attribute"`
			}{
				Attribute: []MISPAttribute{
					{
						ID:           "12345",
						Type:         "ip-dst",
						Value:        request.Value,
						Category:     "Network activity",
						ToIDS:        true,
						UUID:         "550e8400-e29b-41d4-a716-446655440000",
						Timestamp:    "1640995200",
						Distribution: DistributionCommunity,
						Comment:      "Mock malicious IP",
						Event: &MISPEventInfo{
							ID:             "67890",
							UUID:           "550e8400-e29b-41d4-a716-446655440001",
							Info:           "Mock Threat Intelligence Event",
							Date:           "2024-01-01",
							ThreatLevelID:  ThreatLevelMedium,
							Analysis:       AnalysisCompleted,
							AttributeCount: "5",
							Org: &MISPOrganization{
								ID:   "1",
								Name: "Test Organization",
								UUID: "550e8400-e29b-41d4-a716-446655440002",
							},
						},
						Tags: []MISPTag{
							{
								ID:   "1",
								Name: "tlp:white",
							},
							{
								ID:   "2",
								Name: "misp-galaxy:threat-actor=\"APT-MOCK\"",
							},
						},
					},
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	// Event search endpoint
	mux.HandleFunc("/events/restSearch", func(w http.ResponseWriter, r *http.Request) {
		response := MISPEventResponse{
			Response: []MISPEvent{
				{
					ID:                "67890",
					UUID:              "550e8400-e29b-41d4-a716-446655440001",
					Info:              "Mock Threat Intelligence Event",
					Date:              "2024-01-01",
					ThreatLevelID:     ThreatLevelMedium,
					Published:         true,
					Analysis:          AnalysisCompleted,
					Distribution:      DistributionCommunity,
					AttributeCount:    "5",
					Org: &MISPOrganization{
						Name: "Test Organization",
					},
					Attributes: []MISPAttribute{
						{
							ID:       "12345",
							Type:     "ip-dst",
							Value:    "192.168.1.100",
							Category: "Network activity",
							ToIDS:    true,
						},
						{
							ID:       "12346",
							Type:     "domain",
							Value:    "malicious.example.com",
							Category: "Network activity",
							ToIDS:    true,
						},
					},
					Tags: []MISPTag{
						{Name: "tlp:white"},
						{Name: "misp-galaxy:threat-actor=\"APT-MOCK\""},
					},
				},
			},
		}
		
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})
	
	return httptest.NewServer(mux)
}

func TestMISPClient_NewClient(t *testing.T) {
	config := MISPConfig{
		BaseURL:      "https://example.com",
		APIKey:       "test-api-key",
		Timeout:      10 * time.Second,
		RateLimitRPS: 10,
		BurstLimit:   20,
		VerifyTLS:    true,
	}
	
	client, err := NewMISPClient(config, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	if client.baseURL != "https://example.com" {
		t.Errorf("Expected baseURL 'https://example.com', got '%s'", client.baseURL)
	}
	
	if client.apiKey != "test-api-key" {
		t.Errorf("Expected API key 'test-api-key', got '%s'", client.apiKey)
	}
}

func TestMISPClient_HealthCheck(t *testing.T) {
	server := NewMockMISPServer()
	defer server.Close()
	
	config := MISPConfig{
		BaseURL:      server.URL,
		APIKey:       "test-api-key",
		Timeout:      5 * time.Second,
		RateLimitRPS: 10,
		VerifyTLS:    false,
	}
	
	client, err := NewMISPClient(config, log.New(io.Discard, "", 0))
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

func TestMISPClient_ValidateAPIKey(t *testing.T) {
	server := NewMockMISPServer()
	defer server.Close()
	
	tests := []struct {
		name        string
		apiKey      string
		expectError bool
	}{
		{
			name:        "Valid API key",
			apiKey:      "test-api-key",
			expectError: false,
		},
		{
			name:        "Invalid API key",
			apiKey:      "invalid-key",
			expectError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := MISPConfig{
				BaseURL:      server.URL,
				APIKey:       tt.apiKey,
				Timeout:      5 * time.Second,
				RateLimitRPS: 10,
				VerifyTLS:    false,
			}
			
			client, err := NewMISPClient(config, log.New(io.Discard, "", 0))
			if err != nil {
				t.Fatalf("Failed to create client: %v", err)
			}
			defer client.Close()
			
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			err = client.ValidateAPIKey(ctx)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestMISPClient_SearchAttributes(t *testing.T) {
	server := NewMockMISPServer()
	defer server.Close()
	
	config := MISPConfig{
		BaseURL:        server.URL,
		APIKey:         "test-api-key",
		Timeout:        5 * time.Second,
		RateLimitRPS:   10,
		VerifyTLS:      false,
		IncludeContext: true,
		MaxResults:     100,
		DaysBack:       30,
		OnlyToIDS:      true,
	}
	
	client, err := NewMISPClient(config, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	attributes, err := client.SearchAttributes(ctx, "ip", "192.168.1.100", config)
	if err != nil {
		t.Errorf("SearchAttributes failed: %v", err)
	}
	
	if len(attributes) != 1 {
		t.Errorf("Expected 1 attribute, got %d", len(attributes))
	}
	
	if len(attributes) > 0 {
		attr := attributes[0]
		if attr.Value != "192.168.1.100" {
			t.Errorf("Expected attribute value '192.168.1.100', got '%s'", attr.Value)
		}
		if attr.Type != "ip-dst" {
			t.Errorf("Expected attribute type 'ip-dst', got '%s'", attr.Type)
		}
		if !attr.ToIDS {
			t.Error("Expected ToIDS to be true")
		}
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(5, 10) // 5 RPS with burst of 10
	defer rl.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	
	// Should be able to get 10 tokens immediately (burst)
	for i := 0; i < 10; i++ {
		if err := rl.Wait(ctx); err != nil {
			t.Errorf("Failed to get token %d: %v", i+1, err)
		}
	}
	
	// 11th token should be rate limited
	start := time.Now()
	if err := rl.Wait(ctx); err == nil {
		duration := time.Since(start)
		if duration < 150*time.Millisecond { // Should wait ~200ms for 5 RPS
			t.Errorf("Rate limiter didn't wait long enough: %v", duration)
		}
	}
}

func TestObservableExtraction(t *testing.T) {
	plugin := &MISPPlugin{
		config: MISPConfig{
			ProcessIPs:     true,
			ProcessDomains: true,
			ProcessHashes:  true,
			ProcessURLs:    true,
			ProcessEmails:  true,
		},
	}
	
	eventJSON := `{
		"src_endpoint": {
			"ip": "1.2.3.4",
			"hostname": "malicious.example.com"
		},
		"dst_endpoint": {
			"ip": "192.168.1.100"
		},
		"file": {
			"hashes": {
				"md5": "d41d8cd98f00b204e9800998ecf8427e",
				"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
			}
		},
		"url": "https://evil.example.com/malware.exe",
		"user": {
			"email_addr": "victim@company.com"
		}
	}`
	
	observables := plugin.extractObservables(eventJSON)
	
	expectedTypes := map[string]int{
		"ip":     2, // Both public and private IPs for MISP
		"domain": 2, // malicious.example.com, evil.example.com  
		"hash":   2, // MD5 and SHA256
		"url":    1, // https://evil.example.com/malware.exe
		"email":  1, // victim@company.com
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
	plugin := &MISPPlugin{
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
	
	if intel.ThreatLevel == "" {
		t.Error("Expected non-empty threat level")
	}
	
	if !intel.ToIDS {
		t.Error("Expected ToIDS to be true in mock data")
	}
	
	if len(intel.Attributes) == 0 {
		t.Error("Expected at least one attribute in mock data")
	}
	
	if len(intel.Events) == 0 {
		t.Error("Expected at least one event in mock data")
	}
	
	if len(intel.Tags) == 0 {
		t.Error("Expected at least one tag in mock data")
	}
}

func TestConvertToEnrichmentFields(t *testing.T) {
	plugin := &MISPPlugin{}
	
	obs := Observable{
		Type:  "ip",
		Value: "1.2.3.4",
	}
	
	intel := &MISPThreatIntelligence{
		Observable:  obs,
		ThreatLevel: "HIGH",
		ToIDS:       true,
		Attributes: []MISPAttribute{
			{
				ID:       "12345",
				Type:     "ip-dst",
				Value:    "1.2.3.4",
				Category: "Network activity",
				ToIDS:    true,
			},
		},
		Events: []MISPEventInfo{
			{
				ID:             "67890",
				Info:           "Malicious IP Campaign",
				ThreatLevelID:  ThreatLevelHigh,
				Org: &MISPOrganization{
					Name: "Security Team",
				},
			},
		},
		Tags:          []string{"tlp:white", "misp-galaxy:threat-actor=\"APT-TEST\""},
		Categories:    []string{"Network activity"},
		Organizations: []string{"Security Team"},
		GalaxyClusters: []MISPGalaxyCluster{
			{
				Type:  "threat-actor",
				Value: "APT-TEST",
			},
		},
		QueryTime: time.Now(),
	}
	
	fields := plugin.convertToEnrichmentFields(obs, intel)
	
	expectedFields := []string{
		"misp_ip_1_2_3_4_threat_level",
		"misp_ip_1_2_3_4_to_ids",
		"misp_ip_1_2_3_4_events",
		"misp_ip_1_2_3_4_tags",
		"misp_ip_1_2_3_4_categories",
		"misp_ip_1_2_3_4_organizations",
		"misp_ip_1_2_3_4_galaxy_clusters",
		"misp_ip_1_2_3_4_attribute_count",
	}
	
	for _, expectedField := range expectedFields {
		if _, exists := fields[expectedField]; !exists {
			t.Errorf("Expected field %s not found in enrichment", expectedField)
		}
	}
	
	if fields["misp_ip_1_2_3_4_threat_level"] != "HIGH" {
		t.Errorf("Expected threat level HIGH, got %s", fields["misp_ip_1_2_3_4_threat_level"])
	}
	
	if fields["misp_ip_1_2_3_4_to_ids"] != "true" {
		t.Errorf("Expected to_ids true, got %s", fields["misp_ip_1_2_3_4_to_ids"])
	}
	
	if fields["misp_ip_1_2_3_4_attribute_count"] != "1" {
		t.Errorf("Expected attribute count 1, got %s", fields["misp_ip_1_2_3_4_attribute_count"])
	}
}

func TestIsValidIP(t *testing.T) {
	plugin := &MISPPlugin{}
	
	tests := []struct {
		ip       string
		expected bool
	}{
		{"8.8.8.8", true},           // Public IP
		{"1.2.3.4", true},           // Public IP
		{"192.168.1.1", true},       // Private IP (MISP includes all)
		{"10.0.0.1", true},          // Private IP (MISP includes all)
		{"127.0.0.1", true},         // Loopback (MISP includes all)
		{"::1", true},               // IPv6 loopback
		{"invalid", false},          // Invalid IP
		{"", false},                 // Empty
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
	plugin := &MISPPlugin{}
	
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

func TestIsValidEmail(t *testing.T) {
	plugin := &MISPPlugin{}
	
	tests := []struct {
		email    string
		expected bool
	}{
		{"user@example.com", true},
		{"test.email+tag@domain.co.uk", true},
		{"invalid-email", false},
		{"@domain.com", false},
		{"user@", false},
		{"", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			result := plugin.isValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("isValidEmail(%s) = %v, expected %v", tt.email, result, tt.expected)
			}
		})
	}
}

func TestCalculateThreatLevel(t *testing.T) {
	plugin := &MISPPlugin{}
	
	tests := []struct {
		name       string
		attributes []MISPAttribute
		expected   string
	}{
		{
			name: "High threat level",
			attributes: []MISPAttribute{
				{
					Event: &MISPEventInfo{
						ThreatLevelID: ThreatLevelHigh,
					},
				},
			},
			expected: "HIGH",
		},
		{
			name: "Medium threat level",
			attributes: []MISPAttribute{
				{
					Event: &MISPEventInfo{
						ThreatLevelID: ThreatLevelMedium,
					},
				},
			},
			expected: "MEDIUM",
		},
		{
			name:       "No attributes",
			attributes: []MISPAttribute{},
			expected:   "INFORMATIONAL",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.calculateThreatLevel(tt.attributes)
			if result != tt.expected {
				t.Errorf("calculateThreatLevel() = %s, expected %s", result, tt.expected)
			}
		})
	}
}

// Benchmark tests
func BenchmarkObservableExtraction(b *testing.B) {
	plugin := &MISPPlugin{
		config: MISPConfig{
			ProcessIPs:     true,
			ProcessDomains: true,
			ProcessHashes:  true,
			ProcessURLs:    true,
			ProcessEmails:  true,
		},
	}
	
	eventJSON := `{
		"src_endpoint": {"ip": "1.2.3.4", "hostname": "test.com"},
		"dst_endpoint": {"ip": "5.6.7.8"},
		"file": {"hashes": {"md5": "d41d8cd98f00b204e9800998ecf8427e"}},
		"user": {"email_addr": "test@example.com"}
	}`
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plugin.extractObservables(eventJSON)
	}
}

func BenchmarkEnrichmentFieldConversion(b *testing.B) {
	plugin := &MISPPlugin{}
	
	obs := Observable{Type: "ip", Value: "1.2.3.4"}
	intel := &MISPThreatIntelligence{
		Observable:  obs,
		ThreatLevel: "HIGH",
		ToIDS:       true,
		Attributes: []MISPAttribute{
			{Type: "ip-dst", Value: "1.2.3.4", Category: "Network activity"},
		},
		Events: []MISPEventInfo{
			{Info: "Test Event", ThreatLevelID: ThreatLevelHigh},
		},
		Tags:          []string{"tlp:white", "malicious"},
		Categories:    []string{"Network activity"},
		Organizations: []string{"Test Org"},
		QueryTime:     time.Now(),
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = plugin.convertToEnrichmentFields(obs, intel)
	}
}