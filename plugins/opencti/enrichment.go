package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// getOrFetchThreatIntelligence retrieves threat intelligence from cache or OpenCTI
func (p *OpenCTIPlugin) getOrFetchThreatIntelligence(obs Observable) (*ThreatIntelligence, error) {
	// Generate cache key
	cacheKey := generateCacheKey(obs.Type, obs.Value)
	
	// Try cache first
	if intel, found := p.cache.Get(cacheKey); found {
		p.logger.Printf("Cache hit for %s: %s", obs.Type, obs.Value)
		return intel, nil
	}
	
	p.logger.Printf("Cache miss for %s: %s, fetching from OpenCTI", obs.Type, obs.Value)
	
	// If dry run mode, return mock data
	if p.openCTIClient == nil {
		return p.generateMockThreatIntelligence(obs), nil
	}
	
	// Fetch from OpenCTI
	ctx, cancel := context.WithTimeout(p.ctx, p.config.Timeout)
	defer cancel()
	
	intel, err := p.fetchThreatIntelligence(ctx, obs)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch threat intelligence: %w", err)
	}
	
	// Cache the result
	if intel != nil {
		p.cache.Set(cacheKey, intel, p.config.CacheTTL)
	}
	
	return intel, nil
}

// fetchThreatIntelligence fetches threat intelligence from OpenCTI API
func (p *OpenCTIPlugin) fetchThreatIntelligence(ctx context.Context, obs Observable) (*ThreatIntelligence, error) {
	intel := &ThreatIntelligence{
		Observable: obs,
		QueryTime:  time.Now(),
	}
	
	// Search for observables in OpenCTI
	observables, err := p.openCTIClient.SearchObservables(ctx, obs.Type, obs.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to search observables: %w", err)
	}
	
	if len(observables) == 0 {
		p.logger.Printf("No observables found in OpenCTI for %s: %s", obs.Type, obs.Value)
		return intel, nil // Return empty intelligence
	}
	
	p.logger.Printf("Found %d observable(s) in OpenCTI for %s: %s", len(observables), obs.Type, obs.Value)
	
	// Process the first observable (highest confidence)
	primaryObservable := observables[0]
	intel.Confidence = primaryObservable.Confidence
	
	// Determine threat level based on score and confidence
	intel.ThreatLevel = p.calculateThreatLevel(primaryObservable.Score, primaryObservable.Confidence)
	
	// Extract indicators
	for _, indicator := range primaryObservable.Indicators {
		if indicator.Confidence >= p.config.MinConfidence {
			intel.Indicators = append(intel.Indicators, indicator)
		}
	}
	
	// If we want related entities, fetch them
	if p.config.IncludeRelated && p.config.MaxRelations > 0 {
		relatedIntel, err := p.openCTIClient.GetRelatedEntities(ctx, primaryObservable.ID, p.config.MaxRelations)
		if err != nil {
			p.logger.Printf("Warning: failed to get related entities for %s: %v", obs.Value, err)
		} else if relatedIntel != nil {
			// Merge related intelligence
			intel.ThreatActors = append(intel.ThreatActors, relatedIntel.ThreatActors...)
			intel.Campaigns = append(intel.Campaigns, relatedIntel.Campaigns...)
			intel.Malware = append(intel.Malware, relatedIntel.Malware...)
			intel.AttackPatterns = append(intel.AttackPatterns, relatedIntel.AttackPatterns...)
			intel.Relationships = append(intel.Relationships, relatedIntel.Relationships...)
		}
	}
	
	// Search for indicators containing this observable
	indicators, err := p.openCTIClient.SearchByIOC(ctx, obs.Value)
	if err != nil {
		p.logger.Printf("Warning: failed to search indicators for %s: %v", obs.Value, err)
	} else {
		for _, indicator := range indicators {
			if indicator.Confidence >= p.config.MinConfidence {
				intel.Indicators = append(intel.Indicators, indicator)
			}
		}
	}
	
	// Set first and last seen times
	if len(intel.Indicators) > 0 {
		for _, indicator := range intel.Indicators {
			if intel.FirstSeen.IsZero() || indicator.ValidFrom.Before(intel.FirstSeen) {
				intel.FirstSeen = indicator.ValidFrom
			}
			if intel.LastSeen.IsZero() || indicator.ValidUntil.After(intel.LastSeen) {
				intel.LastSeen = indicator.ValidUntil
			}
		}
	}
	
	p.logger.Printf("Fetched threat intelligence for %s: %s (confidence: %d, indicators: %d, threat_actors: %d)", 
		obs.Type, obs.Value, intel.Confidence, len(intel.Indicators), len(intel.ThreatActors))
	
	return intel, nil
}

// calculateThreatLevel determines threat level based on score and confidence
func (p *OpenCTIPlugin) calculateThreatLevel(score, confidence int) string {
	// Combine score and confidence to determine threat level
	combinedScore := (score + confidence) / 2
	
	switch {
	case combinedScore >= 80:
		return "CRITICAL"
	case combinedScore >= 60:
		return "HIGH"
	case combinedScore >= 40:
		return "MEDIUM"
	case combinedScore >= 20:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// convertToEnrichmentFields converts threat intelligence to Redis enrichment fields
func (p *OpenCTIPlugin) convertToEnrichmentFields(obs Observable, intel *ThreatIntelligence) map[string]string {
	enrichment := make(map[string]string)
	
	// Create observable prefix for field names
	obsKey := fmt.Sprintf("%s_%s", obs.Type, p.sanitizeKey(obs.Value))
	
	// Basic observable information
	enrichment[fmt.Sprintf("opencti_%s_confidence", obsKey)] = fmt.Sprintf("%d", intel.Confidence)
	enrichment[fmt.Sprintf("opencti_%s_threat_level", obsKey)] = intel.ThreatLevel
	enrichment[fmt.Sprintf("opencti_%s_query_time", obsKey)] = intel.QueryTime.Format(time.RFC3339)
	
	// First and last seen
	if !intel.FirstSeen.IsZero() {
		enrichment[fmt.Sprintf("opencti_%s_first_seen", obsKey)] = intel.FirstSeen.Format(time.RFC3339)
	}
	if !intel.LastSeen.IsZero() {
		enrichment[fmt.Sprintf("opencti_%s_last_seen", obsKey)] = intel.LastSeen.Format(time.RFC3339)
	}
	
	// Threat actors
	if len(intel.ThreatActors) > 0 {
		var actorNames []string
		var actorCountries []string
		var actorAliases []string
		
		for _, actor := range intel.ThreatActors {
			if actor.Name != "" {
				actorNames = append(actorNames, actor.Name)
			}
			if actor.Country != "" {
				actorCountries = append(actorCountries, actor.Country)
			}
			actorAliases = append(actorAliases, actor.Aliases...)
		}
		
		if len(actorNames) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_threat_actors", obsKey)] = strings.Join(actorNames, ",")
		}
		if len(actorCountries) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_actor_countries", obsKey)] = strings.Join(p.deduplicate(actorCountries), ",")
		}
		if len(actorAliases) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_actor_aliases", obsKey)] = strings.Join(p.deduplicate(actorAliases), ",")
		}
	}
	
	// Campaigns
	if len(intel.Campaigns) > 0 {
		var campaignNames []string
		var campaignObjectives []string
		
		for _, campaign := range intel.Campaigns {
			if campaign.Name != "" {
				campaignNames = append(campaignNames, campaign.Name)
			}
			campaignObjectives = append(campaignObjectives, campaign.Objectives...)
		}
		
		if len(campaignNames) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_campaigns", obsKey)] = strings.Join(campaignNames, ",")
		}
		if len(campaignObjectives) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_campaign_objectives", obsKey)] = strings.Join(p.deduplicate(campaignObjectives), ",")
		}
	}
	
	// Malware
	if len(intel.Malware) > 0 {
		var malwareNames []string
		var malwareLabels []string
		var malwareCapabilities []string
		
		for _, malware := range intel.Malware {
			if malware.Name != "" {
				malwareNames = append(malwareNames, malware.Name)
			}
			malwareLabels = append(malwareLabels, malware.Labels...)
			malwareCapabilities = append(malwareCapabilities, malware.Capabilities...)
		}
		
		if len(malwareNames) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_malware", obsKey)] = strings.Join(malwareNames, ",")
		}
		if len(malwareLabels) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_malware_labels", obsKey)] = strings.Join(p.deduplicate(malwareLabels), ",")
		}
		if len(malwareCapabilities) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_malware_capabilities", obsKey)] = strings.Join(p.deduplicate(malwareCapabilities), ",")
		}
	}
	
	// Attack patterns (MITRE ATT&CK)
	if len(intel.AttackPatterns) > 0 {
		var patternNames []string
		var mitreIDs []string
		var platforms []string
		
		for _, pattern := range intel.AttackPatterns {
			if pattern.Name != "" {
				patternNames = append(patternNames, pattern.Name)
			}
			if pattern.MitreID != "" {
				mitreIDs = append(mitreIDs, pattern.MitreID)
			}
			platforms = append(platforms, pattern.Platforms...)
		}
		
		if len(patternNames) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_attack_patterns", obsKey)] = strings.Join(patternNames, ",")
		}
		if len(mitreIDs) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_mitre_techniques", obsKey)] = strings.Join(mitreIDs, ",")
		}
		if len(platforms) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_platforms", obsKey)] = strings.Join(p.deduplicate(platforms), ",")
		}
	}
	
	// Indicators
	if len(intel.Indicators) > 0 {
		var indicatorNames []string
		var indicatorLabels []string
		
		for _, indicator := range intel.Indicators {
			if indicator.Name != "" {
				indicatorNames = append(indicatorNames, indicator.Name)
			}
			indicatorLabels = append(indicatorLabels, indicator.Labels...)
		}
		
		if len(indicatorNames) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_indicators", obsKey)] = strings.Join(indicatorNames, ",")
		}
		if len(indicatorLabels) > 0 {
			enrichment[fmt.Sprintf("opencti_%s_indicator_labels", obsKey)] = strings.Join(p.deduplicate(indicatorLabels), ",")
		}
		
		enrichment[fmt.Sprintf("opencti_%s_indicator_count", obsKey)] = fmt.Sprintf("%d", len(intel.Indicators))
	}
	
	// Relationships summary
	if len(intel.Relationships) > 0 {
		relationshipTypes := make(map[string]int)
		for _, rel := range intel.Relationships {
			relationshipTypes[rel.RelationType]++
		}
		
		var relTypes []string
		for relType, count := range relationshipTypes {
			relTypes = append(relTypes, fmt.Sprintf("%s:%d", relType, count))
		}
		
		enrichment[fmt.Sprintf("opencti_%s_relationships", obsKey)] = strings.Join(relTypes, ",")
	}
	
	return enrichment
}

// publishEnrichment publishes enrichment data to Redis
func (p *OpenCTIPlugin) publishEnrichment(eventID string, data map[string]string) error {
	enrichment := EnrichmentMessage{
		EventID:    eventID,
		Source:     "opencti",
		Type:       "threat_intelligence",
		Data:       data,
		Timestamp:  time.Now().Unix(),
		PluginName: "opencti-plugin",
	}

	// Serialize data
	dataJSON, err := json.Marshal(enrichment.Data)
	if err != nil {
		return fmt.Errorf("failed to marshal enrichment data: %w", err)
	}

	// Publish to enrichments stream
	fields := map[string]interface{}{
		"event_id":    enrichment.EventID,
		"source":      enrichment.Source,
		"type":        enrichment.Type,
		"data":        string(dataJSON),
		"timestamp":   enrichment.Timestamp,
		"plugin_name": enrichment.PluginName,
	}

	result := p.client.XAdd(p.ctx, &redis.XAddArgs{
		Stream: "enrichments",
		Values: fields,
	})

	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish enrichment: %w", err)
	}

	p.logger.Printf("Published OpenCTI enrichment for event %s with %d fields", eventID, len(data))
	return nil
}

// generateMockThreatIntelligence creates mock threat intelligence for dry-run mode
func (p *OpenCTIPlugin) generateMockThreatIntelligence(obs Observable) *ThreatIntelligence {
	now := time.Now()
	
	intel := &ThreatIntelligence{
		Observable:  obs,
		Confidence:  75,
		ThreatLevel: "MEDIUM",
		QueryTime:   now,
		FirstSeen:   now.AddDate(0, -1, 0), // 1 month ago
		LastSeen:    now.AddDate(0, 0, -1),  // 1 day ago
	}
	
	// Add mock threat actors for certain observables
	if obs.Type == "ip" || obs.Type == "domain" {
		intel.ThreatActors = []STIXThreatActor{
			{
				ID:          "threat-actor--mock-1",
				Name:        "APT-SIMULATION",
				Aliases:     []string{"SimulatedThreat", "MockActor"},
				Description: "Simulated threat actor for testing (dry-run mode)",
				Country:     "Unknown",
				Confidence:  70,
			},
		}
		
		intel.Campaigns = []STIXCampaign{
			{
				ID:          "campaign--mock-1",
				Name:        "Operation DryRun",
				Description: "Simulated campaign for testing purposes",
				FirstSeen:   now.AddDate(0, -1, 0),
				LastSeen:    now.AddDate(0, 0, -1),
				Confidence:  65,
				Objectives:  []string{"testing", "simulation"},
			},
		}
	}
	
	// Add mock indicators
	intel.Indicators = []STIXIndicator{
		{
			ID:          "indicator--mock-1",
			Name:        fmt.Sprintf("Mock indicator for %s", obs.Value),
			Pattern:     fmt.Sprintf("[%s:value = '%s']", obs.Type, obs.Value),
			Labels:      []string{"malicious-activity", "dry-run"},
			Confidence:  75,
			ValidFrom:   now.AddDate(0, -1, 0),
			ValidUntil:  now.AddDate(0, 1, 0),
			Description: "Mock indicator for dry-run testing",
		},
	}
	
	// Add mock attack patterns
	intel.AttackPatterns = []STIXAttackPattern{
		{
			ID:             "attack-pattern--mock-1",
			Name:           "Mock Technique",
			Description:    "Simulated MITRE ATT&CK technique for testing",
			MitreID:        "T1000.001",
			Platforms:      []string{"Windows", "Linux", "macOS"},
			DataSources:   []string{"Network Traffic", "Process Monitoring"},
		},
	}
	
	p.logger.Printf("Generated mock threat intelligence for %s: %s", obs.Type, obs.Value)
	return intel
}

// Helper functions

// sanitizeKey sanitizes a value for use as a Redis key component
func (p *OpenCTIPlugin) sanitizeKey(value string) string {
	// Replace dots and other special characters with underscores
	return strings.ReplaceAll(strings.ReplaceAll(value, ".", "_"), ":", "_")
}

// deduplicate removes duplicate strings from a slice
func (p *OpenCTIPlugin) deduplicate(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if item != "" && !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// getStringField extracts a string field from Redis message values
func getStringField(values map[string]interface{}, key string) string {
	if value, ok := values[key]; ok {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}