package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// getOrFetchThreatIntelligence retrieves threat intelligence from cache or MISP
func (p *MISPPlugin) getOrFetchThreatIntelligence(obs Observable) (*MISPThreatIntelligence, error) {
	// Generate cache key
	cacheKey := generateCacheKey(obs.Type, obs.Value)
	
	// Try cache first
	if intel, found := p.cache.Get(cacheKey); found {
		p.logger.Printf("Cache hit for %s: %s", obs.Type, obs.Value)
		return intel, nil
	}
	
	p.logger.Printf("Cache miss for %s: %s, fetching from MISP", obs.Type, obs.Value)
	
	// If dry run mode, return mock data
	if p.mispClient == nil {
		return p.generateMockThreatIntelligence(obs), nil
	}
	
	// Fetch from MISP
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

// fetchThreatIntelligence fetches threat intelligence from MISP API
func (p *MISPPlugin) fetchThreatIntelligence(ctx context.Context, obs Observable) (*MISPThreatIntelligence, error) {
	intel := &MISPThreatIntelligence{
		Observable: obs,
		QueryTime:  time.Now(),
	}
	
	// Search for attributes in MISP
	attributes, err := p.mispClient.SearchAttributes(ctx, obs.Type, obs.Value, p.config)
	if err != nil {
		return nil, fmt.Errorf("failed to search attributes: %w", err)
	}
	
	if len(attributes) == 0 {
		p.logger.Printf("No attributes found in MISP for %s: %s", obs.Type, obs.Value)
		return intel, nil // Return empty intelligence
	}
	
	p.logger.Printf("Found %d attribute(s) in MISP for %s: %s", len(attributes), obs.Type, obs.Value)
	p.metrics.AttributesFound += int64(len(attributes))
	
	// Process attributes
	intel.Attributes = attributes
	
	// Extract events from attributes
	eventMap := make(map[string]*MISPEventInfo)
	for _, attr := range attributes {
		if attr.Event != nil {
			eventMap[attr.Event.ID] = attr.Event
		}
	}
	
	// Convert event map to slice
	for _, event := range eventMap {
		intel.Events = append(intel.Events, *event)
	}
	
	// Process event correlation if enabled
	if p.config.CorrelateEvents && len(intel.Events) > 0 {
		var eventIDs []string
		for _, event := range intel.Events {
			eventIDs = append(eventIDs, event.ID)
		}
		
		correlatedEvents, err := p.mispClient.SearchEvents(ctx, eventIDs, p.config)
		if err != nil {
			p.logger.Printf("Warning: failed to correlate events for %s: %v", obs.Value, err)
		} else {
			p.metrics.EventsCorrelated += int64(len(correlatedEvents))
			
			// Extract additional attributes from correlated events
			for _, event := range correlatedEvents {
				for _, attr := range event.Attributes {
					// Only include relevant attributes (not the original observable)
					if attr.Value != obs.Value {
						relatedIOC := RelatedIOC{
							Type:     attr.Type,
							Value:    attr.Value,
							EventID:  event.ID,
							Category: attr.Category,
						}
						intel.RelatedIOCs = append(intel.RelatedIOCs, relatedIOC)
					}
				}
			}
		}
	}
	
	// Extract tags and categories
	tagMap := make(map[string]bool)
	categoryMap := make(map[string]bool)
	orgMap := make(map[string]bool)
	
	for _, attr := range attributes {
		// Process categories
		if attr.Category != "" {
			categoryMap[attr.Category] = true
		}
		
		// Process organization
		if attr.Event != nil && attr.Event.Org != nil {
			orgMap[attr.Event.Org.Name] = true
		}
		
		// Process tags
		for _, tag := range attr.Tags {
			tagMap[tag.Name] = true
		}
		
		// Process ToIDS flag
		if attr.ToIDS {
			intel.ToIDS = true
		}
	}
	
	// Convert maps to slices
	for tag := range tagMap {
		intel.Tags = append(intel.Tags, tag)
	}
	for category := range categoryMap {
		intel.Categories = append(intel.Categories, category)
	}
	for org := range orgMap {
		intel.Organizations = append(intel.Organizations, org)
	}
	
	// Process galaxy clusters from tags
	var galaxyTags []string
	for _, tag := range intel.Tags {
		if strings.HasPrefix(tag, "misp-galaxy:") {
			galaxyTags = append(galaxyTags, tag)
		}
	}
	
	if len(galaxyTags) > 0 {
		clusters, err := p.mispClient.GetGalaxyClusters(ctx, galaxyTags)
		if err != nil {
			p.logger.Printf("Warning: failed to get galaxy clusters for %s: %v", obs.Value, err)
		} else {
			intel.GalaxyClusters = clusters
		}
	}
	
	// Determine threat level from events
	intel.ThreatLevel = p.calculateThreatLevel(attributes)
	
	// Set first and last seen times
	intel.FirstSeen, intel.LastSeen = p.calculateTimeRange(attributes)
	
	p.logger.Printf("Fetched threat intelligence for %s: %s (attributes: %d, events: %d, organizations: %d)", 
		obs.Type, obs.Value, len(intel.Attributes), len(intel.Events), len(intel.Organizations))
	
	return intel, nil
}

// calculateThreatLevel determines threat level from attributes and events
func (p *MISPPlugin) calculateThreatLevel(attributes []MISPAttribute) string {
	if len(attributes) == 0 {
		return "INFORMATIONAL"
	}
	
	// Find the highest threat level from all associated events
	highestLevel := 4 // Start with lowest (undefined)
	
	for _, attr := range attributes {
		if attr.Event != nil {
			if level, err := strconv.Atoi(attr.Event.ThreatLevelID); err == nil {
				if level < highestLevel {
					highestLevel = level
				}
			}
		}
	}
	
	switch highestLevel {
	case 1:
		return "HIGH"
	case 2:
		return "MEDIUM"
	case 3:
		return "LOW"
	default:
		return "UNDEFINED"
	}
}

// calculateTimeRange determines first and last seen times from attributes
func (p *MISPPlugin) calculateTimeRange(attributes []MISPAttribute) (time.Time, time.Time) {
	var firstSeen, lastSeen time.Time
	
	for _, attr := range attributes {
		if attr.Timestamp != "" {
			if timestamp, err := strconv.ParseInt(attr.Timestamp, 10, 64); err == nil {
				attrTime := time.Unix(timestamp, 0)
				
				if firstSeen.IsZero() || attrTime.Before(firstSeen) {
					firstSeen = attrTime
				}
				if lastSeen.IsZero() || attrTime.After(lastSeen) {
					lastSeen = attrTime
				}
			}
		}
		
		// Also check event dates
		if attr.Event != nil && attr.Event.Date != "" {
			if eventTime, err := time.Parse("2006-01-02", attr.Event.Date); err == nil {
				if firstSeen.IsZero() || eventTime.Before(firstSeen) {
					firstSeen = eventTime
				}
				if lastSeen.IsZero() || eventTime.After(lastSeen) {
					lastSeen = eventTime
				}
			}
		}
	}
	
	return firstSeen, lastSeen
}

// convertToEnrichmentFields converts threat intelligence to Redis enrichment fields
func (p *MISPPlugin) convertToEnrichmentFields(obs Observable, intel *MISPThreatIntelligence) map[string]string {
	enrichment := make(map[string]string)
	
	// Create observable prefix for field names
	obsKey := fmt.Sprintf("%s_%s", obs.Type, p.sanitizeKey(obs.Value))
	
	// Basic observable information
	enrichment[fmt.Sprintf("misp_%s_query_time", obsKey)] = intel.QueryTime.Format(time.RFC3339)
	enrichment[fmt.Sprintf("misp_%s_threat_level", obsKey)] = intel.ThreatLevel
	enrichment[fmt.Sprintf("misp_%s_to_ids", obsKey)] = fmt.Sprintf("%t", intel.ToIDS)
	
	// Time information
	if !intel.FirstSeen.IsZero() {
		enrichment[fmt.Sprintf("misp_%s_first_seen", obsKey)] = intel.FirstSeen.Format(time.RFC3339)
	}
	if !intel.LastSeen.IsZero() {
		enrichment[fmt.Sprintf("misp_%s_last_seen", obsKey)] = intel.LastSeen.Format(time.RFC3339)
	}
	
	// Event information
	if len(intel.Events) > 0 {
		var eventTitles []string
		var eventIDs []string
		var analysisLevels []string
		
		for _, event := range intel.Events {
			if event.Info != "" {
				eventTitles = append(eventTitles, event.Info)
			}
			eventIDs = append(eventIDs, event.ID)
			
			// Convert analysis level
			if event.Analysis != "" {
				switch event.Analysis {
				case "0":
					analysisLevels = append(analysisLevels, "Initial")
				case "1":
					analysisLevels = append(analysisLevels, "Ongoing")
				case "2":
					analysisLevels = append(analysisLevels, "Completed")
				}
			}
		}
		
		enrichment[fmt.Sprintf("misp_%s_events", obsKey)] = strings.Join(p.truncateStrings(eventTitles, 5), ",")
		enrichment[fmt.Sprintf("misp_%s_event_ids", obsKey)] = strings.Join(p.truncateStrings(eventIDs, 10), ",")
		enrichment[fmt.Sprintf("misp_%s_event_count", obsKey)] = fmt.Sprintf("%d", len(intel.Events))
		
		if len(analysisLevels) > 0 {
			enrichment[fmt.Sprintf("misp_%s_analysis_levels", obsKey)] = strings.Join(p.deduplicate(analysisLevels), ",")
		}
	}
	
	// Categories
	if len(intel.Categories) > 0 {
		enrichment[fmt.Sprintf("misp_%s_categories", obsKey)] = strings.Join(p.deduplicate(intel.Categories), ",")
	}
	
	// Tags
	if len(intel.Tags) > 0 {
		// Separate galaxy tags from regular tags
		var regularTags, galaxyTags []string
		for _, tag := range intel.Tags {
			if strings.HasPrefix(tag, "misp-galaxy:") {
				galaxyTags = append(galaxyTags, tag)
			} else {
				regularTags = append(regularTags, tag)
			}
		}
		
		if len(regularTags) > 0 {
			enrichment[fmt.Sprintf("misp_%s_tags", obsKey)] = strings.Join(p.truncateStrings(regularTags, 10), ",")
		}
		if len(galaxyTags) > 0 {
			enrichment[fmt.Sprintf("misp_%s_galaxy_tags", obsKey)] = strings.Join(p.truncateStrings(galaxyTags, 5), ",")
		}
	}
	
	// Organizations
	if len(intel.Organizations) > 0 {
		enrichment[fmt.Sprintf("misp_%s_organizations", obsKey)] = strings.Join(p.deduplicate(intel.Organizations), ",")
	}
	
	// Galaxy clusters (threat actors, malware, etc.)
	if len(intel.GalaxyClusters) > 0 {
		var clusterNames []string
		var clusterTypes []string
		
		for _, cluster := range intel.GalaxyClusters {
			if cluster.Value != "" {
				clusterNames = append(clusterNames, cluster.Value)
			}
			if cluster.Type != "" {
				clusterTypes = append(clusterTypes, cluster.Type)
			}
		}
		
		if len(clusterNames) > 0 {
			enrichment[fmt.Sprintf("misp_%s_galaxy_clusters", obsKey)] = strings.Join(p.truncateStrings(clusterNames, 5), ",")
		}
		if len(clusterTypes) > 0 {
			enrichment[fmt.Sprintf("misp_%s_cluster_types", obsKey)] = strings.Join(p.deduplicate(clusterTypes), ",")
		}
	}
	
	// Related IOCs
	if len(intel.RelatedIOCs) > 0 {
		var relatedValues []string
		var relatedTypes []string
		
		for _, ioc := range intel.RelatedIOCs {
			relatedValues = append(relatedValues, ioc.Value)
			relatedTypes = append(relatedTypes, ioc.Type)
		}
		
		enrichment[fmt.Sprintf("misp_%s_related_iocs", obsKey)] = strings.Join(p.truncateStrings(relatedValues, 10), ",")
		enrichment[fmt.Sprintf("misp_%s_related_types", obsKey)] = strings.Join(p.deduplicate(relatedTypes), ",")
		enrichment[fmt.Sprintf("misp_%s_related_count", obsKey)] = fmt.Sprintf("%d", len(intel.RelatedIOCs))
	}
	
	// Attribute statistics
	enrichment[fmt.Sprintf("misp_%s_attribute_count", obsKey)] = fmt.Sprintf("%d", len(intel.Attributes))
	
	// Context information
	if len(intel.Attributes) > 0 {
		var comments []string
		for _, attr := range intel.Attributes {
			if attr.Comment != "" {
				comments = append(comments, attr.Comment)
			}
		}
		
		if len(comments) > 0 {
			// Take first comment as context
			enrichment[fmt.Sprintf("misp_%s_context", obsKey)] = p.truncateString(comments[0], 200)
		}
	}
	
	return enrichment
}

// publishEnrichment publishes enrichment data to Redis
func (p *MISPPlugin) publishEnrichment(eventID string, data map[string]string) error {
	enrichment := EnrichmentMessage{
		EventID:    eventID,
		Source:     "misp",
		Type:       "community_intelligence",
		Data:       data,
		Timestamp:  time.Now().Unix(),
		PluginName: "misp-plugin",
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

	p.logger.Printf("Published MISP enrichment for event %s with %d fields", eventID, len(data))
	return nil
}

// generateMockThreatIntelligence creates mock threat intelligence for dry-run mode
func (p *MISPPlugin) generateMockThreatIntelligence(obs Observable) *MISPThreatIntelligence {
	now := time.Now()
	
	intel := &MISPThreatIntelligence{
		Observable:  obs,
		ThreatLevel: "MEDIUM",
		ToIDS:       true,
		QueryTime:   now,
		FirstSeen:   now.AddDate(0, -1, 0), // 1 month ago
		LastSeen:    now.AddDate(0, 0, -1),  // 1 day ago
	}
	
	// Mock attributes
	intel.Attributes = []MISPAttribute{
		{
			ID:           "12345",
			Type:         p.mapObservableTypeToMISP(obs.Type),
			Value:        obs.Value,
			Category:     "Network activity",
			ToIDS:        true,
			Comment:      "Mock attribute for dry-run testing",
			Distribution: DistributionCommunity,
			Event: &MISPEventInfo{
				ID:             "67890",
				Info:           "Mock MISP Event for Testing",
				ThreatLevelID:  ThreatLevelMedium,
				Analysis:       AnalysisCompleted,
				AttributeCount: "5",
				Org: &MISPOrganization{
					Name: "Test Organization",
				},
			},
			Tags: []MISPTag{
				{Name: "tlp:white"},
				{Name: "misp-galaxy:threat-actor=\"APT-SIMULATION\""},
				{Name: "type:OSINT"},
			},
		},
	}
	
	// Mock events
	intel.Events = []MISPEventInfo{
		{
			ID:             "67890",
			Info:           "Mock MISP Event for Testing",
			Date:           now.AddDate(0, 0, -7).Format("2006-01-02"),
			ThreatLevelID:  ThreatLevelMedium,
			Analysis:       AnalysisCompleted,
			AttributeCount: "5",
			Org: &MISPOrganization{
				Name: "Test Organization",
			},
		},
	}
	
	// Mock tags and categories
	intel.Tags = []string{"tlp:white", "misp-galaxy:threat-actor=\"APT-SIMULATION\"", "type:OSINT"}
	intel.Categories = []string{"Network activity", "Artifacts dropped"}
	intel.Organizations = []string{"Test Organization", "Community Feed"}
	
	// Mock galaxy clusters
	if obs.Type == "ip" || obs.Type == "domain" {
		intel.GalaxyClusters = []MISPGalaxyCluster{
			{
				Type:        "threat-actor",
				Value:       "APT-SIMULATION",
				Tag:         "misp-galaxy:threat-actor=\"APT-SIMULATION\"",
				Description: "Simulated threat actor for testing (dry-run mode)",
				Synonyms:    []string{"MockThreat", "TestActor"},
			},
		}
	}
	
	// Mock related IOCs
	if obs.Type == "ip" {
		intel.RelatedIOCs = []RelatedIOC{
			{
				Type:     "domain",
				Value:    "mock-c2.example.com",
				EventID:  "67890",
				Category: "Network activity",
			},
			{
				Type:     "sha256",
				Value:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				EventID:  "67890",
				Category: "Artifacts dropped",
			},
		}
	}
	
	p.logger.Printf("Generated mock threat intelligence for %s: %s", obs.Type, obs.Value)
	return intel
}

// Helper functions

// mapObservableTypeToMISP maps our observable types to MISP attribute types
func (p *MISPPlugin) mapObservableTypeToMISP(observableType string) string {
	switch observableType {
	case "ip":
		return "ip-dst"
	case "domain":
		return "domain"
	case "url":
		return "url"
	case "email":
		return "email-src"
	case "hash":
		return "sha256" // Default to SHA256
	default:
		return "other"
	}
}

// sanitizeKey sanitizes a value for use as a Redis key component
func (p *MISPPlugin) sanitizeKey(value string) string {
	// Replace dots and other special characters with underscores
	return strings.ReplaceAll(strings.ReplaceAll(value, ".", "_"), ":", "_")
}

// deduplicate removes duplicate strings from a slice
func (p *MISPPlugin) deduplicate(slice []string) []string {
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

// truncateStrings limits the number of strings in a slice
func (p *MISPPlugin) truncateStrings(slice []string, maxItems int) []string {
	if len(slice) <= maxItems {
		return slice
	}
	return slice[:maxItems]
}

// truncateString limits the length of a string
func (p *MISPPlugin) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}