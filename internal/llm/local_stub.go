package llm

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ashfaaq98/ocsf-console-ir/internal/store"
)

// LLMProvider defines the interface for LLM providers
type LLMProvider interface {
	SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error)
	AnalyzeEvents(ctx context.Context, events []store.Event) (*EventAnalysis, error)
	GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error)
}

// EventAnalysis represents the analysis of a set of events
type EventAnalysis struct {
	Summary           string            `json:"summary"`
	KeyFindings       []string          `json:"key_findings"`
	ThreatIndicators  []string          `json:"threat_indicators"`
	AffectedAssets    []string          `json:"affected_assets"`
	Timeline          []TimelineEntry   `json:"timeline"`
	Severity          string            `json:"severity"`
	Confidence        float64           `json:"confidence"`
	IOCs              []IOC             `json:"iocs"`
	AttackTechniques  []string          `json:"attack_techniques"`
}

// TimelineEntry represents an entry in the event timeline
type TimelineEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
}

// IOC represents an Indicator of Compromise
type IOC struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// LocalStub provides a heuristic-based LLM implementation
type LocalStub struct {
	// Future: Add configuration for external LLM providers
	// apiKey string
	// endpoint string
}

// NewLocalStub creates a new local stub LLM provider
func NewLocalStub() *LocalStub {
	return &LocalStub{}
}

// SummarizeCase generates a heuristic summary of a case
func (ls *LocalStub) SummarizeCase(ctx context.Context, case_ store.Case, events []store.Event) (string, error) {
	if len(events) == 0 {
		return "No events found for this case.", nil
	}

	// Analyze events
	analysis, err := ls.AnalyzeEvents(ctx, events)
	if err != nil {
		return "", fmt.Errorf("failed to analyze events: %w", err)
	}

	// Generate summary
	var summary strings.Builder
	
	summary.WriteString(fmt.Sprintf("Case: %s\n", case_.Title))
	summary.WriteString(fmt.Sprintf("Status: %s | Severity: %s\n", case_.Status, case_.Severity))
	summary.WriteString(fmt.Sprintf("Events: %d | Timespan: %s\n\n", 
		len(events), ls.getTimespan(events)))
	
	summary.WriteString("EXECUTIVE SUMMARY:\n")
	summary.WriteString(analysis.Summary)
	summary.WriteString("\n\n")
	
	if len(analysis.KeyFindings) > 0 {
		summary.WriteString("KEY FINDINGS:\n")
		for i, finding := range analysis.KeyFindings {
			summary.WriteString(fmt.Sprintf("%d. %s\n", i+1, finding))
		}
		summary.WriteString("\n")
	}
	
	if len(analysis.ThreatIndicators) > 0 {
		summary.WriteString("THREAT INDICATORS:\n")
		for _, indicator := range analysis.ThreatIndicators {
			summary.WriteString(fmt.Sprintf("• %s\n", indicator))
		}
		summary.WriteString("\n")
	}
	
	if len(analysis.IOCs) > 0 {
		summary.WriteString("INDICATORS OF COMPROMISE:\n")
		for _, ioc := range analysis.IOCs {
			summary.WriteString(fmt.Sprintf("• %s: %s (confidence: %.1f%%)\n", 
				strings.ToUpper(ioc.Type), ioc.Value, ioc.Confidence*100))
		}
		summary.WriteString("\n")
	}
	
	summary.WriteString(fmt.Sprintf("Overall Assessment: %s severity with %.1f%% confidence\n", 
		strings.ToUpper(analysis.Severity), analysis.Confidence*100))

	return summary.String(), nil
}

// AnalyzeEvents performs heuristic analysis of events
func (ls *LocalStub) AnalyzeEvents(ctx context.Context, events []store.Event) (*EventAnalysis, error) {
	if len(events) == 0 {
		return &EventAnalysis{
			Summary:    "No events to analyze",
			Severity:   "informational",
			Confidence: 1.0,
		}, nil
	}

	analysis := &EventAnalysis{
		KeyFindings:      []string{},
		ThreatIndicators: []string{},
		AffectedAssets:   []string{},
		Timeline:         []TimelineEntry{},
		IOCs:             []IOC{},
		AttackTechniques: []string{},
	}

	// Analyze event patterns
	eventTypes := make(map[string]int)
	severityCount := make(map[string]int)
	hosts := make(map[string]bool)
	ips := make(map[string]bool)
	processes := make(map[string]bool)
	files := make(map[string]bool)
	users := make(map[string]bool)

	var highestSeverity string
	severityOrder := map[string]int{
		"informational": 1,
		"low":          2,
		"medium":       3,
		"high":         4,
		"critical":     5,
	}
	maxSeverityValue := 0

	// Process events
	for _, event := range events {
		// Count event types
		eventTypes[event.EventType]++
		
		// Count severities
		severityCount[event.Severity]++
		if severityOrder[event.Severity] > maxSeverityValue {
			maxSeverityValue = severityOrder[event.Severity]
			highestSeverity = event.Severity
		}
		
		// Collect assets
		if event.Host != "" {
			hosts[event.Host] = true
		}
		if event.SrcIP != "" {
			ips[event.SrcIP] = true
		}
		if event.DstIP != "" {
			ips[event.DstIP] = true
		}
		if event.ProcessName != "" {
			processes[event.ProcessName] = true
		}
		if event.FileName != "" {
			files[event.FileName] = true
		}
		if event.UserName != "" {
			users[event.UserName] = true
		}

		// Add to timeline
		analysis.Timeline = append(analysis.Timeline, TimelineEntry{
			Timestamp:   event.Timestamp,
			EventType:   event.EventType,
			Description: ls.generateEventDescription(event),
			Severity:    event.Severity,
		})
	}

	// Sort timeline by timestamp
	sort.Slice(analysis.Timeline, func(i, j int) bool {
		return analysis.Timeline[i].Timestamp.Before(analysis.Timeline[j].Timestamp)
	})

	// Generate summary
	analysis.Summary = ls.generateSummary(len(events), eventTypes, hosts, ips)
	analysis.Severity = highestSeverity
	analysis.Confidence = ls.calculateConfidence(events)

	// Generate key findings
	analysis.KeyFindings = ls.generateKeyFindings(eventTypes, severityCount, hosts, ips, processes)

	// Generate threat indicators
	analysis.ThreatIndicators = ls.generateThreatIndicators(events, eventTypes)

	// Extract IOCs
	analysis.IOCs = ls.extractIOCs(events)

	// Identify attack techniques
	analysis.AttackTechniques = ls.identifyAttackTechniques(eventTypes, events)

	// Collect affected assets
	for host := range hosts {
		analysis.AffectedAssets = append(analysis.AffectedAssets, fmt.Sprintf("Host: %s", host))
	}
	for ip := range ips {
		analysis.AffectedAssets = append(analysis.AffectedAssets, fmt.Sprintf("IP: %s", ip))
	}

	return analysis, nil
}

// GenerateRecommendations generates actionable recommendations
func (ls *LocalStub) GenerateRecommendations(ctx context.Context, case_ store.Case, events []store.Event) ([]string, error) {
	recommendations := []string{}

	if len(events) == 0 {
		return []string{"No events available for analysis"}, nil
	}

	analysis, err := ls.AnalyzeEvents(ctx, events)
	if err != nil {
		return nil, err
	}

	// Base recommendations
	recommendations = append(recommendations, "Review and validate all identified IOCs")
	recommendations = append(recommendations, "Correlate events with external threat intelligence")

	// Severity-based recommendations
	switch analysis.Severity {
	case "critical", "high":
		recommendations = append(recommendations, "Immediately isolate affected systems")
		recommendations = append(recommendations, "Activate incident response team")
		recommendations = append(recommendations, "Preserve forensic evidence")
	case "medium":
		recommendations = append(recommendations, "Monitor affected systems closely")
		recommendations = append(recommendations, "Consider containment measures")
	case "low":
		recommendations = append(recommendations, "Continue monitoring for escalation")
	}

	// Event type specific recommendations
	eventTypes := make(map[string]bool)
	for _, event := range events {
		eventTypes[event.EventType] = true
	}

	if eventTypes["network"] {
		recommendations = append(recommendations, "Review network traffic patterns")
		recommendations = append(recommendations, "Check firewall and IDS logs")
	}

	if eventTypes["process"] {
		recommendations = append(recommendations, "Analyze process execution chains")
		recommendations = append(recommendations, "Review system integrity")
	}

	if eventTypes["file"] {
		recommendations = append(recommendations, "Scan files with updated antivirus")
		recommendations = append(recommendations, "Check file integrity and signatures")
	}

	if eventTypes["authentication"] {
		recommendations = append(recommendations, "Review authentication logs")
		recommendations = append(recommendations, "Consider password reset for affected accounts")
	}

	return recommendations, nil
}

// Helper methods

func (ls *LocalStub) generateSummary(eventCount int, eventTypes map[string]int, hosts, ips map[string]bool) string {
	var summary strings.Builder
	
	summary.WriteString(fmt.Sprintf("Analysis of %d security events across %d hosts and %d IP addresses. ", 
		eventCount, len(hosts), len(ips)))
	
	if len(eventTypes) == 1 {
		for eventType := range eventTypes {
			summary.WriteString(fmt.Sprintf("All events are %s-related. ", eventType))
		}
	} else {
		summary.WriteString("Multiple event types detected including ")
		types := make([]string, 0, len(eventTypes))
		for eventType := range eventTypes {
			types = append(types, eventType)
		}
		summary.WriteString(strings.Join(types, ", "))
		summary.WriteString(". ")
	}
	
	if len(ips) > 10 {
		summary.WriteString("High number of unique IP addresses suggests potential scanning or lateral movement. ")
	}
	
	return summary.String()
}

func (ls *LocalStub) generateKeyFindings(eventTypes map[string]int, severityCount map[string]int, 
	hosts, ips map[string]bool, processes map[string]bool) []string {
	
	findings := []string{}
	
	// Event distribution findings
	if len(eventTypes) > 1 {
		findings = append(findings, fmt.Sprintf("Multiple attack vectors detected: %d different event types", len(eventTypes)))
	}
	
	// Severity findings
	if severityCount["critical"] > 0 || severityCount["high"] > 0 {
		findings = append(findings, "High-severity events detected requiring immediate attention")
	}
	
	// Asset findings
	if len(hosts) > 5 {
		findings = append(findings, fmt.Sprintf("Multiple systems affected: %d unique hosts", len(hosts)))
	}
	
	if len(ips) > 20 {
		findings = append(findings, "Extensive network activity detected")
	}
	
	// Process findings
	if len(processes) > 10 {
		findings = append(findings, "Multiple processes involved, possible process injection or lateral movement")
	}
	
	return findings
}

func (ls *LocalStub) generateThreatIndicators(events []store.Event, eventTypes map[string]int) []string {
	indicators := []string{}
	
	// Pattern-based indicators
	if eventTypes["network"] > 50 {
		indicators = append(indicators, "High volume network activity")
	}
	
	if eventTypes["process"] > 20 {
		indicators = append(indicators, "Suspicious process execution patterns")
	}
	
	// Time-based indicators
	timeWindows := make(map[string]int)
	for _, event := range events {
		hour := event.Timestamp.Format("2006-01-02-15")
		timeWindows[hour]++
	}
	
	for _, count := range timeWindows {
		if count > 100 {
			indicators = append(indicators, "Burst activity detected in short time window")
			break
		}
	}
	
	return indicators
}

func (ls *LocalStub) extractIOCs(events []store.Event) []IOC {
	iocs := []IOC{}
	ipSeen := make(map[string]bool)
	hashSeen := make(map[string]bool)
	
	for _, event := range events {
		// Extract IP addresses
		if event.SrcIP != "" && !ipSeen[event.SrcIP] && ls.isSuspiciousIP(event.SrcIP) {
			iocs = append(iocs, IOC{
				Type:        "ip",
				Value:       event.SrcIP,
				Confidence:  0.7,
				Description: "Source IP from security event",
			})
			ipSeen[event.SrcIP] = true
		}
		
		if event.DstIP != "" && !ipSeen[event.DstIP] && ls.isSuspiciousIP(event.DstIP) {
			iocs = append(iocs, IOC{
				Type:        "ip",
				Value:       event.DstIP,
				Confidence:  0.7,
				Description: "Destination IP from security event",
			})
			ipSeen[event.DstIP] = true
		}
		
		// Extract file hashes
		if event.FileHash != "" && !hashSeen[event.FileHash] {
			iocs = append(iocs, IOC{
				Type:        "hash",
				Value:       event.FileHash,
				Confidence:  0.8,
				Description: fmt.Sprintf("File hash from %s", event.FileName),
			})
			hashSeen[event.FileHash] = true
		}
	}
	
	return iocs
}

func (ls *LocalStub) identifyAttackTechniques(eventTypes map[string]int, events []store.Event) []string {
	techniques := []string{}
	
	if eventTypes["process"] > 0 {
		techniques = append(techniques, "T1055 - Process Injection")
	}
	
	if eventTypes["network"] > 0 {
		techniques = append(techniques, "T1071 - Application Layer Protocol")
	}
	
	if eventTypes["file"] > 0 {
		techniques = append(techniques, "T1105 - Ingress Tool Transfer")
	}
	
	// Check for specific patterns
	for _, event := range events {
		if strings.Contains(strings.ToLower(event.ProcessName), "powershell") {
			techniques = append(techniques, "T1059.001 - PowerShell")
			break
		}
	}
	
	return techniques
}

func (ls *LocalStub) generateEventDescription(event store.Event) string {
	switch event.EventType {
	case "network":
		if event.SrcIP != "" && event.DstIP != "" {
			return fmt.Sprintf("Network connection from %s to %s", event.SrcIP, event.DstIP)
		}
		return "Network activity detected"
	case "process":
		if event.ProcessName != "" {
			return fmt.Sprintf("Process execution: %s", event.ProcessName)
		}
		return "Process activity detected"
	case "file":
		if event.FileName != "" {
			return fmt.Sprintf("File activity: %s", event.FileName)
		}
		return "File system activity detected"
	case "authentication":
		if event.UserName != "" {
			return fmt.Sprintf("Authentication event for user: %s", event.UserName)
		}
		return "Authentication activity detected"
	default:
		return event.Message
	}
}

func (ls *LocalStub) getTimespan(events []store.Event) string {
	if len(events) == 0 {
		return "N/A"
	}
	
	earliest := events[0].Timestamp
	latest := events[0].Timestamp
	
	for _, event := range events {
		if event.Timestamp.Before(earliest) {
			earliest = event.Timestamp
		}
		if event.Timestamp.After(latest) {
			latest = event.Timestamp
		}
	}
	
	duration := latest.Sub(earliest)
	if duration < time.Minute {
		return "< 1 minute"
	} else if duration < time.Hour {
		return fmt.Sprintf("%.0f minutes", duration.Minutes())
	} else if duration < 24*time.Hour {
		return fmt.Sprintf("%.1f hours", duration.Hours())
	} else {
		return fmt.Sprintf("%.1f days", duration.Hours()/24)
	}
}

func (ls *LocalStub) calculateConfidence(events []store.Event) float64 {
	// Simple heuristic: more events = higher confidence, up to a point
	eventCount := len(events)
	if eventCount >= 100 {
		return 0.9
	} else if eventCount >= 50 {
		return 0.8
	} else if eventCount >= 20 {
		return 0.7
	} else if eventCount >= 10 {
		return 0.6
	} else {
		return 0.5
	}
}

func (ls *LocalStub) isSuspiciousIP(ip string) bool {
	// Simple heuristic: consider private IPs less suspicious
	// In a real implementation, this would check against threat intelligence
	return !strings.HasPrefix(ip, "192.168.") && 
		   !strings.HasPrefix(ip, "10.") && 
		   !strings.HasPrefix(ip, "172.16.")
}