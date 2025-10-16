package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// convertToEnrichmentFields converts a normalized IntelOwlResult into a flat map for Redis Streams.
func (p *IntelOwlPlugin) convertToEnrichmentFields(obs Observable, intel *IntelOwlResult) map[string]string {
	fields := make(map[string]string)
	prefix := fmt.Sprintf("intelowl_%s_%s_", obs.Type, sanitizeKey(obs.Value))

	put := func(k, v string) {
		fields[prefix+k] = v
	}

	put("artifact", obs.Value)
	put("verdict", strings.ToLower(intel.Verdict))
	put("confidence", strings.ToLower(intel.Confidence))
	put("evidence_count", fmt.Sprintf("%d", intel.EvidenceCount))
	if len(intel.Tags) > 0 {
		put("tags", strings.Join(intel.Tags, ","))
	}
	if len(intel.Analyzers) > 0 {
		put("analyzers", strings.Join(intel.Analyzers, ","))
	}
	if len(intel.Jobs) > 0 {
		put("jobs", strings.Join(intel.Jobs, ","))
	}
	if intel.Summary != "" {
		put("summary", intel.Summary)
	}

	// Optional compact per-analyzer JSON (capped)
	if len(intel.PerAnalyzer) > 0 {
		if b, err := json.Marshal(intel.PerAnalyzer); err == nil {
			compact := string(b)
			// Cap to avoid stream bloat (approx 2KB)
			if len(compact) > 2048 {
				compact = compact[:2048]
				if !strings.HasSuffix(compact, "...") {
					compact += "..."
				}
			}
			put("per_analyzer_json", compact)
		}
	}

	return fields
}

// sanitizeKey converts an observable value into a Redis field-safe token.
func sanitizeKey(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.ReplaceAll(v, "://", "_")
	nonAlnum := regexp.MustCompile(`[^a-z0-9]+`)
	v = nonAlnum.ReplaceAllString(v, "_")
	v = strings.Trim(v, "_")
	if v == "" {
		v = "na"
	}
	return v
}