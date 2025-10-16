package llm

import (
	"context"
	"strings"
	"time"
)

// ChatMessage represents a single message in a chat conversation
type ChatMessage struct {
	Role      string    `json:"role"`      // "user", "assistant", "system"
	Content   string    `json:"content"`
	Timestamp time.Time `json:"timestamp"`
	Persona   string    `json:"persona,omitempty"`   // IR analyst, threat hunter, etc.
	TokensEst int       `json:"tokens_est,omitempty"` // Estimated tokens for this message
}

// ChatRequest represents a request to the chat interface
type ChatRequest struct {
	Messages []ChatMessage `json:"messages"`
	Persona  string        `json:"persona"`
	MCPMode  string        `json:"mcp_mode"` // "local", "remote", etc.
	MaxTokens int          `json:"max_tokens,omitempty"`
}

// ChatResponse represents a response from the chat interface
type ChatResponse struct {
	Message    ChatMessage `json:"message"`
	TokensUsed int         `json:"tokens_used"`
	Cost       float64     `json:"cost,omitempty"`
	Error      string      `json:"error,omitempty"`
}

// EstimateTokens provides a rough token estimation for text
func EstimateTokens(text string) int {
	// Rough estimation: ~4 characters per token on average
	return len(text) / 4
}

// ChatProvider extends LLMProvider with chat capabilities
type ChatProvider interface {
	LLMProvider
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
	EstimateTokens(text string) int
}

// Chat implements chat functionality for LocalStub
func (ls *LocalStub) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	if len(req.Messages) == 0 {
		return &ChatResponse{
			Error: "No messages provided",
		}, nil
	}

	// Get the last user message
	var userMessage string
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userMessage = req.Messages[i].Content
			break
		}
	}

	if userMessage == "" {
		return &ChatResponse{
			Error: "No user message found",
		}, nil
	}

	// Generate response based on persona and content
	response := ls.generateChatResponse(userMessage, req.Persona, req.MCPMode)
	
	// Estimate tokens (rough calculation)
	tokensUsed := EstimateTokens(userMessage + response)
	
	return &ChatResponse{
		Message: ChatMessage{
			Role:      "assistant",
			Content:   response,
			Timestamp: time.Now(),
			Persona:   req.Persona,
			TokensEst: EstimateTokens(response),
		},
		TokensUsed: tokensUsed,
		Cost:       float64(tokensUsed) * 0.002 / 1000, // Rough cost estimate
	}, nil
}

// EstimateTokens implements token estimation
func (ls *LocalStub) EstimateTokens(text string) int {
	return EstimateTokens(text)
}

// generateChatResponse generates a contextual response based on persona
func (ls *LocalStub) generateChatResponse(message, persona, mcpMode string) string {
	msg := strings.ToLower(message)
	
	// Persona-specific responses
	switch persona {
	// Accept canonical constants and a legacy label for SOC
	case PersonaSOC, "IR Analyst":
		return ls.generateSOCAnalystResponse(msg, mcpMode)
	// Threat Hunter (canonical constant covers the literal)
	case PersonaHunter:
		return ls.generateThreatHunterResponse(msg, mcpMode)
	// Forensics: accept canonical and legacy "Forensics Expert"
	case PersonaForensics, "Forensics Expert":
		return ls.generateForensicsResponse(msg, mcpMode)
	default:
		return ls.generateGeneralResponse(msg, mcpMode)
	}
}

func (ls *LocalStub) generateIRAnalystResponse(message, mcpMode string) string {
	if strings.Contains(message, "contain") || strings.Contains(message, "isolate") {
		return "For containment, I recommend: 1) Isolate affected systems from the network, 2) Preserve forensic evidence, 3) Document all actions taken. Consider network segmentation if lateral movement is suspected."
	}
	
	if strings.Contains(message, "timeline") {
		return "To build an incident timeline: 1) Collect logs from all affected systems, 2) Correlate events by timestamp, 3) Identify initial compromise vector, 4) Map attacker progression through the environment."
	}
	
	if strings.Contains(message, "eradicate") || strings.Contains(message, "remove") {
		return "Eradication steps: 1) Remove malware and artifacts, 2) Close attack vectors, 3) Update security controls, 4) Patch vulnerabilities. Ensure complete removal before recovery phase."
	}
	
	return "As an IR analyst, I can help with incident containment, evidence collection, timeline reconstruction, and recovery planning. What specific aspect of the incident would you like assistance with?"
}

func (ls *LocalStub) generateThreatHunterResponse(message, mcpMode string) string {
	if strings.Contains(message, "hunt") || strings.Contains(message, "search") {
		return "For threat hunting, focus on: 1) Anomalous network connections, 2) Unusual process execution patterns, 3) Privilege escalation indicators, 4) Data exfiltration signs. Use MITRE ATT&CK framework for structured hunting."
	}
	
	if strings.Contains(message, "ioc") || strings.Contains(message, "indicator") {
		return "Key IOCs to investigate: IP addresses, file hashes, domain names, registry keys, and behavioral patterns. Cross-reference with threat intelligence feeds and check for false positives."
	}
	
	if strings.Contains(message, "lateral") || strings.Contains(message, "movement") {
		return "Lateral movement indicators: 1) Unusual authentication patterns, 2) Remote tool execution, 3) Credential dumping activities, 4) Network reconnaissance. Check for tools like PsExec, WMI, or PowerShell remoting."
	}
	
	return "As a threat hunter, I specialize in proactive threat detection, IOC analysis, and behavioral pattern recognition. What threats or indicators would you like me to help investigate?"
}

func (ls *LocalStub) generateSOCAnalystResponse(message, mcpMode string) string {
	if strings.Contains(message, "alert") || strings.Contains(message, "trigger") {
		return "For alert analysis: 1) Validate the alert against known false positives, 2) Check related events in the timeframe, 3) Correlate with threat intelligence, 4) Assess impact and severity."
	}
	
	if strings.Contains(message, "escalate") {
		return "Escalation criteria: 1) Confirmed malicious activity, 2) Critical system involvement, 3) Data exfiltration indicators, 4) Advanced persistent threat signs. Document findings clearly for L2/L3 teams."
	}
	
	if strings.Contains(message, "triage") {
		return "Triage process: 1) Assess alert severity and scope, 2) Check for immediate threats, 3) Prioritize based on business impact, 4) Route to appropriate team. Focus on high-confidence, high-impact events first."
	}
	
	return "As a SOC analyst, I can help with alert triage, initial investigation, escalation decisions, and monitoring strategy. What security event would you like me to analyze?"
}

func (ls *LocalStub) generateForensicsResponse(message, mcpMode string) string {
	if strings.Contains(message, "preserve") || strings.Contains(message, "evidence") {
		return "Evidence preservation: 1) Create bit-for-bit disk images, 2) Document chain of custody, 3) Use write-blockers for physical media, 4) Calculate and verify hashes. Maintain forensic integrity throughout."
	}
	
	if strings.Contains(message, "analyze") || strings.Contains(message, "examine") {
		return "Forensic analysis approach: 1) Start with volatile data (memory, network connections), 2) Examine filesystem artifacts, 3) Review logs and registry, 4) Reconstruct attacker timeline. Use validated forensic tools."
	}
	
	if strings.Contains(message, "memory") || strings.Contains(message, "dump") {
		return "Memory analysis priorities: 1) Running processes and DLLs, 2) Network connections, 3) Injected code, 4) Registry handles. Look for process hollowing, code injection, and rootkit indicators."
	}
	
	return "As a forensics expert, I can guide evidence collection, analysis techniques, and artifact interpretation. What forensic examination would you like assistance with?"
}

func (ls *LocalStub) generateGeneralResponse(message, mcpMode string) string {
	if strings.Contains(message, "help") || strings.Contains(message, "what") {
		return "I can assist with incident response, threat hunting, security analysis, and forensics. Ask me about containment strategies, IOC analysis, timeline reconstruction, or evidence handling."
	}
	
	if strings.Contains(message, "recommend") {
		return "Based on the current case context, I recommend: 1) Review all related events for patterns, 2) Check for lateral movement indicators, 3) Validate IOCs against threat intelligence, 4) Consider containment measures if active threat detected."
	}
	
	// Default response based on MCP mode
	if mcpMode == "local" {
		return "I'm running in local mode with limited capabilities. I can provide general security guidance, but for advanced analysis, consider switching to a remote MCP server with enhanced threat intelligence access."
	}
	
	return "I'm here to help with your security investigation. You can ask me about incident response procedures, threat analysis, forensics techniques, or specific security events. What would you like to explore?"
}