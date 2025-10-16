package llm

import (
	"context"
	"testing"
	"time"
)

func TestEstimateTokens(t *testing.T) {
	text := "This is a short message with some tokens."
	est := EstimateTokens(text)
	if est <= 0 {
		t.Fatalf("expected positive token estimate, got %d", est)
	}

	ls := &LocalStub{}
	est2 := ls.EstimateTokens(text)
	if est2 != est {
		t.Fatalf("LocalStub.EstimateTokens mismatch: %d vs %d", est2, est)
	}
}

func TestLocalStubChatBasic(t *testing.T) {
	ls := &LocalStub{}
	req := ChatRequest{
		Persona:   PersonaSOC,
		MCPMode:   "local",
		MaxTokens: 200,
		Messages: []ChatMessage{
			{Role: "system", Content: "You are a helpful assistant", Timestamp: time.Now()},
			{Role: "user", Content: "Give me containment steps", Timestamp: time.Now()},
		},
	}
	resp, err := ls.Chat(context.Background(), req)
	if err != nil {
		t.Fatalf("Chat returned error: %v", err)
	}
	if resp == nil {
		t.Fatalf("Chat returned nil response")
	}
	if resp.Error != "" {
		t.Fatalf("Chat returned error string: %s", resp.Error)
	}
	if resp.Message.Role != "assistant" {
		t.Fatalf("expected assistant role, got %q", resp.Message.Role)
	}
	if resp.Message.Content == "" {
		t.Fatalf("expected non-empty assistant message")
	}
	if resp.TokensUsed <= 0 {
		t.Fatalf("expected positive TokensUsed, got %d", resp.TokensUsed)
	}
	if resp.Cost < 0 {
		t.Fatalf("expected non-negative cost, got %f", resp.Cost)
	}
}

func TestLocalStubChatPersonaVariation(t *testing.T) {
	ls := &LocalStub{}

	makeReq := func(persona, content string) ChatRequest {
		return ChatRequest{
			Persona: persona,
			MCPMode: "local",
			Messages: []ChatMessage{
				{Role: "user", Content: content, Timestamp: time.Now()},
			},
		}
	}

	respSOC, _ := ls.Chat(context.Background(), makeReq(PersonaSOC, "build a timeline"))
	respTH, _ := ls.Chat(context.Background(), makeReq(PersonaHunter, "hunt for iocs"))
	respFor, _ := ls.Chat(context.Background(), makeReq(PersonaForensics, "preserve evidence"))

	if respSOC == nil || respSOC.Message.Content == "" {
		t.Fatalf("SOC Analyst response empty")
	}
	if respTH == nil || respTH.Message.Content == "" {
		t.Fatalf("Threat Hunter response empty")
	}
	if respFor == nil || respFor.Message.Content == "" {
		t.Fatalf("Forensics response empty")
	}
}